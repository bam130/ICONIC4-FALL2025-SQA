#!/usr/bin/env python3
"""
Improved fuzz.py for MLForensics SQA project.

- Tries to import target functions using multiple common module paths.
- Uses forensics_logger if available (writes logs/forensics.log).
- Writes a concise fuzz-results.log containing JSON records of failures.
- Exits with status 1 if any failure was detected (so CI fails).
- Tunable iterations via FUZZ_ITERATIONS env var.
"""

import os
import sys
import time
import json
import random
import string
import tempfile
import traceback
from pathlib import Path

# Try to import a shared forensic logger if present; otherwise fallback to simple logging
try:
    from forensics_logger import logger
except Exception:
    import logging
    logger = logging.getLogger("fuzz_fallback")
    if not logger.handlers:
        h = logging.StreamHandler()
        fmt = "%(asctime)s %(levelname)s %(message)s"
        h.setFormatter(__import__("logging").Formatter(fmt))
        logger.addHandler(h)
    logger.setLevel(20)  # INFO

# -------------------------------------------------------------------
# Resolve target functions (support multiple possible module names)
# -------------------------------------------------------------------

def try_import(module_name, attr):
    try:
        m = __import__(module_name, fromlist=[attr])
        return getattr(m, attr)
    except Exception:
        return None

# Common module/name variations found in this repo
TARGET_LOOKUPS = [
    # parse Python file / parser
    ("FAME_ML.py_parser", "parse_python_file"),
    ("FAME-ML.py_parser", "parse_python_file"),
    ("FAME_ML.py_parser", "getPythonParseObject"),
    ("FAME-ML.py_parser", "getPythonParseObject"),
    # lint engine or class
    ("FAME_ML.lint_engine", "LintEngine"),
    ("FAME-ML.lint_engine", "LintEngine"),
    # empirical frequency
    ("empirical.frequency", "compute_token_frequency"),
    ("empirical.frequency", "compute_token_frequency"),  # duplicate for safety
    ("empirical.frequency", "reportProportion"),
    # empirical report
    ("empirical.report", "Report"),
    # mining git repo
    ("mining.git_repo_miner", "mine_git_repo"),
    ("mining.git.repo.miner", "mine_git_repo"),
    ("mining.git.repo.miner", "process_repo"),
    ("mining.git_repo_miner", "process_repo"),
]

# Map canonical target names to the callable (or class) found
TARGETS = {
    "parse_python_file": None,
    "LintEngine": None,
    "compute_token_frequency": None,
    "Report": None,
    "mine_git_repo": None,
    "reportProportion": None,
    "getPythonParseObject": None,
}

for mod, attr in TARGET_LOOKUPS:
    if attr in TARGETS and TARGETS[attr] is None:
        fn = try_import(mod, attr)
        if fn:
            TARGETS[attr] = fn
            logger.info(f"Resolved {attr} -> {mod}.{attr}")

# If some names are present under different attribute names, try to heuristically map them:
# (For example: compute_token_frequency might be named compute_token_frequency, computeTokenFrequency, etc.)
# We'll try a few common alternatives if original not found.
if TARGETS["compute_token_frequency"] is None:
    for alt in ("compute_token_frequency", "computeTokenFrequency", "compute_tokenfreq"):
        fn = try_import("empirical.frequency", alt)
        if fn:
            TARGETS["compute_token_frequency"] = fn
            logger.info(f"Resolved compute_token_frequency -> empirical.frequency.{alt}")
            break

# -------------------------------------------------------------------
# Random generators
# -------------------------------------------------------------------

def rand_str(n=50):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def rand_path(suffix=".py", make_file=False, content=None):
    # create a temp path; optionally write a small file
    fd, p = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    if not make_file:
        # remove the file if we don't want it on disk (simulate a non-existent path)
        try:
            os.remove(p)
        except Exception:
            pass
        return p  # still returns path that likely does not exist
    # create and write content
    with open(p, "w", encoding="utf-8", errors="ignore") as f:
        if content is None:
            # write some valid-ish or random content
            if suffix == ".py":
                f.write("def fuzz_sample():\n    return " + repr(rand_str(10)) + "\n")
            else:
                f.write("label,value\nA,1\nB,2\n")
        else:
            f.write(content)
    return p

def rand_code(tokens=20):
    parts = ["def", "class", "return", "if", "else", "import", "for", "while"]
    parts += [rand_str(5) for _ in range(6)]
    return " ".join(random.choice(parts) for _ in range(tokens))

def rand_stats():
    return {
        "file_count": random.randint(-10, 1000),
        "avg_tokens": random.random() * 100,
        "top_tokens": [rand_str(5) for _ in range(5)]
    }

# -------------------------------------------------------------------
# Helpers: call targets and record failures
# -------------------------------------------------------------------

FUZZ_LOG = Path("fuzz-results.log")
FUZZ_LOG.write_text("")  # truncate at start
FAILURES = []

def record_failure(record):
    # append JSON record to fuzz-results.log and to in-memory list
    try:
        s = json.dumps(record, default=str, indent=2)
    except Exception:
        s = repr(record)
    with open(FUZZ_LOG, "a", encoding="utf-8") as fh:
        fh.write(s + "\n\n")
    FAILURES.append(record)
    logger.error("Fuzzer recorded failure", extra={"module": record.get("module"), "function": record.get("function")})

# -------------------------------------------------------------------
# Fuzz harness: sequence of calls similar to original script
# -------------------------------------------------------------------

def run_iteration(i):
    ts = time.time()
    # 1) parse_python_file / getPythonParseObject
    parser_fn = TARGETS.get("parse_python_file") or TARGETS.get("getPythonParseObject")
    if parser_fn:
        try:
            # sometimes create a real file, sometimes pass non-existing path
            use_file = random.random() < 0.5
            p = rand_path(suffix=".py", make_file=use_file, content=rand_code(40) if use_file else None)
            parser_fn(p)
        except Exception as e:
            record_failure({
                "iteration": i,
                "time": ts,
                "module": getattr(parser_fn, "__module__", None),
                "function": getattr(parser_fn, "__name__", str(parser_fn)),
                "args": [p],
                "error": str(e),
                "traceback": traceback.format_exc()
            })

    # 2) LintEngine.run (class-based)
    LintEngine = TARGETS.get("LintEngine")
    if LintEngine:
        try:
            # if class, instantiate; if function, call directly
            if isinstance(LintEngine, type):
                engine = LintEngine()
                # some engines accept code, file path, or nothing — try several
                try:
                    engine.run(rand_code(30))
                except TypeError:
                    # try giving a path
                    p2 = rand_path(suffix=".py", make_file=True, content=rand_code(10))
                    engine.run(p2)
            else:
                # function
                LintEngine(rand_code(30))
        except Exception as e:
            record_failure({
                "iteration": i,
                "time": ts,
                "module": getattr(LintEngine, "__module__", None),
                "function": getattr(LintEngine, "__name__", str(LintEngine)),
                "args": ["<random code>"],
                "error": str(e),
                "traceback": traceback.format_exc()
            })

    # 3) compute_token_frequency / compute_token_frequency
    freq_fn = TARGETS.get("compute_token_frequency")
    if freq_fn:
        try:
            # build arbitrary bytes/chars text
            text = "".join(chr(random.randint(32, 126)) for _ in range(random.randint(10, 500)))
            freq_fn(text)
        except Exception as e:
            record_failure({
                "iteration": i,
                "time": ts,
                "module": getattr(freq_fn, "__module__", None),
                "function": getattr(freq_fn, "__name__", str(freq_fn)),
                "args": ["<random text len=%d>" % len(text)],
                "error": str(e),
                "traceback": traceback.format_exc()
            })

    # 4) Report.generate (class-based)
    ReportCls = TARGETS.get("Report")
    if ReportCls:
        try:
            if isinstance(ReportCls, type):
                rep = ReportCls()
                rep.generate(rand_stats())
            else:
                # function alternative
                ReportCls(rand_stats())
        except Exception as e:
            record_failure({
                "iteration": i,
                "time": ts,
                "module": getattr(ReportCls, "__module__", None),
                "function": getattr(ReportCls, "__name__", str(ReportCls)),
                "args": ["<random stats>"],
                "error": str(e),
                "traceback": traceback.format_exc()
            })

    # 5) mine_git_repo / mine_git_repo variant
    miner = TARGETS.get("mine_git_repo")
    if miner:
        try:
            fake_path = rand_path(suffix="", make_file=False)  # typically non-existent repo path
            miner(fake_path)
        except Exception as e:
            record_failure({
                "iteration": i,
                "time": ts,
                "module": getattr(miner, "__module__", None),
                "function": getattr(miner, "__name__", str(miner)),
                "args": [fake_path],
                "error": str(e),
                "traceback": traceback.format_exc()
            })

# -------------------------------------------------------------------
# Main harness
# -------------------------------------------------------------------

def main():
    iterations = int(os.environ.get("FUZZ_ITERATIONS", "300"))
    logger.info(f"Fuzzer starting: iterations={iterations}")
    start = time.time()

    for i in range(iterations):
        try:
            run_iteration(i)
        finally:
            # tiny delay to avoid hammering IO too hard
            if i % 50 == 0:
                time.sleep(0.01)

    elapsed = time.time() - start
    logger.info(f"Fuzzer finished: iterations={iterations} elapsed={elapsed:.2f}s failures={len(FAILURES)}")

    if FAILURES:
        # leave a brief top-level summary file for CI
        summary = {
            "timestamp": time.time(),
            "iterations": iterations,
            "failures": len(FAILURES),
            "first_failure": FAILURES[0] if FAILURES else None
        }
        Path("fuzz-summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        logger.error("Fuzzer completed with failures; see fuzz-results.log and fuzz-summary.json")
        # exit non-zero so CI fails
        sys.exit(1)
    else:
        logger.info("Fuzzer completed with no failures")
        sys.exit(0)

if __name__ == "__main__":
    main()

