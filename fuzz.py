import random
import string
import os
import traceback
import logging

# Import target functions
try:
    from FAME_ML.py_parser import parse_python_file
except Exception:
    parse_python_file = None

try:
    from FAME_ML.lint_engine import LintEngine
except Exception:
    LintEngine = None

try:
    from empirical.frequency import compute_token_frequency
except Exception:
    compute_token_frequency = None

try:
    from empirical.report import Report
except Exception:
    Report = None

try:
    from mining.git_repo_miner import mine_git_repo
except Exception:
    mine_git_repo = None


# ---------------------------
# Random Data Generators
# ---------------------------

def rand_str(n=50):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))

def rand_path():
    # Random path, may not exist (this is intentional for fuzzing)
    return "/tmp/" + rand_str(10) + ".py"

def rand_code():
    """Generate random Python-like text (may be invalid)."""
    tokens = [
        "def", "class", "return", "if", "else", "import", "for", "while",
        rand_str(5), rand_str(8), rand_str(3)
    ]
    return " ".join(random.choice(tokens) for _ in range(20))

def rand_stats():
    """Random dict for Report.generate."""
    return {
        "file_count": random.randint(-10, 1000),
        "avg_tokens": random.random() * 100,
        "top_tokens": [rand_str(5) for _ in range(5)]
    }


# ---------------------------
# Fuzzing entry point
# ---------------------------

def main():
    with open("fuzz_log.txt", "w") as log:
        log.write("=== FUZZING SESSION STARTED ===\n\n")

        for i in range(300):  # number of iterations
            log.write(f"\n--- ITERATION {i} ---\n")

            # ------------------------
            # 1. parse_python_file
            # ------------------------
            if parse_python_file:
                try:
                    fake_file_path = rand_path()
                    # Create fake file sometimes
                    if random.random() < 0.3:
                        with open(fake_file_path, "w") as f:
                            f.write(rand_code())
                    parse_python_file(fake_file_path)
                except Exception:
                    log.write("CRASH: parse_python_file\n")
                    log.write(traceback.format_exc() + "\n")

            # ------------------------
            # 2. LintEngine.run
            # ------------------------
            if LintEngine:
                try:
                    engine = LintEngine()
                    engine.run(rand_code())  # pass random fake Python code
                except Exception:
                    log.write("CRASH: LintEngine.run\n")
                    log.write(traceback.format_exc() + "\n")

            # ------------------------
            # 3. compute_token_frequency
            # ------------------------
            if compute_token_frequency:
                try:
                    text = "".join(chr(random.randint(0, 255)) for _ in range(100))
                    compute_token_frequency(text)
                except Exception:
                    log.write("CRASH: compute_token_frequency\n")
                    log.write(traceback.format_exc() + "\n")

            # ------------------------
            # 4. Report.generate
            # ------------------------
            if Report:
                try:
                    report = Report()
                    report.generate(rand_stats())
                except Exception:
                    log.write("CRASH: Report.generate\n")
                    log.write(traceback.format_exc() + "\n")

            # ------------------------
            # 5. mine_git_repo
            # ------------------------
            if mine_git_repo:
                try:
                    fake_path = "/tmp/" + rand_str(8)
                    mine_git_repo(fake_path)
                except Exception:
                    log.write("CRASH: mine_git_repo\n")
                    log.write(traceback.format_exc() + "\n")

        log.write("\n=== FUZZING SESSION COMPLETE ===\n")


if __name__ == "__main__":
    main()

