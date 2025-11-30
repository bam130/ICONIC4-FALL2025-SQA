# forensics_logger.py
import logging
from logging.handlers import RotatingFileHandler
import os

LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("mlforensics")
logger.setLevel(logging.DEBUG)

# Rotating handler: keep artifacts reasonable for CI
handler = RotatingFileHandler(os.path.join(LOG_DIR, "forensics.log"),
                              maxBytes=500_000, backupCount=3)
fmt = "%(asctime)s %(levelname)s %(name)s %(filename)s:%(lineno)d %(message)s"
handler.setFormatter(logging.Formatter(fmt))
if not logger.handlers:
    logger.addHandler(handler)
