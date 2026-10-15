"""Shared logging setup so every layer (monitor, model, response, GUI)
writes to the same logs/ directory in a consistent format, supporting
the forensic-logging requirement in Ch. 3.4.
"""

import logging
from pathlib import Path


def get_logger(name: str, log_dir: str = "logs") -> logging.Logger:
    Path(log_dir).mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    if logger.handlers:
        return logger  # already configured

    logger.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s | %(name)s | %(levelname)s | %(message)s"
    )

    file_handler = logging.FileHandler(Path(log_dir) / "system.log")
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger
