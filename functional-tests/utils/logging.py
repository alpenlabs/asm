import logging
import os
import sys

from constants import DEFAULT_LOG_LEVEL

FORMATTER = logging.Formatter("%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s")
TEST_FILE_HANDLER_ATTR = "_asm_test_file_handler"


def setup_root_logger():
    """Configure root logger from LOG_LEVEL env var."""
    log_level = os.getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL).upper()
    log_level = getattr(logging, log_level, logging.NOTSET)

    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(FORMATTER)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(stream_handler)


def setup_test_logger(datadir_root: str, test_name: str) -> logging.Logger:
    """Attach a per-test file handler and return a logger for the test."""
    log_dir = os.path.join(datadir_root, "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{test_name}.log")

    root_logger = logging.getLogger()
    for handler in list(root_logger.handlers):
        if getattr(handler, TEST_FILE_HANDLER_ATTR, False):
            root_logger.removeHandler(handler)
            handler.close()

    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(FORMATTER)
    setattr(file_handler, TEST_FILE_HANDLER_ATTR, True)
    root_logger.addHandler(file_handler)

    logger = logging.getLogger(f"root.{test_name}")
    logger.handlers.clear()
    logger.propagate = True
    logger.setLevel(
        getattr(logging, os.getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL).upper(), logging.NOTSET)
    )
    return logger
