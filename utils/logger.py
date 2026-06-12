import logging

from config.settings import settings


def get_logger(name: str) -> logging.Logger:
    logging.basicConfig(
        level=settings.LOG_LEVEL,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    return logging.getLogger(name)

