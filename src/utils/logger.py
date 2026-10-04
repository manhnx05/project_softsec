import logging


def get_logger(
    name: str = "lms_security",
):

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | "
            "%(levelname)s | "
            "%(message)s"
        ),
    )

    return logging.getLogger(name)