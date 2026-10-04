from enum import Enum


class AuthState(str, Enum):
    """
    Các trạng thái của chức năng Authentication.
    """

    LOGGED_OUT = "LOGGED_OUT"

    LOGIN_FAILED = "LOGIN_FAILED"

    LOGGED_IN = "LOGGED_IN"

    LOCKED = "LOCKED"


class EmailState(str, Enum):
    """
    Các trạng thái của chức năng Email Notification.
    """

    IDLE = "IDLE"

    QUEUED = "QUEUED"

    SENT = "SENT"

    FAILED = "FAILED"