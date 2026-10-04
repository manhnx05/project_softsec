# ====================================================
# AUTO-GENERATED FILE
# Do not edit manually.
# Generated from Kripke models.
# ====================================================

from enum import Enum

class AuthStateGenerated(str, Enum):
    LOGGED_OUT = "LOGGED_OUT"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGGED_IN = "LOGGED_IN"
    LOCKED = "LOCKED"

class EmailStateGenerated(str, Enum):
    IDLE = "IDLE"
    QUEUED = "QUEUED"
    SENT = "SENT"
    FAILED = "FAILED"
