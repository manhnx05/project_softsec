import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from src.models.states import AuthState

_PASSWORD_HASH_ALGORITHM = "pbkdf2_sha256"
_PASSWORD_HASH_ITERATIONS = 600_000
_MIN_PASSWORD_HASH_ITERATIONS = 600_000
_MAX_PASSWORD_HASH_ITERATIONS = 2_000_000
_PASSWORD_SALT_BYTES = 16


@dataclass
class LoginParams:
    max_attempts: int = 3
    session_ttl_seconds: int = 3600
    min_password_length: int = 8


@dataclass
class User:
    username: str
    password_hash: str
    state: AuthState = AuthState.LOGGED_OUT
    failed_attempts: int = 0


@dataclass
class Session:
    token: str
    username: str
    created_at: datetime
    expires_at: datetime


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(_PASSWORD_SALT_BYTES)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _PASSWORD_HASH_ITERATIONS,
    )

    encoded_salt = base64.urlsafe_b64encode(salt).decode("ascii")
    encoded_digest = base64.urlsafe_b64encode(digest).decode("ascii")

    return (
        f"{_PASSWORD_HASH_ALGORITHM}$"
        f"{_PASSWORD_HASH_ITERATIONS}$"
        f"{encoded_salt}$"
        f"{encoded_digest}"
    )


def verify_password(password: str, password_hash: str) -> bool:
    try:
        algorithm, iteration_count, encoded_salt, encoded_digest = (
            password_hash.split("$")
        )
        iterations = int(iteration_count)
        if (
            algorithm != _PASSWORD_HASH_ALGORITHM
            or not (
                _MIN_PASSWORD_HASH_ITERATIONS
                <= iterations
                <= _MAX_PASSWORD_HASH_ITERATIONS
            )
        ):
            return False

        salt = base64.b64decode(
            encoded_salt,
            altchars=b"-_",
            validate=True,
        )
        expected_digest = base64.b64decode(
            encoded_digest,
            altchars=b"-_",
            validate=True,
        )
        actual_digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            iterations,
        )
    except (ValueError, UnicodeError):
        return False

    return hmac.compare_digest(actual_digest, expected_digest)


class AuthenticationModule:

    def __init__(
        self,
        params: LoginParams | None = None
    ):
        self.params = params or LoginParams()

        self.users: dict[str, User] = {}

        self.sessions: dict[str, Session] = {}

    def register(
        self,
        username: str,
        password: str
    ) -> User:

        if not username:
            raise ValueError(
                "Username không được rỗng."
            )

        if len(password) < self.params.min_password_length:
            raise ValueError(
                f"Password phải có ít nhất "
                f"{self.params.min_password_length} ký tự."
            )

        if username in self.users:
            raise ValueError(
                "Username đã tồn tại."
            )

        user = User(
            username=username,
            password_hash=hash_password(password)
        )

        self.users[username] = user

        return user

    def login(
        self,
        username: str,
        password: str
    ) -> Session | None:

        user = self.users.get(username)

        if user is None:
            return None

        if user.state == AuthState.LOCKED:
            return None

        if not verify_password(password, user.password_hash):

            user.failed_attempts += 1

            if user.failed_attempts >= self.params.max_attempts:
                user.state = AuthState.LOCKED
            else:
                user.state = AuthState.LOGIN_FAILED

            return None

        user.failed_attempts = 0

        user.state = AuthState.LOGGED_IN

        now = datetime.now(UTC)

        session = Session(
            token=secrets.token_urlsafe(32),
            username=username,
            created_at=now,
            expires_at=(
                now +
                timedelta(
                    seconds=self.params.session_ttl_seconds
                )
            )
        )

        self.sessions[session.token] = session

        return session

    def authenticate(
        self,
        token: str
    ) -> User | None:

        session = self.sessions.get(token)

        if session is None:
            return None

        now = datetime.now(UTC)

        if now >= session.expires_at:

            self.sessions.pop(
                token,
                None
            )

            return None

        user = self.users.get(
            session.username
        )

        if user is None:
            return None

        if user.state != AuthState.LOGGED_IN:
            return None

        return user

    def logout(
        self,
        token: str
    ) -> bool:

        session = self.sessions.pop(
            token,
            None
        )

        if session is None:
            return False

        user = self.users.get(
            session.username
        )

        if user:
            user.state = AuthState.LOGGED_OUT

        return True

    def reset_lock(
        self,
        username: str
    ) -> bool:

        user = self.users.get(username)

        if user is None:
            return False

        user.failed_attempts = 0

        user.state = AuthState.LOGGED_OUT

        return True