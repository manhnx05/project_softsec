from dataclasses import dataclass
import re

from src.models.states import EmailState


# =============================================================
# EMAIL VALIDATION
# =============================================================

EMAIL_PATTERN = re.compile(
    r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
)


# =============================================================
# PARAMETERS
# =============================================================

@dataclass
class EmailParams:
    """
    Tham số của Email Notification.
    """

    max_retry: int = 2


# =============================================================
# NOTIFICATION MODEL
# =============================================================

@dataclass
class Notification:
    """
    Một email notification.
    """

    notification_id: int

    recipient: str

    subject: str

    body: str

    state: EmailState = EmailState.IDLE

    retry_count: int = 0


# =============================================================
# EMAIL MODULE
# =============================================================

class EmailNotificationModule:

    def __init__(
        self,
        params: EmailParams | None = None
    ):
        self.params = params or EmailParams()

        # Database giả lập

        self.notifications: dict[
            int,
            Notification
        ] = {}

        self._next_id = 1

    # =========================================================
    # VALIDATE EMAIL
    # =========================================================

    @staticmethod
    def is_valid_email(
        email: str
    ) -> bool:

        return bool(
            EMAIL_PATTERN.fullmatch(email)
        )

    # =========================================================
    # CREATE NOTIFICATION
    # =========================================================

    def create(
        self,
        recipient: str,
        subject: str,
        body: str
    ) -> Notification:
        """
        Tạo notification.

        State:

        IDLE -> QUEUED
        """

        # Constraint:
        # recipient phải hợp lệ

        if not self.is_valid_email(recipient):

            raise ValueError(
                "Email người nhận không hợp lệ."
            )

        notification = Notification(
            notification_id=self._next_id,

            recipient=recipient,

            subject=subject,

            body=body,

            state=EmailState.QUEUED
        )

        self.notifications[
            self._next_id
        ] = notification

        self._next_id += 1

        return notification

    # =========================================================
    # SEND
    # =========================================================

    def send(
        self,
        notification_id: int,
        transport
    ) -> bool:
        """
        Gửi email.

        QUEUED -> SENT

        hoặc

        QUEUED -> FAILED

        FAILED -> QUEUED
        """

        notification = self.notifications.get(
            notification_id
        )

        if notification is None:
            raise ValueError(
                "Không tìm thấy notification."
            )

        # Email đã gửi rồi

        if notification.state == EmailState.SENT:
            return True

        # Chỉ QUEUED hoặc FAILED mới được xử lý

        if notification.state not in (
            EmailState.QUEUED,
            EmailState.FAILED
        ):
            return False

        try:

            transport.send(
                recipient=notification.recipient,

                subject=notification.subject,

                body=notification.body
            )

            # Gửi thành công

            notification.state = EmailState.SENT

            return True

        except Exception:

            # Gửi thất bại

            notification.retry_count += 1

            # Vượt quá retry cho phép

            if (
                notification.retry_count
                > self.params.max_retry
            ):

                notification.state = EmailState.FAILED

            else:

                # Cho phép retry

                notification.state = EmailState.QUEUED

            return False


# =============================================================
# MOCK EMAIL TRANSPORT
# =============================================================

class MockEmailTransport:

    """
    SMTP giả lập để testing.

    should_fail=True:
        gửi email thất bại

    should_fail=False:
        gửi email thành công
    """

    def __init__(
        self,
        should_fail: bool = False
    ):

        self.should_fail = should_fail

        self.sent_messages = []

    def send(
        self,
        recipient: str,
        subject: str,
        body: str
    ):

        if self.should_fail:

            raise RuntimeError(
                "Mock SMTP failure"
            )

        self.sent_messages.append({
            "recipient": recipient,
            "subject": subject,
            "body": body
        })