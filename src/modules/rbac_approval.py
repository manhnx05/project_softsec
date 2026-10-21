from dataclasses import dataclass
from enum import Enum

from src.state_machine.machine import StateMachine
from src.state_machine.state import State
from src.state_machine.transition import Transition


class ApprovalState(str, Enum):
    PENDING = "PENDING"
    STEP_VERIFY = "STEP_VERIFY"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class Role(str, Enum):
    STUDENT = "STUDENT"
    AUDITOR = "AUDITOR"
    ADMIN = "ADMIN"


class SecurityWorkflowError(Exception):
    """Lỗi vi phạm an toàn quy trình nghiệp vụ hoặc phân quyền."""


class IllegalStateTransitionError(SecurityWorkflowError):
    """Lỗi cố gắng chuyển trạng thái không hợp lệ (ví dụ: bypass STEP_VERIFY)."""


class PermissionDeniedError(SecurityWorkflowError):
    """Lỗi vai trò không có thẩm quyền thực hiện thao tác."""


@dataclass
class ApprovalRequest:
    request_id: str
    requester: str
    state: ApprovalState = ApprovalState.PENDING
    verified_by: str | None = None
    approved_by: str | None = None
    rejection_reason: str | None = None


def create_approval_state_machine() -> StateMachine:
    """Tạo máy trạng thái chuẩn cho quy trình phê duyệt LMS (PENDING -> STEP_VERIFY -> APPROVED)."""
    states = [
        State(ApprovalState.PENDING.value, "Yêu cầu mới khởi tạo, chờ thẩm định"),
        State(ApprovalState.STEP_VERIFY.value, "Đang trong bước thẩm định/xác thực điều kiện"),
        State(ApprovalState.APPROVED.value, "Đã được phê duyệt chính thức"),
        State(ApprovalState.REJECTED.value, "Yêu cầu đã bị từ chối"),
    ]

    # Các chuyển trạng thái hợp lệ trong quy trình bảo mật:
    # Tuyệt đối không có transition trực tiếp từ PENDING -> APPROVED
    transitions = [
        Transition(
            source=ApprovalState.PENDING.value,
            target=ApprovalState.STEP_VERIFY.value,
            event="verify_step",
        ),
        Transition(
            source=ApprovalState.STEP_VERIFY.value,
            target=ApprovalState.APPROVED.value,
            event="approve",
        ),
        Transition(
            source=ApprovalState.STEP_VERIFY.value,
            target=ApprovalState.REJECTED.value,
            event="reject",
        ),
    ]

    return StateMachine(
        states=states,
        transitions=transitions,
        initial_state=ApprovalState.PENDING.value,
    )


class RBACApprovalModule:
    """
    Module quản lý phê duyệt với kiểm soát truy cập dựa trên vai trò (RBAC)
    và ràng buộc chống nhảy cóc trạng thái (Anti-Bypass).
    """

    def __init__(self) -> None:
        self.requests: dict[str, ApprovalRequest] = {}

    def submit_request(self, request_id: str, requester: str) -> ApprovalRequest:
        if request_id in self.requests:
            raise ValueError(f"Request {request_id} đã tồn tại.")
        req = ApprovalRequest(request_id=request_id, requester=requester)
        self.requests[request_id] = req
        return req

    def verify_step(self, request_id: str, actor_role: Role, actor_name: str) -> bool:
        """
        Bước thẩm định: Chuyển từ PENDING -> STEP_VERIFY.
        Chỉ AUDITOR hoặc ADMIN mới được thực hiện.
        """
        req = self._get_request(request_id)

        if actor_role not in (Role.AUDITOR, Role.ADMIN):
            raise PermissionDeniedError(
                f"Vai trò {actor_role} không có quyền thực hiện thẩm định (STEP_VERIFY)."
            )

        if req.state != ApprovalState.PENDING:
            raise IllegalStateTransitionError(
                f"Không thể thẩm định khi yêu cầu đang ở trạng thái {req.state.value}."
            )

        req.state = ApprovalState.STEP_VERIFY
        req.verified_by = actor_name
        return True

    def approve(self, request_id: str, actor_role: Role, actor_name: str) -> bool:
        """
        Bước phê duyệt: Chuyển từ STEP_VERIFY -> APPROVED.
        Chỉ ADMIN mới được phê duyệt, và BẮT BUỘC phải qua STEP_VERIFY trước.
        Nếu gọi khi đang ở PENDING -> ném IllegalStateTransitionError (CWE-841).
        """
        req = self._get_request(request_id)

        # Kiểm tra chuyển trạng thái bất hợp lệ trước (ngăn chặn bypass bước thẩm định)
        if req.state == ApprovalState.PENDING:
            raise IllegalStateTransitionError(
                "LỖ HỔNG BẢO MẬT: Không thể nhảy cóc từ PENDING thẳng sang APPROVED "
                "mà bỏ qua bước kiểm tra điều kiện (STEP_VERIFY)!"
            )

        if actor_role != Role.ADMIN:
            raise PermissionDeniedError(
                f"Vai trò {actor_role} không được phép phê duyệt (chỉ ADMIN có quyền)."
            )

        if req.state != ApprovalState.STEP_VERIFY:
            raise IllegalStateTransitionError(
                f"Chuyển trạng thái bất hợp lệ từ {req.state.value} sang APPROVED."
            )

        req.state = ApprovalState.APPROVED
        req.approved_by = actor_name
        return True

    def reject(
        self,
        request_id: str,
        actor_role: Role,
        actor_name: str,
        reason: str = "Không đạt điều kiện",
    ) -> bool:
        req = self._get_request(request_id)

        if actor_role not in (Role.AUDITOR, Role.ADMIN):
            raise PermissionDeniedError(
                f"Vai trò {actor_role} không có quyền từ chối yêu cầu."
            )

        if req.state not in (ApprovalState.PENDING, ApprovalState.STEP_VERIFY):
            raise IllegalStateTransitionError(
                f"Không thể từ chối khi đang ở trạng thái {req.state.value}."
            )

        req.state = ApprovalState.REJECTED
        req.rejection_reason = f"{actor_name}: {reason}"
        return True

    def _get_request(self, request_id: str) -> ApprovalRequest:
        req = self.requests.get(request_id)
        if req is None:
            raise ValueError(f"Không tìm thấy yêu cầu: {request_id}")
        return req
