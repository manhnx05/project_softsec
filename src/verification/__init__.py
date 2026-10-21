"""Formal verification and comparative analysis package."""

from src.verification.comparator import (
    CANONICAL_COMPARISON,
    ToolComparisonRecord,
    VerificationMethod,
    evaluate_live_comparison,
    generate_comparison_dataframe,
    generate_markdown_table,
    get_buffer_copy_case_comparison,
)
from src.verification.constraints import (
    AUTH_CONSTRAINTS,
    EMAIL_CONSTRAINTS,
    Constraint,
    verify_constraints,
)
from src.verification.kripke import (
    build_auth_kripke,
    build_email_kripke,
)

__all__ = [
    "AUTH_CONSTRAINTS",
    "EMAIL_CONSTRAINTS",
    "Constraint",
    "verify_constraints",
    "build_auth_kripke",
    "build_email_kripke",
    "VerificationMethod",
    "ToolComparisonRecord",
    "CANONICAL_COMPARISON",
    "get_buffer_copy_case_comparison",
    "generate_comparison_dataframe",
    "generate_markdown_table",
    "evaluate_live_comparison",
]
