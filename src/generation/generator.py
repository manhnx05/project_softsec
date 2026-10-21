"""Code Generator – Safe C mode included.

Generates:
  • Python state-enum files  (state.py.j2)
  • Safe C buffer files      (safe_buffer.c.j2 / safe_buffer.h.j2)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from src.specification.schemas import FunctionSpec

# ---------------------------------------------------------------------------
# Jinja2 environment
# ---------------------------------------------------------------------------

_TEMPLATE_DIR = Path(__file__).parent / "templetes"

_ENV = Environment(
    loader=FileSystemLoader(_TEMPLATE_DIR),
    keep_trailing_newline=True,
)


def _now_utc() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _to_identifier(name: str) -> str:
    """Convert an arbitrary name to a safe C identifier (upper-case)."""
    identifier = re.sub(r"[^A-Za-z0-9_]", "_", name)
    return identifier.upper()


# ---------------------------------------------------------------------------
# CodeGenerator
# ---------------------------------------------------------------------------


class CodeGenerator:
    """Generates source files from Jinja2 templates."""

    def __init__(self) -> None:
        # Keep a local reference for clarity; uses the module-level env.
        self._env = _ENV

    # -----------------------------------------------------------------------
    # Python state enum
    # -----------------------------------------------------------------------

    def generate_state_enum(
        self,
        function: FunctionSpec,
        output_dir: str = "generated",
    ) -> Path:
        """Render a Python Enum class for the states of *function*.

        Parameters
        ----------
        function:
            The function specification whose states are rendered.
        output_dir:
            Directory where the generated file is written.

        Returns
        -------
        Path
            Absolute path of the written file.
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        template = self._env.get_template("state.py.j2")
        content = template.render(
            class_name=f"{function.name}State",
            states=function.states,
        )

        file_path = output_path / f"{function.name.lower()}_states.py"
        file_path.write_text(content, encoding="utf-8")
        return file_path

    # -----------------------------------------------------------------------
    # Safe C buffer files
    # -----------------------------------------------------------------------

    def generate_safe_buffer_c(
        self,
        file_name: str = "safe_buffer",
        buffer_capacity: int = 64,
        output_dir: str = "generated_c",
    ) -> dict[str, Path]:
        """Render a pair of Safe-C buffer files (.h + .c).

        The generated code enforces the following defensive rules:
          [R1] NULL-pointer check before any dereference.
          [R2] Negative-length check before casting to size_t.
          [R3] Zero-length copy rejected.
          [R4] Bounds check (length ≤ src_size AND length ≤ dst_cap).
          [R5] Dangerous functions (strcpy, strcat, sprintf) are banned.
          [R6] NUL terminator always written at index (capacity − 1).

        Parameters
        ----------
        file_name:
            Base name (without extension) for the generated files.
            Also used as the C identifier prefix.
        buffer_capacity:
            Default buffer capacity constant embedded in the header.
        output_dir:
            Directory where the generated files are written.

        Returns
        -------
        dict[str, Path]
            ``{"header": Path(...), "source": Path(...)}``
        """
        if buffer_capacity <= 0:
            raise ValueError(
                f"buffer_capacity must be a positive integer, got {buffer_capacity!r}"
            )

        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        prefix = _to_identifier(file_name)
        guard_name = f"LMS_{prefix}_H"
        context = {
            "file_name": file_name,
            "prefix": prefix,
            "guard_name": guard_name,
            "buffer_capacity": buffer_capacity,
            "generated_at": _now_utc(),
        }

        # ── Header ──────────────────────────────────────────────────────────
        header_template = self._env.get_template("safe_buffer.h.j2")
        header_content = header_template.render(**context)
        header_path = output_path / f"{file_name}.h"
        header_path.write_text(header_content, encoding="utf-8")

        # ── Source ──────────────────────────────────────────────────────────
        source_template = self._env.get_template("safe_buffer.c.j2")
        source_content = source_template.render(**context)
        source_path = output_path / f"{file_name}.c"
        source_path.write_text(source_content, encoding="utf-8")

        return {"header": header_path, "source": source_path}

    # -----------------------------------------------------------------------
    # Audit helper
    # -----------------------------------------------------------------------

    @staticmethod
    def audit_c_source(source_path: Path) -> dict[str, object]:
        """Perform a quick static audit of a C source file.

        Checks for banned functions (strcpy, strcat, sprintf, gets) and
        verifies that recommended safe patterns are present.

        Parameters
        ----------
        source_path:
            Path to the ``.c`` file to audit.

        Returns
        -------
        dict
            Keys:
              ``banned_found``  – list of banned function names detected.
              ``safe_present``  – list of safe patterns detected.
              ``passed``        – True when no banned functions are found.
              ``details``       – human-readable summary string.
        """
        if not source_path.is_file():
            raise FileNotFoundError(f"Source file not found: {source_path}")

        raw_text = source_path.read_text(encoding="utf-8")

        # Strip /* ... */ block comments and // line comments so that
        # keywords mentioned only in comments don't cause false positives.
        # Strategy: remove block comments first, then line comments.
        no_block = re.sub(r"/\*.*?\*/", " ", raw_text, flags=re.DOTALL)
        code_only = re.sub(r"//[^\n]*", " ", no_block)

        banned = ["strcpy", "strcat", "sprintf", "gets", "scanf"]
        safe_patterns = ["strncpy", "snprintf", "memcpy", "strncat", "fgets"]

        # Match banned names only when followed by '(' (function call),
        # not merely as part of a longer identifier.
        banned_found = [
            fn for fn in banned
            if re.search(rf"\b{fn}\s*\(", code_only)
        ]
        safe_present = [fn for fn in safe_patterns if fn in code_only]

        passed = len(banned_found) == 0
        if passed:
            details = "[PASS] No banned functions detected."
        else:
            details = f"[WARN] Banned functions found: {', '.join(banned_found)}"

        return {
            "banned_found": banned_found,
            "safe_present": safe_present,
            "passed": passed,
            "details": details,
        }