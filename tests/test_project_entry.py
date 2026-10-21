import shutil
import subprocess
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import main
import src.main as demo_main
from src.generation.generator import CodeGenerator
from src.specification.loader import load_project_spec


def test_main_help_lists_available_commands():
    with pytest.raises(SystemExit) as excinfo:
        main.main(["--help"])

    assert excinfo.value.code == 0


def test_legacy_demo_entrypoint_imports():
    assert callable(demo_main.main)


def test_state_generator_renders_spec(tmp_path):
    function = load_project_spec("specs")[0].functions[0]

    output = CodeGenerator().generate_state_enum(function, str(tmp_path))

    generated_source = output.read_text(encoding="utf-8")
    assert output.exists()
    assert "class AuthenticationState" in generated_source
    assert "LOGGED_OUT" in generated_source


def test_safe_c_generator_emits_canonical_implementation_and_header(tmp_path):
    generated_files = CodeGenerator().generate_safe_c_files(str(tmp_path))
    project_root = Path(__file__).resolve().parents[1]

    assert [path.name for path in generated_files] == [
        "buffer_copy.c",
        "buffer_copy.h",
    ]
    assert generated_files[0].read_bytes() == (
        project_root / "csrc" / "safe" / "buffer_copy.c"
    ).read_bytes()
    assert generated_files[1].read_bytes() == (
        project_root / "csrc" / "include" / "buffer_copy.h"
    ).read_bytes()

    compiler = shutil.which("gcc")
    if compiler is not None:
        binary = tmp_path / "generated_safe_copy"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(tmp_path),
                str(generated_files[0]),
                str(project_root / "csrc" / "cli" / "buffer_copy_cli.c"),
                "-o",
                str(binary),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        assert subprocess.run(
            [str(binary), "16"],
            check=False,
            capture_output=True,
        ).returncode == 0
        assert subprocess.run(
            [str(binary), "-1"],
            check=False,
            capture_output=True,
        ).returncode == 2


def test_dashboard_actions_store_section_results():
    app = AppTest.from_file("../app.py").run()

    app.button(key="run_function_scenario").click().run()
    assert app.session_state["function_result"]["Login"] == "PASS"
    assert all(
        scenario["Result"] == "PASS"
        for scenario in app.session_state["function_result"]["Scenarios"]
    )

    app.selectbox(key="function_scenario_selector").select(1).run()
    app.button(key="run_function_scenario").click().run()
    assert app.session_state["function_result"]["Function"] == "EmailNotification"
    assert all(
        scenario["Result"] == "PASS"
        for scenario in app.session_state["function_result"]["Scenarios"]
    )

    app.button(
        key="FormSubmitter:parameter_validation_form-Validate parameters"
    ).click().run()
    assert all(
        result["Result"] == "PASS"
        for result in app.session_state["parameter_result"]["checks"]
    )

    app.button(key="analyze_states").click().run()
    assert app.session_state["state_result"]["errors"] == []

    app.button(
        key="FormSubmitter:constraint_check_form-Check authentication constraints"
    ).click().run()
    assert app.session_state["constraint_result"]["passed"] is True

    app.button(key="build_kripke_model").click().run()
    assert app.session_state["kripke_result"]["errors"] == []
    kripke_result = app.session_state["kripke_result"]
    assert len(kripke_result["state_rows"]) == kripke_result["states"]
    assert all(row["Propositions"] for row in kripke_result["state_rows"])
    assert all(row["Description"] for row in kripke_result["state_rows"])
    assert len(kripke_result["transition_rows"]) == kripke_result["transitions"]
    assert "doublecircle" in kripke_result["graph"]
    assert not app.exception

    app.button(key="generate_safe_c_code").click().run()
    generated_safe_c = app.session_state["generated_safe_c_files"]
    assert len(generated_safe_c) == 2
    assert all(Path(path).is_file() for path in generated_safe_c)
    assert not app.exception
