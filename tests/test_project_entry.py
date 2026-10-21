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


def test_dashboard_actions_store_section_results():
    app = AppTest.from_file("../app.py").run(timeout=30)

    app.button(key="run_function_scenario").click().run(timeout=30)
    assert app.session_state["function_result"]["Login"] == "PASS"

    app.button(
        key="FormSubmitter:parameter_validation_form-Validate parameters"
    ).click().run(timeout=30)

    assert all(
        result["Result"] == "PASS"
        for result in app.session_state["parameter_result"]["checks"]
    )

    app.button(key="analyze_states").click().run(timeout=30)
    assert app.session_state["state_result"]["errors"] == []

    app.button(
        key="FormSubmitter:constraint_check_form-Check authentication constraints"
    ).click().run(timeout=30)
    assert app.session_state["constraint_result"]["passed"] is True

    app.button(key="build_kripke_model").click().run(timeout=30)
    assert app.session_state["kripke_result"]["errors"] == []
    assert not app.exception

