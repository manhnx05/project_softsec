import json
from pathlib import Path

import pandas as pd
import streamlit as st
import yaml

from src.constraints.z3_solver import Z3ConstraintEngine
from src.generation.generator import CodeGenerator
from src.kripke.builder import build_kripke
from src.kripke.visualizer import create_pyvis
from src.models.states import AuthState
from src.modules.authentication import AuthenticationModule, LoginParams
from src.modules.email_notification import (
    EmailNotificationModule,
    EmailParams,
    MockEmailTransport,
)
from src.specification.loader import load_project_spec
from src.specification.schemas import FunctionSpec
from src.testing.dynamic import run_coverage, run_pytest
from src.testing.static import run_mypy, run_ruff
from src.verification.constraints import (
    AUTH_CONSTRAINTS,
    EMAIL_CONSTRAINTS,
    verify_constraints,
)

st.set_page_config(
    page_title="LMS Security Simulator",
    page_icon="🔐",
    layout="wide",
)


@st.cache_data
def load_specs():
    try:
        return load_project_spec("specs")
    except (OSError, ValueError, yaml.YAMLError):
        return []


def render_summary(specifications):
    total_functions = sum(len(spec.functions) for spec in specifications)
    total_states = sum(
        len(function.states) for spec in specifications for function in spec.functions
    )
    total_params = sum(
        len(function.parameters) for spec in specifications for function in spec.functions
    )

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Functions", total_functions)
    col2.metric("States", total_states)
    col3.metric("Parameters", total_params)
    col4.metric("Specifications", len(specifications))


def select_function(functions: list[FunctionSpec], key: str) -> FunctionSpec:
    selected_index = st.selectbox(
        "Function",
        options=range(len(functions)),
        format_func=lambda index: functions[index].name,
        key=key,
    )
    return functions[selected_index]


def parameter_defaults(function: FunctionSpec) -> dict[str, object]:
    return {parameter.name: parameter.default for parameter in function.parameters}


def parameter_value(defaults: dict[str, object], name: str, fallback: object) -> object:
    value = defaults.get(name)
    return fallback if value is None else value


def run_function_scenario(function: FunctionSpec) -> dict[str, object]:
    defaults = parameter_defaults(function)
    if function.name.lower() == "authentication":
        auth = AuthenticationModule(
            LoginParams(
                max_attempts=int(parameter_value(defaults, "max_attempts", 3)),
                session_ttl_seconds=int(parameter_value(defaults, "session_ttl_seconds", 3600)),
                min_password_length=int(parameter_value(defaults, "min_password_length", 8)),
            )
        )
        user = auth.register("streamlit-demo", "SecurePass123")
        session = auth.login("streamlit-demo", "SecurePass123")
        return {
            "Function": function.name,
            "Registration": "PASS",
            "Login": "PASS" if session is not None else "FAIL",
            "Session authentication": (
                "PASS"
                if session is not None and auth.authenticate(session.token) is user
                else "FAIL"
            ),
            "Final state": user.state.value,
        }

    if function.name.lower() == "emailnotification":
        email = EmailNotificationModule(
            EmailParams(max_retry=int(parameter_value(defaults, "max_retry", 2)))
        )
        notification = email.create(
            "student@example.com",
            "LMS demo notification",
            "Notification delivery test",
        )
        sent = email.send(
            notification.notification_id,
            MockEmailTransport(),
        )
        return {
            "Function": function.name,
            "Recipient validation": "PASS",
            "Send": "PASS" if sent else "FAIL",
            "Final state": notification.state.value,
            "Retries": notification.retry_count,
        }

    return {"Function": function.name, "Result": "No executable demo is registered."}


def validate_parameter_values(
    function: FunctionSpec,
    values: dict[str, object],
) -> list[dict[str, object]]:
    results = []
    for parameter in function.parameters:
        value = values[parameter.name]
        expected_type = parameter.type.lower()
        if expected_type in {"integer", "int"}:
            valid = isinstance(value, int) and not isinstance(value, bool)
        elif expected_type in {"boolean", "bool"}:
            valid = isinstance(value, bool)
        else:
            valid = isinstance(value, str)

        if parameter.name in {"max_attempts", "session_ttl_seconds", "min_password_length"}:
            valid = valid and int(value) > 0
        elif parameter.name == "max_retry":
            valid = valid and int(value) >= 0

        results.append(
            {
                "Parameter": parameter.name,
                "Value": value,
                "Result": "PASS" if valid else "FAIL",
            }
        )
    return results


def analyze_state_graph(function: FunctionSpec) -> dict[str, object]:
    model = build_kripke(function)
    known_states = set(model.states)
    errors = []
    adjacency = {state: set() for state in known_states}
    for transition in model.transitions:
        if transition.source not in known_states or transition.target not in known_states:
            errors.append(
                f"Invalid transition: {transition.source} -> {transition.target}"
            )
        elif transition.source in adjacency:
            adjacency[transition.source].add(transition.target)

    reachable = set()
    if model.initial_state in known_states:
        pending = [model.initial_state]
        while pending:
            state = pending.pop()
            if state in reachable:
                continue
            reachable.add(state)
            pending.extend(adjacency[state] - reachable)
    else:
        errors.append("Initial state is not defined in the state list.")

    return {
        "model": model,
        "errors": errors,
        "reachable": reachable,
        "unreachable": known_states - reachable,
    }


def render_state_diagram(title: str, states: list[str], transitions: list[tuple[str, str, str]]):
    body = [
        "digraph state_flow {",
        "  rankdir=LR;",
        "  node [shape=circle, style=filled, fillcolor=\"#EAF2FF\", color=\"#4C78A8\"];",
        "  edge [color=\"#2F6B9F\", fontcolor=\"#1F2937\"];",
    ]
    for state in states:
        body.append(f'  "{state}";')
    for src, dest, label in transitions:
        body.append(f'  "{src}" -> "{dest}" [label="{label}"];')
    body.append("}")

    st.subheader(title)
    st.graphviz_chart("\n".join(body))


st.title("LMS Software Security Simulator")
st.caption("End-to-End Software Security Verification Pipeline")

with st.sidebar:
    st.title("Project Status")
    st.caption("Educational model; results appear after each check runs.")
    st.markdown(
        """
        - Authentication workflow modeled
        - Email notification workflow modeled
        - Kripke-state verification enabled
        - C buffer analysis integrated
        - Tests and report pipeline available
        """
    )

specifications = load_specs()
if specifications:
    render_summary(specifications)
else:
    st.warning(
        "No specification found. The project can still run and show the architecture, but no functional specs were loaded."
    )

st.markdown("---")

tabs = st.tabs(
    [
        "1. Functions",
        "2. Parameters",
        "3. States",
        "4. Constraints",
        "5. Kripke",
        "6. Code Generation",
        "7. Static Testing",
        "8. Dynamic Testing",
        "9. Report",
        "10. C Security Analysis",
    ]
)

with tabs[0]:
    st.header("Function Specification")

    functions = [function for spec in specifications for function in spec.functions]
    if not functions:
        st.warning("No specification found.")
    else:
        selected_function = select_function(functions, "function_scenario_selector")
        st.write(selected_function.description)
        st.write(
            "States: "
            + ", ".join(state.name for state in selected_function.states)
        )
        st.write(
            "Events: "
            + ", ".join(transition.event for transition in selected_function.transitions)
        )
        if st.button("Run function scenario", key="run_function_scenario"):
            st.session_state["function_result"] = run_function_scenario(selected_function)

        function_result = st.session_state.get("function_result")
        if function_result and function_result.get("Function") == selected_function.name:
            st.dataframe(pd.DataFrame([function_result]), width="stretch")

with tabs[1]:
    st.header("Parameters")
    functions = [function for spec in specifications for function in spec.functions]
    if functions:
        selected_function = select_function(functions, "parameter_function_selector")
        values = {}
        with st.form("parameter_validation_form"):
            for parameter in selected_function.parameters:
                default = parameter.default
                if parameter.type.lower() in {"integer", "int"}:
                    values[parameter.name] = st.number_input(
                        parameter.name,
                        value=int(default or 0),
                        step=1,
                        key=f"parameter_{selected_function.name}_{parameter.name}",
                    )
                elif parameter.type.lower() in {"boolean", "bool"}:
                    values[parameter.name] = st.checkbox(
                        parameter.name,
                        value=bool(default),
                        key=f"parameter_{selected_function.name}_{parameter.name}",
                    )
                else:
                    values[parameter.name] = st.text_input(
                        parameter.name,
                        value=str(default or ""),
                        key=f"parameter_{selected_function.name}_{parameter.name}",
                    )
            submitted = st.form_submit_button("Validate parameters")

        if submitted:
            st.session_state["parameter_result"] = {
                "function": selected_function.name,
                "checks": validate_parameter_values(selected_function, values),
            }

        parameter_result = st.session_state.get("parameter_result")
        if parameter_result and parameter_result["function"] == selected_function.name:
            st.dataframe(pd.DataFrame(parameter_result["checks"]), width="stretch")
            if all(row["Result"] == "PASS" for row in parameter_result["checks"]):
                st.success("All parameters passed validation.")
            else:
                st.error("One or more parameters failed validation.")
    else:
        st.info("No function parameters are available.")

with tabs[2]:
    st.header("States")
    functions = [function for spec in specifications for function in spec.functions]
    if functions:
        selected_function = select_function(functions, "state_function_selector")
        if st.button("Analyze state transitions", key="analyze_states"):
            analysis = analyze_state_graph(selected_function)
            model = analysis["model"]
            reachable = analysis["reachable"]
            st.session_state["state_result"] = {
                "function": selected_function.name,
                "states": [
                    {
                        "State": state.name,
                        "Initial": state.name == model.initial_state,
                        "Reachable": state.name in reachable,
                        "Description": next(
                            item.description
                            for item in selected_function.states
                            if item.name == state.name
                        ),
                    }
                    for state in model.states.values()
                ],
                "transitions": [
                    {
                        "Source": transition.source,
                        "Event": transition.label,
                        "Target": transition.target,
                    }
                    for transition in model.transitions
                ],
                "errors": analysis["errors"],
                "unreachable": sorted(analysis["unreachable"]),
            }

        state_result = st.session_state.get("state_result")
        if state_result and state_result["function"] == selected_function.name:
            st.dataframe(pd.DataFrame(state_result["states"]), width="stretch")
            st.subheader("Transitions")
            st.dataframe(pd.DataFrame(state_result["transitions"]), width="stretch")
            if state_result["errors"]:
                st.error("\n".join(state_result["errors"]))
            elif state_result["unreachable"]:
                st.warning(
                    "Unreachable states: " + ", ".join(state_result["unreachable"])
                )
            else:
                st.success("All declared states are reachable from the initial state.")
    else:
        st.info("No states are available.")

with tabs[3]:
    st.header("Constraint Verification")
    constraint_family = st.selectbox(
        "Constraint family",
        ["Authentication", "Email"],
        key="constraint_family",
    )
    matching_function = next(
        (
            function
            for spec in specifications
            for function in spec.functions
            if function.name.lower()
            == ("authentication" if constraint_family == "Authentication" else "emailnotification")
        ),
        None,
    )
    defaults = parameter_defaults(matching_function) if matching_function else {}

    with st.form("constraint_check_form"):
        if constraint_family == "Authentication":
            password = st.text_input("Password", value="SecurePass123")
            auth_state_name = st.selectbox(
                "Account state",
                [state.value for state in AuthState],
            )
            login_allowed = st.checkbox("Login is allowed", value=False)
            session_valid = st.checkbox("Session is valid", value=False)
            failed_attempts = st.number_input(
                "Failed attempts",
                min_value=0,
                value=0,
                step=1,
            )
            submitted = st.form_submit_button("Check authentication constraints")
        else:
            recipient = st.text_input("Recipient email", value="student@example.com")
            sent = st.checkbox("Notification sent", value=False)
            was_queued = st.checkbox("Was queued before sending", value=True)
            retry_count = st.number_input("Retry count", min_value=0, value=0, step=1)
            submitted = st.form_submit_button("Check email constraints")

    if submitted:
        if constraint_family == "Authentication":
            max_attempts = int(parameter_value(defaults, "max_attempts", 3))
            min_password_length = int(
                parameter_value(defaults, "min_password_length", 8)
            )
            context = {
                "password": password,
                "min_password_length": min_password_length,
                "state": AuthState(auth_state_name),
                "login_allowed": login_allowed,
                "failed_attempts": int(failed_attempts),
                "max_attempts": max_attempts,
                "session_valid": session_valid,
            }
            passed, errors = verify_constraints(AUTH_CONSTRAINTS, context)
            engine = Z3ConstraintEngine()
            engine.add_authentication_constraints(max_attempts, min_password_length)
            z3_result = "SAT" if engine.check() else "UNSAT"
            checks = [
                {
                    "Check": "Z3 formula consistency",
                    "Result": z3_result,
                },
                *[
                    {
                        "Check": constraint.name,
                        "Result": "PASS" if constraint.check(context) else "FAIL",
                    }
                    for constraint in AUTH_CONSTRAINTS
                ],
            ]
        else:
            max_retry = int(parameter_value(defaults, "max_retry", 2))
            context = {
                "valid_recipient": EmailNotificationModule.is_valid_email(recipient),
                "sent": sent,
                "was_queued": was_queued,
                "retry_count": int(retry_count),
                "max_retry": max_retry,
            }
            passed, errors = verify_constraints(EMAIL_CONSTRAINTS, context)
            checks = [
                {
                    "Check": constraint.name,
                    "Result": "PASS" if constraint.check(context) else "FAIL",
                }
                for constraint in EMAIL_CONSTRAINTS
            ]

        st.session_state["constraint_result"] = {
            "family": constraint_family,
            "passed": passed,
            "checks": checks,
            "errors": errors,
        }

    constraint_result = st.session_state.get("constraint_result")
    if constraint_result and constraint_result["family"] == constraint_family:
        st.dataframe(pd.DataFrame(constraint_result["checks"]), width="stretch")
        if constraint_result["passed"]:
            st.success(f"{constraint_family} constraints passed.")
        else:
            st.error(f"{constraint_family} constraints failed.")
        for error in constraint_result["errors"]:
            st.warning(error)
        if constraint_family == "Authentication":
            st.caption("Z3 SAT confirms consistency; it does not prove every input satisfies the requirements.")

with tabs[4]:
    st.header("Kripke Model")
    functions = [function for spec in specifications for function in spec.functions]
    if functions:
        selected_function = select_function(functions, "kripke_function_selector")
        if st.button("Build and validate Kripke model", key="build_kripke_model"):
            analysis = analyze_state_graph(selected_function)
            output = create_pyvis(
                analysis["model"],
                f"reports_{selected_function.name}.html",
            )
            st.session_state["kripke_result"] = {
                "function": selected_function.name,
                "states": len(analysis["model"].states),
                "transitions": len(analysis["model"].transitions),
                "errors": analysis["errors"],
                "unreachable": sorted(analysis["unreachable"]),
                "output": output,
            }

        kripke_result = st.session_state.get("kripke_result")
        if kripke_result and kripke_result["function"] == selected_function.name:
            st.metric("States", kripke_result["states"])
            st.metric("Transitions", kripke_result["transitions"])
            if kripke_result["errors"]:
                st.error("\n".join(kripke_result["errors"]))
            elif kripke_result["unreachable"]:
                st.warning("Unreachable states: " + ", ".join(kripke_result["unreachable"]))
            else:
                st.success("Kripke model is structurally valid and all states are reachable.")
            st.success(f"HTML graph created: {kripke_result['output']}")
            html = Path(kripke_result["output"]).read_text(encoding="utf-8")
            st.download_button(
                "Download Kripke HTML",
                data=html,
                file_name=Path(kripke_result["output"]).name,
                mime="text/html",
            )
    else:
        st.info("No function models are available.")

with tabs[5]:
    st.header("Code Generation")
    if st.button("Generate state enums", key="generate_state_enums"):
        generator = CodeGenerator()
        generated_files = [
            str(generator.generate_state_enum(function))
            for spec in specifications
            for function in spec.functions
        ]
        st.session_state["generated_state_files"] = generated_files

    for generated_file in st.session_state.get("generated_state_files", []):
        st.success(f"Generated: {generated_file}")
        generated_source = Path(generated_file).read_text(encoding="utf-8")
        st.code(generated_source, language="python")
        st.download_button(
            f"Download {Path(generated_file).name}",
            data=generated_source,
            file_name=Path(generated_file).name,
            mime="text/x-python",
            key=f"download_{Path(generated_file).name}",
        )

with tabs[6]:
    st.header("Static Testing")
    if st.button("Chạy kiểm tra tĩnh", key="run_static_check"):
        st.session_state["static_results"] = [run_ruff(), run_mypy()]

    static_results = st.session_state.get("static_results", [])
    if static_results:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Check": result["tool"],
                        "Result": "PASS" if result["passed"] else "FAIL",
                    }
                    for result in static_results
                ]
            ),
            width="stretch",
        )
        for result in static_results:
            with st.expander(f"{result['tool']} output"):
                st.code(result["command"], language="shell")
                st.code(
                    "\n".join(
                        part
                        for part in (result["stdout"], result["stderr"])
                        if part
                    )
                    or "No diagnostics."
                )
    else:
        st.info("Chưa chạy Ruff hoặc mypy trong phiên này.")

with tabs[7]:
    st.header("Dynamic Testing")
    if st.button("Chạy pytest", key="run_dynamic_check"):
        st.session_state["pytest_result"] = run_pytest()
    if st.button("Chạy pytest + coverage", key="run_coverage_check"):
        st.session_state["coverage_result"] = run_coverage()

    for result_key, title in (
        ("pytest_result", "Pytest"),
        ("coverage_result", "Coverage"),
    ):
        result = st.session_state.get(result_key)
        if result:
            status = "PASS" if result["passed"] else "FAIL"
            (st.success if result["passed"] else st.error)(f"{title}: {status}")
            with st.expander(f"{title} output"):
                st.code(
                    "\n".join(
                        part for part in (result["stdout"], result["stderr"]) if part
                    )
                    or "No output."
                )

with tabs[8]:
    st.header("Security Verification Report")
    report_rows = []
    constraint_result = st.session_state.get("constraint_result")
    if constraint_result:
        report_rows.append(
            {
                "Check": f"{constraint_result['family']} constraints",
                "Result": "PASS" if constraint_result["passed"] else "FAIL",
            }
        )
    function_result = st.session_state.get("function_result")
    if function_result:
        function_checks = [
            value for value in function_result.values() if value in {"PASS", "FAIL"}
        ]
        report_rows.append(
            {
                "Check": f"{function_result['Function']} scenario",
                "Result": "PASS" if function_checks and all(
                    value == "PASS" for value in function_checks
                ) else "FAIL",
            }
        )
    parameter_result = st.session_state.get("parameter_result")
    if parameter_result:
        report_rows.append(
            {
                "Check": f"{parameter_result['function']} parameters",
                "Result": "PASS"
                if all(row["Result"] == "PASS" for row in parameter_result["checks"])
                else "FAIL",
            }
        )
    state_result = st.session_state.get("state_result")
    if state_result:
        report_rows.append(
            {
                "Check": f"{state_result['function']} state graph",
                "Result": "PASS"
                if not state_result["errors"] and not state_result["unreachable"]
                else "FAIL",
            }
        )
    kripke_result = st.session_state.get("kripke_result")
    if kripke_result:
        report_rows.append(
            {
                "Check": f"{kripke_result['function']} Kripke model",
                "Result": "PASS"
                if not kripke_result["errors"] and not kripke_result["unreachable"]
                else "FAIL",
            }
        )
    generated_state_files = st.session_state.get("generated_state_files", [])
    if generated_state_files:
        report_rows.append(
            {
                "Check": "State code generation",
                "Result": "PASS"
                if all(Path(path).is_file() for path in generated_state_files)
                else "FAIL",
            }
        )
    for result in st.session_state.get("static_results", []):
        report_rows.append(
            {
                "Check": result["tool"],
                "Result": "PASS" if result["passed"] else "FAIL",
            }
        )
    for result_key, title in (("pytest_result", "Pytest"), ("coverage_result", "Coverage")):
        result = st.session_state.get(result_key)
        if result:
            report_rows.append(
                {"Check": title, "Result": "PASS" if result["passed"] else "FAIL"}
            )
    analysis_report = st.session_state.get("c_analysis_report")
    if analysis_report:
        report_rows.extend(
            {"Check": check["name"], "Result": check["status"]}
            for check in analysis_report["checks"]
        )

    if report_rows:
        st.dataframe(pd.DataFrame(report_rows), width="stretch")
        st.download_button(
            "Download session report (JSON)",
            data=json.dumps(report_rows, indent=2, ensure_ascii=False),
            file_name="softsec_session_report.json",
            mime="application/json",
        )
    else:
        st.info("Chạy một hoặc nhiều bước kiểm tra để tạo báo cáo phiên này.")

with tabs[9]:
    st.header("C Buffer Security Analysis")
    st.write(
        "Analyze the vulnerable and corrected memcpy examples with a bounded formal model, GCC diagnostics, optional CBMC, sanitizers, and deterministic mutation fuzzing."
    )
    st.info("The vulnerable C source is an isolated teaching example. Run it only through this analysis workflow.")

    col1, col2 = st.columns(2)
    with col1:
        iterations = st.number_input(
            "Fuzz iterations",
            min_value=1,
            max_value=100000,
            value=10000,
            step=100,
            key="fuzz_iterations",
        )
    with col2:
        seed = st.number_input(
            "Reproducible fuzz seed",
            min_value=0,
            max_value=100000000,
            value=12648430,
            step=1,
            key="fuzz_seed",
        )

    if st.button("Run end-to-end C analysis", key="run_c_analysis_button"):
        from src.c_analysis.runner import run_c_analysis

        try:
            analysis_report = run_c_analysis(iterations=int(iterations), seed=int(seed))
            st.session_state["c_analysis_report"] = analysis_report.to_dict()
        except (OSError, ValueError) as exc:
            st.error(f"C analysis could not be completed: {exc}")

    analysis_report = st.session_state.get("c_analysis_report")
    if analysis_report:
        render_state_diagram(
            "Sơ đồ trạng thái phân tích C",
            ["Input C", "Compile analysis", "CBMC check", "Sanitizer", "Fuzzing", "Final report"],
            [
                ("Input C", "Compile analysis", "build"),
                ("Compile analysis", "CBMC check", "formal"),
                ("CBMC check", "Sanitizer", "runtime"),
                ("Sanitizer", "Fuzzing", "explore"),
                ("Fuzzing", "Final report", "summary"),
            ],
        )
        st.caption(
            f"Generated at {analysis_report['generated_at']} · Report: {analysis_report['report_path']}"
        )
        chart_df = pd.DataFrame(
            {
                "Check": [check["name"] for check in analysis_report["checks"]],
                "StatusValue": [
                    {"PASS": 2, "FINDING": 1, "UNAVAILABLE": 0, "ERROR": -1}.get(
                        check["status"], 0
                    )
                    for check in analysis_report["checks"]
                ],
            }
        )
        st.bar_chart(chart_df.set_index("Check"), height=220)

        for check in analysis_report["checks"]:
            status = check["status"]
            message = f"**{check['name']} — {status}:** {check['summary']}"
            if status == "PASS":
                st.success(message)
            elif status == "FINDING":
                st.warning(message)
            elif status == "UNAVAILABLE":
                st.info(message)
            else:
                st.error(message)

            if check["command"]:
                st.code(check["command"], language="shell")
            if check["details"]:
                with st.expander(f"Details: {check['name']}"):
                    st.code(check["details"])
    else:
        st.info("Chưa chạy phân tích C. Bấm nút để xem mô phỏng counterexample, sanitizer và fuzzing.")
        render_state_diagram(
            "Sơ đồ trạng thái chờ chạy",
            ["Input C", "Compile", "Check", "Report"],
            [
                ("Input C", "Compile", "queued"),
                ("Compile", "Check", "pending"),
                ("Check", "Report", "waiting"),
            ],
        )
