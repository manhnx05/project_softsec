import streamlit as st
import yaml

from src.constraints.z3_solver import (
    Z3ConstraintEngine,
)
from src.kripke.builder import build_kripke
from src.kripke.visualizer import create_pyvis
from src.specification.loader import load_project_spec

st.set_page_config(
    page_title="LMS Security Simulator",
    page_icon="🔐",
    layout="wide",
)


st.title("LMS Software Security Simulator")

st.caption(
    "End-to-End Software Security Verification Pipeline"
)


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


try:
    specifications = load_project_spec("specs")

except (OSError, ValueError, yaml.YAMLError) as exc:

    st.error(
        f"Cannot load specification: {exc}"
    )

    specifications = []


# ============================================================
# FUNCTIONS
# ============================================================

with tabs[0]:

    st.header("Function Specification")

    if not specifications:

        st.warning(
            "No specification found."
        )

    else:

        for spec in specifications:

            st.subheader(
                spec.project_name
            )

            for function in spec.functions:

                st.write(
                    f"**Function:** {function.name}"
                )

                st.write(
                    function.description
                )


# ============================================================
# PARAMETERS
# ============================================================

with tabs[1]:

    st.header("Parameters")

    for spec in specifications:

        for function in spec.functions:

            st.subheader(function.name)

            for parameter in function.parameters:

                st.metric(
                    parameter.name,
                    parameter.default,
                )


# ============================================================
# STATES
# ============================================================

with tabs[2]:

    st.header("States")

    for spec in specifications:

        for function in spec.functions:

            st.subheader(function.name)

            for state in function.states:

                st.write(
                    f"• `{state.name}` — "
                    f"{state.description}"
                )


# ============================================================
# CONSTRAINTS
# ============================================================

with tabs[3]:

    st.header("Constraint Verification")

    engine = Z3ConstraintEngine()

    engine.add_authentication_constraints(
        max_attempts=3,
        min_password_length=8,
    )

    if engine.check():

        st.success(
            "All Z3 constraints are SAT."
        )

    else:

        st.error(
            "Constraint verification failed."
        )


# ============================================================
# KRIPKE
# ============================================================

with tabs[4]:

    st.header("Kripke Model")

    for spec in specifications:

        for function in spec.functions:

            st.subheader(function.name)

            model = build_kripke(function)

            st.write(
                f"States: {len(model.states)}"
            )

            st.write(
                f"Transitions: "
                f"{len(model.transitions)}"
            )

            output = create_pyvis(
                model,
                f"reports_{function.name}.html",
            )

            st.success(
                f"Kripke model generated: {output}"
            )


# ============================================================
# CODE GENERATION
# ============================================================

with tabs[5]:

    st.header("Code Generation")

    st.info(
        "Generate Python source code "
        "from the specification."
    )


# ============================================================
# STATIC TESTING
# ============================================================

with tabs[6]:

    st.header("Static Testing")

    st.code(
        "ruff check src\n"
        "mypy src"
    )


# ============================================================
# DYNAMIC TESTING
# ============================================================

with tabs[7]:

    st.header("Dynamic Testing")

    st.code(
        "pytest -v\n"
        "pytest --cov=src"
    )


# ============================================================
# REPORT
# ============================================================

with tabs[8]:

    st.header("Security Verification Report")

    st.write(
        "Pipeline:"
    )

    st.code(
        """
Function
   ↓
Parameters
   ↓
States
   ↓
Constraints
   ↓
Kripke Model
   ↓
Code Generation
   ↓
Static Testing
   ↓
Dynamic Testing
   ↓
Security Report
"""
    )


# ============================================================
# C SECURITY ANALYSIS
# ============================================================

with tabs[9]:

    st.header("C Buffer Security Analysis")

    st.write(
        "Analyze the vulnerable and corrected memcpy examples with a bounded "
        "formal model, GCC diagnostics, optional CBMC, sanitizers, and "
        "deterministic mutation fuzzing."
    )

    st.warning(
        "The vulnerable C source is an isolated teaching example. "
        "Run it only through this analysis workflow."
    )

    iterations = st.number_input(
        "Fuzz iterations",
        min_value=1,
        max_value=1_000_000,
        value=10_000,
        step=1_000,
    )
    seed = st.number_input(
        "Reproducible fuzz seed",
        min_value=0,
        max_value=4_294_967_295,
        value=12_648_430,
        step=1,
    )

    if st.button("Run end-to-end C analysis"):
        from src.c_analysis.runner import run_c_analysis

        try:
            analysis_report = run_c_analysis(
                iterations=int(iterations),
                seed=int(seed),
            )
            st.session_state["c_analysis_report"] = analysis_report.to_dict()
        except (OSError, ValueError) as exc:
            st.error(f"C analysis could not be completed: {exc}")

    analysis_report = st.session_state.get("c_analysis_report")
    if analysis_report:
        st.caption(
            f"Generated at {analysis_report['generated_at']} · "
            f"Report: {analysis_report['report_path']}"
        )

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