import pytest

from src.testing.scenarios import (
    SCENARIOS,
    run_e2e_scenarios,
    scenario_catalogue,
)


def test_catalogue_exposes_every_declared_scenario():
    catalogue = scenario_catalogue()

    assert len(catalogue) == len(SCENARIOS)
    assert [row["ID"] for row in catalogue] == [scenario.id for scenario in SCENARIOS]
    assert all(
        row["Steps"] and row["Expected"] and row["Scenario"] for row in catalogue
    )


def test_scenario_ids_are_unique_and_cover_every_family():
    ids = [scenario.id for scenario in SCENARIOS]
    families = {scenario.function for scenario in SCENARIOS}

    assert len(ids) == len(set(ids))
    assert {
        "Authentication",
        "EmailNotification",
        "Verification",
        "End-to-end",
    } <= families


@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s.id for s in SCENARIOS])
def test_each_scenario_declares_and_passes(scenario):
    passed, evidence = scenario.check()

    assert passed, f"{scenario.id} failed: {evidence}"
    assert isinstance(evidence, str) and evidence


def test_run_all_scenarios_reports_pass():
    results = run_e2e_scenarios()

    assert len(results) == len(SCENARIOS)
    failed = [row for row in results if row["Result"] != "PASS"]
    assert not failed, f"failing scenarios: {[row['ID'] for row in failed]}"
    assert all(row["Evidence"] for row in results)
