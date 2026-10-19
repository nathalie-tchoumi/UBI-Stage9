"""Tests for the containment/recovery action planner. No action is ever
executed; these tests validate the plan's structure and safety
ordering only."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
from detections.containment.actions import build_response_plan, ContainmentAction


def test_plan_is_list_of_containment_actions():
    plan = build_response_plan()
    assert len(plan) > 0
    assert all(isinstance(a, ContainmentAction) for a in plan)


def test_preservation_precedes_all_destructive_actions():
    plan = build_response_plan()
    destructive_indices = [i for i, a in enumerate(plan) if a.destructive]
    preservation_indices = [i for i, a in enumerate(plan) if a.action_type == "evidence_preservation"]
    assert preservation_indices, "no evidence preservation action found"
    assert min(destructive_indices) > min(preservation_indices)


def test_all_actions_target_confirmed_evidence():
    plan = build_response_plan()
    known_confirmed_locators = {
        "sysmon.jsonl:line:50001-50006",
        "sysmon.jsonl:line:50002",
        "sysmon.jsonl:line:50003",
        "incident.pcap:frame:49",
    }
    for action in plan:
        assert action.evidence_locator in known_confirmed_locators


def test_no_action_module_has_execution_capability():
    import detections.containment.actions as actions_module
    import inspect
    source = inspect.getsource(actions_module)
    forbidden = ["subprocess", "os.system", "os.popen", "socket.", "paramiko"]
    for token in forbidden:
        assert token not in source


if __name__ == "__main__":
    test_plan_is_list_of_containment_actions()
    test_preservation_precedes_all_destructive_actions()
    test_all_actions_target_confirmed_evidence()
    test_no_action_module_has_execution_capability()
    print("All containment action tests: PASS")
