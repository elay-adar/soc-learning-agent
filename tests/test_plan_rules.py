"""Tests for src/plan_rules.py. Never calls a model or the network."""

import copy

import pytest

from src.plan_rules import PlanRuleError, check_plan
from src.schemas import KnowledgePack, StagePlan
from src.stages_config import DEFAULT_STAGES_PATH, load_stages_config

CONFIG = load_stages_config(DEFAULT_STAGES_PATH)

SRC = "https://nvd.nist.gov/vuln/detail/CVE-0000-0000"


def documented(text):
    return {"value": text, "tag": "documented", "source_url": SRC}


def pack(steps=2):
    return KnowledgePack.model_validate(
        {
            "topic": "CVE-0000-0000",
            "topic_type": "cve",
            "exploitation_status": "unknown",
            "attack_steps": [
                {"number": n, "action": documented(f"Step {n}")} for n in range(1, steps + 1)
            ],
        }
    )


ITEMS = {
    "overview": ("overview", "story_flow", []),
    "why_possible": ("technical", "architecture", []),
    "attack_chain": ("technical", "kill_chain_frames", [1, 2]),
    "analyst_view": ("operational", "detection_flow", []),
    "response_prevention": ("operational", "decision_tree", []),
}


def plan_of(*keys, **overrides):
    """A plan made of the given stage keys. overrides: key -> dict of fields to replace."""
    stages = []
    for number, key in enumerate(keys, start=1):
        depth, diagram, covers = ITEMS[key]
        item = {
            "number": number, "key": key, "subject": key,
            "depth": depth, "diagram": diagram, "covers_steps": covers,
        }
        item.update(overrides.get(key, {}))
        stages.append(item)
    return StagePlan.model_validate({"stages": stages})


THREE = ("overview", "why_possible", "response_prevention")
FOUR = ("overview", "why_possible", "attack_chain", "response_prevention")
FIVE = ("overview", "why_possible", "attack_chain", "analyst_view", "response_prevention")


@pytest.mark.parametrize("keys", [THREE, FOUR, FIVE, ("overview", "why_possible", "analyst_view", "response_prevention")])
def test_valid_plans_pass(keys):
    check_plan(plan_of(*keys), pack(), CONFIG)


def test_three_stage_plan_keeps_stages_1_2_and_5():
    plan = plan_of(*THREE)
    assert [s.key for s in plan.stages] == ["overview", "why_possible", "response_prevention"]
    check_plan(plan, pack(), CONFIG)


@pytest.mark.parametrize(
    "keys, missing",
    [
        (("overview", "why_possible"), "response_prevention"),
        (("overview", "why_possible", "attack_chain"), "response_prevention"),
        (("overview", "response_prevention"), "why_possible"),
        (("why_possible", "attack_chain", "response_prevention"), "overview"),
    ],
)
def test_required_stages_are_enforced(keys, missing):
    with pytest.raises(PlanRuleError, match=missing):
        check_plan(plan_of(*keys), pack(), CONFIG)


def test_unknown_key_is_rejected():
    plan = plan_of(*THREE)
    data = plan.model_dump()
    data["stages"][1]["key"] = "deep_dive"
    with pytest.raises(PlanRuleError, match="deep_dive"):
        check_plan(StagePlan.model_validate(data), pack(), CONFIG)


def test_duplicate_key_is_rejected():
    plan = plan_of("overview", "why_possible", "why_possible", "response_prevention")
    with pytest.raises(PlanRuleError, match="more than once"):
        check_plan(plan, pack(), CONFIG)


def test_stages_must_follow_definition_order():
    plan = plan_of("overview", "why_possible", "analyst_view", "attack_chain", "response_prevention")
    with pytest.raises(PlanRuleError, match="order"):
        check_plan(plan, pack(), CONFIG)


def test_depth_outside_the_allowed_list_is_rejected():
    plan = plan_of(*THREE, overview={"depth": "technical"})
    with pytest.raises(PlanRuleError, match="depth"):
        check_plan(plan, pack(), CONFIG)


def test_diagram_outside_the_allowed_list_is_rejected():
    plan = plan_of(*THREE, why_possible={"diagram": "decision_tree"})
    with pytest.raises(PlanRuleError, match="diagram"):
        check_plan(plan, pack(), CONFIG)


def test_stage_2_may_use_a_sequence_diagram_and_conceptual_depth():
    plan = plan_of(*THREE, why_possible={"diagram": "sequence", "depth": "conceptual"})
    check_plan(plan, pack(), CONFIG)


def test_attack_chain_must_cover_every_step():
    with pytest.raises(PlanRuleError, match="every attack step"):
        check_plan(plan_of(*FOUR, attack_chain={"covers_steps": [1]}), pack(steps=2), CONFIG)


def test_attack_chain_needs_attack_steps_in_the_pack():
    with pytest.raises(PlanRuleError, match="no attack steps"):
        check_plan(plan_of(*FOUR, attack_chain={"covers_steps": []}), pack(steps=0), CONFIG)


def test_plan_without_attack_chain_is_fine_for_a_pack_without_steps():
    check_plan(plan_of(*THREE), pack(steps=0), CONFIG)


def test_missing_attack_step_reference_is_rejected():
    with pytest.raises(PlanRuleError, match="missing attack steps"):
        check_plan(plan_of(*FOUR, attack_chain={"covers_steps": [1, 2, 3]}), pack(steps=2), CONFIG)


def test_all_problems_are_reported_together():
    plan = plan_of("overview", "why_possible", overview={"diagram": "decision_tree"})
    with pytest.raises(PlanRuleError) as info:
        check_plan(plan, pack(), CONFIG)
    text = str(info.value)
    assert "diagram" in text and "response_prevention" in text


def test_check_does_not_change_the_plan():
    plan = plan_of(*FIVE)
    before = copy.deepcopy(plan)
    check_plan(plan, pack(), CONFIG)
    assert plan == before
