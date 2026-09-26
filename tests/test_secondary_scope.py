"""D-034: secondary sources may only feed weakness_mechanism and attack_steps, and a secondary
step carries no ATT&CK mapping. No model, no network."""

import pytest

from src.merge import MergeError, merge_additions, parse_additions
from tests.test_merge import base_pack, step
from tests.test_secondary import PAGE

ATTACK = "https://attack.mitre.org/techniques/T1558/003"
T1190 = "https://attack.mitre.org/techniques/T1190"  # the default source of tests.test_merge.step()


def sec(text="A claim from a vendor page", url=PAGE):
    return {"value": text, "tag": "secondary", "source_url": url}


def merged(additions):
    return merge_additions(base_pack(False), parse_additions(additions), allowed_urls={PAGE, ATTACK, T1190})


# ---- where secondary may be used -------------------------------------------------------


def test_secondary_is_allowed_in_mechanism_and_steps():
    pack = merged({"weakness_mechanism": [sec()], "attack_steps": [{"number": 1, "action": sec()}]})
    assert pack.attack_steps[0].action.tag.value == "secondary"


@pytest.mark.parametrize(
    "additions, where",
    [
        ({"detection_items": [{"kind": "telemetry", "content": sec()}]}, r"detection_items\.0\.content"),
        ({"response_items": [{"kind": "hardening", "content": sec()}]}, r"response_items\.0\.content"),
        (
            {"conflicts": [{"subject": "s", "claims": [sec(), sec("Another claim")]}]},
            r"conflicts\.0\.claims\.0",
        ),
    ],
)
def test_secondary_is_rejected_outside_mechanism_and_steps(additions, where):
    with pytest.raises(MergeError, match=where + r".*only allowed for weakness_mechanism and attack_steps"):
        merged(additions)


def test_the_same_items_are_fine_as_inference():
    pack = merged({
        "detection_items": [{"kind": "telemetry", "content": {"value": "Web logs", "tag": "inference"}}],
        "response_items": [{"kind": "hardening", "content": {"value": "Update it", "tag": "inference"}}],
    })
    assert len(pack.detection_items) == 1 and len(pack.response_items) == 1


# ---- ATT&CK mapping on steps -------------------------------------------------------------


def test_secondary_step_cannot_carry_an_attack_technique_id():
    step_ = {"number": 1, "action": sec(), "mitre_technique": "T1558.003"}
    with pytest.raises(MergeError, match=r"attack_steps\.0\.mitre_technique.*secondary"):
        merged({"attack_steps": [step_]})


def test_secondary_step_without_a_technique_id_passes():
    merged({"attack_steps": [{"number": 1, "action": sec(), "mitre_technique": None}]})


def test_documented_step_may_still_carry_its_technique_id():
    pack = merged({"attack_steps": [step(1)]})  # documented, T1190, as before
    assert pack.attack_steps[0].mitre_technique == "T1190"


def test_all_problems_are_reported_together():
    with pytest.raises(MergeError) as info:
        merged({
            "detection_items": [{"kind": "telemetry", "content": sec()}],
            "attack_steps": [{"number": 1, "action": sec(), "mitre_technique": "T1558.003"}],
        })
    assert "detection_items.0.content" in str(info.value) and "attack_steps.0.mitre_technique" in str(info.value)
