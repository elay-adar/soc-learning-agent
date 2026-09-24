"""Tests for src/schemas.py. Run from the repo root: python -m pytest"""

import pytest
from pydantic import ValidationError

from src.schemas import (
    ExploitationStatus,
    KnowledgePack,
    ProvenanceTag,
    SourcedValue,
    StagePlan,
)

NVD = "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


def documented(text: str, url: str = NVD) -> dict:
    return {"value": text, "tag": "documented", "source_url": url}


def valid_pack() -> dict:
    """A small but complete example that must pass validation."""
    return {
        "topic": "Example vulnerability",
        "topic_type": "cve",
        "exploitation_status": "documented",
        "exploitation_evidence": documented("Listed in the KEV catalog", KEV),
        "incidents": [
            {"name": "Example incident", "impact": documented("Service disruption")}
        ],
        "triage_fields": {
            "severity": {"status": "value", "item": documented("CVSS 10.0")},
            "epss": {"status": "unknown"},
            "cvss_note": {"status": "not_applicable"},
        },
        "weakness_mechanism": [documented("Untrusted input is evaluated by the logger")],
        "attack_steps": [
            {"number": 1, "action": documented("Attacker sends crafted input")},
            {"number": 2, "action": documented("Server fetches attacker payload")},
        ],
        "detection_items": [
            {
                "kind": "detection_gap",
                "content": {"value": "Default logging misses the request", "tag": "inference"},
                "step": 1,
            }
        ],
        "response_items": [
            {"kind": "hardening", "content": {"value": "Update the library", "tag": "inference"}}
        ],
        "conflicts": [],
    }


def valid_plan() -> dict:
    return {
        "stages": [
            {"number": 1, "subject": "Overview", "depth": "overview", "diagram": "story_flow"},
            {
                "number": 2,
                "subject": "Attack chain",
                "depth": "technical",
                "diagram": "kill_chain_frames",
                "covers_steps": [1, 2],
            },
        ]
    }


# ---- valid examples pass ---------------------------------------------------


def test_valid_pack_passes():
    pack = KnowledgePack.model_validate(valid_pack())
    assert pack.exploitation_status == ExploitationStatus.DOCUMENTED
    assert len(pack.attack_steps) == 2


def test_valid_plan_passes_and_matches_pack():
    pack = KnowledgePack.model_validate(valid_pack())
    plan = StagePlan.model_validate(valid_plan())
    plan.check_against(pack)
    assert plan.stage_count == 2


def test_pack_survives_json_round_trip():
    pack = KnowledgePack.model_validate(valid_pack())
    again = KnowledgePack.model_validate_json(pack.model_dump_json())
    assert again == pack


# ---- invalid examples are rejected ------------------------------------------


def test_documented_item_without_source_is_rejected():
    with pytest.raises(ValidationError):
        SourcedValue(value="A claim", tag=ProvenanceTag.DOCUMENTED)


def test_inference_item_does_not_need_source():
    item = SourcedValue(value="A guess", tag=ProvenanceTag.INFERENCE)
    assert item.source_url is None


def test_status_outside_the_enum_is_rejected():
    data = valid_pack()
    data["exploitation_status"] = "probably_exploited"
    with pytest.raises(ValidationError):
        KnowledgePack.model_validate(data)


def test_provenance_tag_outside_the_enum_is_rejected():
    data = valid_pack()
    data["weakness_mechanism"][0]["tag"] = "Documented"  # capital D is not allowed
    with pytest.raises(ValidationError):
        KnowledgePack.model_validate(data)


def test_not_documented_status_cannot_carry_incidents():
    data = valid_pack()
    data["exploitation_status"] = "not_documented"
    data["exploitation_evidence"] = None  # incidents still present, so it must fail
    with pytest.raises(ValidationError):
        KnowledgePack.model_validate(data)


def test_documented_status_needs_evidence():
    data = valid_pack()
    data["exploitation_evidence"] = None
    with pytest.raises(ValidationError):
        KnowledgePack.model_validate(data)


def test_attack_steps_must_be_numbered_without_gaps():
    data = valid_pack()
    data["attack_steps"][1]["number"] = 3
    with pytest.raises(ValidationError):
        KnowledgePack.model_validate(data)


def test_detection_item_cannot_point_to_missing_step():
    data = valid_pack()
    data["detection_items"][0]["step"] = 9
    with pytest.raises(ValidationError):
        KnowledgePack.model_validate(data)


def test_unknown_field_is_rejected():
    data = valid_pack()
    data["invented_field"] = "surprise"
    with pytest.raises(ValidationError):
        KnowledgePack.model_validate(data)


def test_triage_value_status_needs_an_item():
    data = valid_pack()
    data["triage_fields"]["severity"] = {"status": "value"}
    with pytest.raises(ValidationError):
        KnowledgePack.model_validate(data)


def test_plan_referring_to_missing_step_is_rejected():
    pack = KnowledgePack.model_validate(valid_pack())
    data = valid_plan()
    data["stages"][1]["covers_steps"] = [1, 7]
    plan = StagePlan.model_validate(data)  # the plan alone is well formed
    with pytest.raises(ValueError):
        plan.check_against(pack)  # but it does not fit this pack


def test_plan_numbering_gap_is_rejected():
    data = valid_plan()
    data["stages"][1]["number"] = 4
    with pytest.raises(ValidationError):
        StagePlan.model_validate(data)
