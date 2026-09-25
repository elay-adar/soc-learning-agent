"""Tests for src/merge.py: the agent may add entries but never change code-owned facts."""

import json
from pathlib import Path

import pytest

from src.facts import assemble_pack
from src.merge import MergeError, is_official_url, merge_additions, parse_additions
from src.schemas import ExploitationStatus
from src.sources.kev import parse_kev_catalog
from src.sources.nvd import parse_nvd_response

FIXTURES = Path(__file__).parent / "fixtures"


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def base_pack(listed_in_kev: bool):
    data = load("nvd_synthetic_analyzed.json")
    if listed_in_kev:
        data["vulnerabilities"][0]["cve"]["id"] = "CVE-2021-44228"
    record = parse_nvd_response(data)
    return assemble_pack(record, parse_kev_catalog(load("kev_sample.json")))


def sourced(text, tag="documented", url="https://attack.mitre.org/techniques/T1190"):
    item = {"value": text, "tag": tag}
    if url:
        item["source_url"] = url
    return item


def step(number, text="Attacker sends a crafted request"):
    return {"number": number, "action": sourced(text), "mitre_technique": "T1190"}


def test_additions_are_appended_and_code_owned_fields_stay_the_same():
    base = base_pack(listed_in_kev=False)
    additions = parse_additions(
        {
            "weakness_mechanism": [sourced("The parser trusts input", tag="inference", url=None)],
            "attack_steps": [step(1), step(2, "Attacker runs code")],
            "detection_items": [
                {"kind": "telemetry", "content": sourced("Web server logs", "inference", None), "step": 1}
            ],
        }
    )
    merged = merge_additions(base, additions)

    assert len(merged.attack_steps) == 2 and len(merged.detection_items) == 1
    assert len(merged.weakness_mechanism) == len(base.weakness_mechanism) + 1
    assert merged.weakness_mechanism[: len(base.weakness_mechanism)] == base.weakness_mechanism
    for owned in ("topic", "topic_type", "exploitation_status", "exploitation_evidence", "triage_fields"):
        assert getattr(merged, owned) == getattr(base, owned)


def test_base_pack_is_not_modified():
    base = base_pack(False)
    before = base.model_dump()
    merge_additions(base, parse_additions({"attack_steps": [step(1)]}))
    assert base.model_dump() == before


@pytest.mark.parametrize(
    "forbidden",
    [
        {"exploitation_status": "documented"},
        {"exploitation_evidence": sourced("made up")},
        {"triage_fields": {}},
        {"topic": "something else"},
        {"topic_type": "technique"},
        {"invented_field": 1},
    ],
)
def test_attempt_to_set_a_code_owned_or_unknown_field_is_rejected(forbidden):
    with pytest.raises(MergeError, match="Extra inputs are not permitted"):
        parse_additions({"attack_steps": [step(1)], **forbidden})


def test_incidents_are_rejected_when_exploitation_is_not_documented():
    base = base_pack(listed_in_kev=False)
    assert base.exploitation_status == ExploitationStatus.NOT_DOCUMENTED
    additions = parse_additions(
        {"incidents": [{"name": "Made-up breach", "impact": sourced("Data stolen")}]}
    )
    with pytest.raises(MergeError, match="only allowed when exploitation is documented"):
        merge_additions(base, additions)


def test_incidents_are_accepted_when_exploitation_is_documented():
    base = base_pack(listed_in_kev=True)
    assert base.exploitation_status == ExploitationStatus.DOCUMENTED
    additions = parse_additions(
        {"incidents": [{"name": "Example incident", "impact": sourced("Disclosed impact")}]}
    )
    assert len(merge_additions(base, additions).incidents) == 1


def test_documented_item_without_a_source_is_rejected():
    with pytest.raises(MergeError, match="source_url"):
        parse_additions({"weakness_mechanism": [sourced("Claim", "documented", None)]})


def test_step_numbering_gap_is_rejected():
    additions = parse_additions({"attack_steps": [step(1), step(3)]})
    with pytest.raises(MergeError, match="without gaps"):
        merge_additions(base_pack(False), additions)


def test_detection_item_pointing_at_a_missing_step_is_rejected():
    additions = parse_additions(
        {
            "attack_steps": [step(1)],
            "detection_items": [
                {"kind": "event_id", "content": sourced("Event 4769", "inference", None), "step": 5}
            ],
        }
    )
    with pytest.raises(MergeError, match="missing attack step 5"):
        merge_additions(base_pack(False), additions)


def test_bad_json_and_wrong_shape_are_reported():
    with pytest.raises(MergeError, match="not valid JSON"):
        parse_additions("{not json")
    with pytest.raises(MergeError, match="JSON object"):
        parse_additions("[1, 2]")


def test_error_message_names_the_field_so_it_can_be_sent_back_to_the_agent():
    with pytest.raises(MergeError, match=r"attack_steps\.0\.number"):
        parse_additions({"attack_steps": [{**step(1), "number": 0}]})


def test_json_text_input_works():
    additions = parse_additions(json.dumps({"attack_steps": [step(1)]}))
    assert len(additions.attack_steps) == 1


def test_empty_additions_return_an_equal_pack():
    base = base_pack(False)
    assert merge_additions(base, parse_additions({})) == base


# ---- official-source check on documented claims ----


@pytest.mark.parametrize(
    "url, ok",
    [
        ("https://nvd.nist.gov/vuln/detail/CVE-2021-44228", True),
        ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog", True),
        ("https://attack.mitre.org/techniques/T1558/003", True),
        ("https://cwe.mitre.org/data/definitions/502.html", True),
        ("https://blog.example.com/log4shell", False),
        ("https://nvd.nist.gov.evil.example/x", False),
        ("https://evil.example/?u=nvd.nist.gov", False),
        ("https://user@evil.example/nvd.nist.gov", False),
        ("https://notnvd.nist.gov.example", False),
    ],
)
def test_official_url_check(url, ok):
    assert is_official_url(url) is ok


def test_documented_claim_citing_a_blog_is_rejected_at_merge():
    additions = parse_additions(
        {"attack_steps": [{"number": 1, "action": sourced("Step", url="https://blog.example.com/x")}]}
    )
    with pytest.raises(MergeError, match=r"attack_steps\.0\.action.*not an official source"):
        merge_additions(base_pack(False), additions)


def test_inference_without_a_url_is_still_fine():
    additions = parse_additions(
        {"weakness_mechanism": [sourced("A guess", tag="inference", url=None)]}
    )
    merge_additions(base_pack(False), additions)
