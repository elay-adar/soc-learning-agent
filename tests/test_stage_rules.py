"""Tests for src/stage_content.py and src/stage_rules.py. Never calls a model or the network."""

import pytest
from pydantic import ValidationError

from src.schemas import KnowledgePack, StagePlanItem
from src.stage_content import StageContent
from src.stage_rules import NO_INCIDENT_PHRASE, StageRuleError, check_stage, pack_urls

NVD = "https://nvd.nist.gov/vuln/detail/CVE-0000-0000"
KEV = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
INC = "https://www.cisa.gov/news-events/alerts/example-incident"

FLOW = 'flowchart LR\n    W["Weakness"] --> A["Attack"] --> D["Damage"]\n'
SEQ = 'sequenceDiagram\n    participant C as Client\n    participant S as Server\n    C->>S: input\n'


def doc(text, url=NVD):
    return {"value": text, "tag": "documented", "source_url": url}


def inf(text):
    return {"value": text, "tag": "inference"}


def make_pack(status="documented"):
    data = {
        "topic": "CVE-0000-0000",
        "topic_type": "cve",
        "exploitation_status": status,
        "weakness_mechanism": [doc("Input is evaluated by the logger")],
        "attack_steps": [{"number": 1, "action": doc("Attacker sends input")}],
    }
    if status == "documented":
        data["exploitation_evidence"] = doc("Listed in KEV", KEV)
        data["incidents"] = [{"name": "Example incident", "impact": doc("Servers were taken over", INC)}]
    return KnowledgePack.model_validate(data)


def item(number, key, diagram, depth):
    return StagePlanItem(number=number, key=key, subject="s", depth=depth, diagram=diagram)


OVERVIEW = item(1, "overview", "story_flow", "overview")
WHY = item(2, "why_possible", "architecture", "technical")


def stage1(*blocks, diagram=FLOW):
    return StageContent.model_validate(
        {"stage_number": 1, "key": "overview", "title": "Overview", "blocks": list(blocks),
         "diagram": {"type": "story_flow", "mermaid": diagram}}
    )


def stage2(*blocks, diagram=FLOW, dtype="architecture"):
    return StageContent.model_validate(
        {"stage_number": 2, "key": "why_possible", "title": "Why", "blocks": list(blocks),
         "diagram": {"type": dtype, "mermaid": diagram}}
    )


DOCUMENTED_STAGE1 = (doc("Servers were taken over", INC), doc("Listed in KEV", KEV))


# ---- schema ----------------------------------------------------------------


def test_content_needs_at_least_one_block():
    with pytest.raises(ValidationError):
        stage1()


def test_documented_block_needs_a_source():
    with pytest.raises(ValidationError):
        stage1({"value": "x", "tag": "documented"})


def test_unknown_field_is_rejected():
    with pytest.raises(ValidationError):
        StageContent.model_validate(
            {"stage_number": 1, "key": "overview", "title": "t", "blocks": [inf("x")],
             "diagram": {"type": "story_flow", "mermaid": FLOW}, "extra": 1}
        )


# ---- generic rules -----------------------------------------------------------


def test_pack_urls_collects_every_source():
    urls = pack_urls(make_pack())
    assert {NVD, KEV, INC} <= urls


def test_valid_documented_stage1_passes():
    check_stage(stage1(*DOCUMENTED_STAGE1), make_pack(), OVERVIEW)


def test_wrong_stage_number_key_or_diagram_type_is_rejected():
    content = stage1(*DOCUMENTED_STAGE1)
    with pytest.raises(StageRuleError, match="stage_number"):
        check_stage(content, make_pack(), item(2, "overview", "story_flow", "overview"))
    with pytest.raises(StageRuleError, match="key"):
        check_stage(content, make_pack(), item(1, "why_possible", "story_flow", "technical"))
    with pytest.raises(StageRuleError, match="diagram type"):
        check_stage(content, make_pack(), item(1, "overview", "architecture", "overview"))


def test_documented_block_citing_a_url_outside_the_pack_is_rejected():
    blocks = DOCUMENTED_STAGE1 + (doc("Something", "https://nvd.nist.gov/vuln/detail/CVE-9999-9999"),)
    with pytest.raises(StageRuleError, match="not in the Knowledge Pack"):
        check_stage(stage1(*blocks), make_pack(), OVERVIEW)


def test_trailing_slash_does_not_matter_for_urls():
    blocks = (doc("Servers were taken over", INC + "/"), doc("Listed", KEV))
    check_stage(stage1(*blocks), make_pack(), OVERVIEW)


def test_bad_mermaid_is_rejected_with_the_reason():
    with pytest.raises(StageRuleError, match="before it is defined"):
        check_stage(stage1(*DOCUMENTED_STAGE1, diagram='flowchart LR\n A --> B\n'), make_pack(), OVERVIEW)


def test_all_problems_are_reported_together():
    content = stage1(doc("x", "https://nvd.nist.gov/other"), diagram="nonsense")
    with pytest.raises(StageRuleError) as info:
        check_stage(content, make_pack(), OVERVIEW)
    assert "not in the Knowledge Pack" in str(info.value) and "first line" in str(info.value)


# ---- exploitation status rules for stage 1 (D-006) ---------------------------


def test_documented_status_needs_a_block_citing_the_incident_or_evidence():
    with pytest.raises(StageRuleError, match="incident"):
        check_stage(stage1(doc("A weakness exists", NVD)), make_pack(), OVERVIEW)


def test_documented_status_must_not_say_no_incident():
    blocks = DOCUMENTED_STAGE1 + (inf(NO_INCIDENT_PHRASE + "."),)
    with pytest.raises(StageRuleError, match="documented exploitation"):
        check_stage(stage1(*blocks), make_pack(), OVERVIEW)


NOT_DOCUMENTED_OK = (
    doc("A logging library evaluates input", NVD),
    inf(NO_INCIDENT_PHRASE + ". The impact below is potential, not observed."),
    inf("Potential impact: an attacker could run code on the server."),
)


def test_not_documented_stage1_passes_with_the_required_wording():
    check_stage(stage1(*NOT_DOCUMENTED_OK), make_pack("not_documented"), OVERVIEW)


def test_not_documented_stage1_needs_the_no_incident_phrase():
    blocks = (inf("Potential impact: code execution."),)
    with pytest.raises(StageRuleError, match="No documented incident"):
        check_stage(stage1(*blocks), make_pack("not_documented"), OVERVIEW)


def test_not_documented_stage1_needs_potential_labelled_impact():
    blocks = (inf(NO_INCIDENT_PHRASE + "."), doc("A library evaluates input", NVD))
    with pytest.raises(StageRuleError, match="potential"):
        check_stage(stage1(*blocks), make_pack("not_documented"), OVERVIEW)


@pytest.mark.parametrize(
    "sentence",
    [
        "The flaw was exploited by criminals.",
        "Servers were actively exploited last week.",
        "It has been exploited in the wild.",
        "Attackers exploited the flaw to steal data.",
    ],
)
def test_not_documented_stage1_must_not_describe_an_attack_as_real(sentence):
    blocks = NOT_DOCUMENTED_OK + (inf(sentence),)
    with pytest.raises(StageRuleError, match="describes an attack"):
        check_stage(stage1(*blocks), make_pack("not_documented"), OVERVIEW)


def test_not_documented_may_use_hypothetical_wording():
    blocks = NOT_DOCUMENTED_OK + (inf("An attacker could exploit the flaw if the service is reachable."),)
    check_stage(stage1(*blocks), make_pack("not_documented"), OVERVIEW)


def test_unknown_status_needs_a_note_that_the_check_was_partial():
    with pytest.raises(StageRuleError, match="partial"):
        check_stage(stage1(*NOT_DOCUMENTED_OK), make_pack("unknown"), OVERVIEW)
    blocks = NOT_DOCUMENTED_OK + (inf("The exploitation check was partial: a source was unreachable."),)
    check_stage(stage1(*blocks), make_pack("unknown"), OVERVIEW)


def test_status_rules_also_stop_stage_2_describing_a_real_attack():
    blocks = (doc("Input is evaluated by the logger", NVD), inf("Criminals exploited this flaw."))
    with pytest.raises(StageRuleError, match="describes an attack"):
        check_stage(stage2(*blocks), make_pack("not_documented"), WHY)


# ---- stage 2 ---------------------------------------------------------------


def test_valid_stage2_passes():
    check_stage(stage2(doc("Input is evaluated by the logger"), inf("So a crafted value runs code.")),
                make_pack(), WHY)


def test_stage2_may_use_a_sequence_diagram():
    why = item(2, "why_possible", "sequence", "technical")
    check_stage(stage2(doc("Input is evaluated"), diagram=SEQ, dtype="sequence"), make_pack(), why)


def test_stage2_needs_a_documented_block_when_the_pack_documents_the_weakness():
    with pytest.raises(StageRuleError, match="documented"):
        check_stage(stage2(inf("It probably evaluates input.")), make_pack(), WHY)


def test_stage2_without_a_documented_weakness_needs_no_documented_block():
    data = make_pack().model_dump()
    data["weakness_mechanism"] = []
    pack = KnowledgePack.model_validate(data)
    check_stage(stage2(inf("It probably evaluates input.")), pack, WHY)
