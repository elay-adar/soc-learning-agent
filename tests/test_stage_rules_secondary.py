"""Stage rules for secondary sources and technique-only topics (D-027 to D-030). No model, no network."""

import pytest

from src.frames import build_frames
from src.schemas import KnowledgePack, StagePlanItem
from src.stage_content import ChainStep, StageContent
from src.stage_rules import NO_CVE_CWE_PHRASE, StageRuleError, check_stage, has_cve_or_cwe
from tests.test_stage_rules import FLOW, KEV, NVD, OVERVIEW, WHY, doc, inf, make_pack, stage1, stage2

PAGE = "https://www.crowdstrike.com/en-us/cybersecurity-101/kerberoasting/"
PAGE2 = "https://www.picussecurity.com/resource/blog/kerberoasting"
ATTACK = "https://attack.mitre.org/techniques/T1558/003"
CHAIN = StagePlanItem(number=3, key="attack_chain", subject="s", depth="technical",
                      diagram="kill_chain_frames", covers_steps=[1, 2])


def sec(text, url=PAGE):
    return {"value": text, "tag": "secondary", "source_url": url}


def technique_pack(with_cwe=False):
    data = {
        "topic": "T1558.003",
        "topic_type": "technique",
        "exploitation_status": "not_applicable",
        "weakness_mechanism": [sec("Service tickets are encrypted with the account's password hash")],
        "attack_steps": [
            {"number": 1, "action": sec("The attacker lists service accounts", PAGE), "mitre_technique": "T1558.003"},
            {"number": 2, "action": sec("The attacker requests a service ticket", PAGE2), "mitre_technique": "T1558.003"},
        ],
        "triage_fields": {"weakness_type": {"status": "unknown"}},
    }
    if with_cwe:
        data["triage_fields"] = {"weakness_type": {"status": "value", "item": doc("CWE-916", ATTACK)}}
    return KnowledgePack.model_validate(data)


def stage3(pack, blocks=None, details=None):
    chain = [
        ChainStep(step=s.number, label=f"Label {s.number}", detail=(details or {}).get(s.number, s.action))
        for s in pack.attack_steps
    ]
    return StageContent.model_validate({
        "stage_number": 3, "key": "attack_chain", "title": "Execution flow",
        "blocks": blocks or [sec("Each step abuses the ticket design from stage 2")],
        "chain": [c.model_dump(mode="json") for c in chain],
        "frames": [f.model_dump(mode="json") for f in build_frames(pack, chain)],
    })


# ---- the two tags cannot be swapped ------------------------------------------------


def test_secondary_block_citing_a_pack_secondary_url_passes():
    pack = technique_pack()
    check_stage(stage2(sec("Tickets are encrypted with a password hash"), inf(NO_CVE_CWE_PHRASE + " exists"), ), pack, WHY)


def test_documented_block_citing_a_secondary_url_is_rejected():
    pack = technique_pack()
    content = stage2(doc("Tickets are encrypted with a password hash", PAGE), inf(NO_CVE_CWE_PHRASE))
    with pytest.raises(StageRuleError, match="secondary source.*tag it 'secondary'"):
        check_stage(content, pack, WHY)


def test_secondary_block_citing_an_official_url_is_rejected():
    pack = make_pack()
    content = stage2(sec("Input is evaluated", NVD))
    with pytest.raises(StageRuleError, match="secondary block cites .* not a secondary-source"):
        check_stage(content, pack, WHY)


def test_secondary_block_citing_a_url_outside_the_pack_is_rejected():
    pack = technique_pack()
    content = stage2(sec("Something", "https://www.crowdstrike.com/other"), inf(NO_CVE_CWE_PHRASE))
    with pytest.raises(StageRuleError, match="not in the Knowledge Pack"):
        check_stage(content, pack, WHY)


def test_secondary_block_may_not_cite_a_url_the_pack_records_as_documented():
    # A Pack that (wrongly) files an allowlist URL under a documented entry: the stage may not call it secondary.
    data = technique_pack().model_dump(mode="json")
    data["weakness_mechanism"] = [doc("A fact", PAGE)]
    pack = KnowledgePack.model_validate(data)
    content = stage2(sec("A fact", PAGE), inf(NO_CVE_CWE_PHRASE))
    with pytest.raises(StageRuleError, match="records as documented"):
        check_stage(content, pack, WHY)


# ---- stage 2: the "no CVE or CWE" statement ---------------------------------------------


def test_has_cve_or_cwe():
    assert has_cve_or_cwe(make_pack()) is True
    assert has_cve_or_cwe(technique_pack()) is False
    assert has_cve_or_cwe(technique_pack(with_cwe=True)) is True


def test_technique_without_cve_or_cwe_must_say_so_in_stage_2():
    pack = technique_pack()
    with pytest.raises(StageRuleError, match="no CVE or CWE"):
        check_stage(stage2(sec("Tickets are encrypted with a password hash")), pack, WHY)


def test_stage_2_for_a_technique_without_cve_or_cwe_passes_with_the_statement_and_a_secondary_block():
    pack = technique_pack()
    content = stage2(inf("This technique has no CVE or CWE, so the flaw is explained directly"),
                     sec("Tickets are encrypted with a password hash"))
    check_stage(content, pack, WHY)


def test_the_statement_alone_is_not_enough_a_secondary_block_is_needed():
    pack = technique_pack()
    with pytest.raises(StageRuleError, match="at least one secondary block"):
        check_stage(stage2(inf("This technique has no CVE or CWE")), pack, WHY)


def test_stage_2_may_not_name_a_cve_or_cwe_id_when_there_is_none():
    pack = technique_pack()
    content = stage2(inf("This technique has no CVE or CWE, unlike CWE-916"), sec("Tickets use a weak key"))
    with pytest.raises(StageRuleError, match="names CWE-916"):
        check_stage(content, pack, WHY)


def test_stage_2_may_not_claim_there_is_no_cve_or_cwe_when_the_pack_has_one():
    with pytest.raises(StageRuleError, match="must not say"):
        check_stage(stage2(doc("Input is evaluated by the logger"), inf("This has no CVE or CWE")), make_pack(), WHY)
    with pytest.raises(StageRuleError, match="must not say"):
        check_stage(stage2(inf("This has no CVE or CWE")), technique_pack(with_cwe=True), WHY)


# ---- technique topics skip the exploitation rules ----------------------------------------


def test_technique_stage_1_needs_no_exploitation_sentence():
    pack = technique_pack()
    content = stage1(inf("Kerberoasting is a credential access technique against service tickets"))
    check_stage(content, pack, OVERVIEW)  # no "No documented incident", no "potential", no "partial"


def test_cve_stage_1_still_needs_the_exploitation_sentence():
    with pytest.raises(StageRuleError, match="No documented incident"):
        check_stage(stage1(inf("A logger flaw")), make_pack("not_documented"), OVERVIEW)


def test_technique_stage_3_may_be_secondary_without_possible_scenario():
    pack = technique_pack()
    check_stage(stage3(pack), pack, CHAIN)


def test_cve_stage_3_without_documented_exploitation_still_needs_possible_scenario():
    from tests.test_frames import ITEM, chain_pack

    pack = chain_pack("not_documented")
    with pytest.raises(StageRuleError, match="Possible scenario"):
        check_stage(stage3(pack, details={}), pack, ITEM)


# ---- stage 1 prose ------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["It maps to CWE-916", "It scores a CVSS of 7.5", "It is technique T1558.003"])
def test_stage_1_prose_has_no_cwe_cvss_or_attack_id(text):
    with pytest.raises(StageRuleError, match="stage 1 text must not contain"):
        check_stage(stage1(inf(text)), technique_pack(), OVERVIEW)


def test_cve_id_in_stage_1_is_fine():
    check_stage(stage1(doc("Servers were taken over", NVD), doc("Listed in KEV", KEV), inf("See CVE-0000-0000")),
                make_pack(), OVERVIEW)


# ---- wording ------------------------------------------------------------------------------


@pytest.mark.parametrize("text", ["This is a kill chain", "one Kill-Chain step", "a killchain"])
def test_kill_chain_wording_is_rejected(text):
    with pytest.raises(StageRuleError, match="kill chain"):
        check_stage(stage1(inf(text), *(doc("Servers were taken over", NVD),)), make_pack("not_documented"), OVERVIEW)
