"""Tests for src/glossary.py and the glossary part of the schema and stage rules (D-025). No model."""

import pytest
from pydantic import ValidationError

from src.glossary import MAX_DEFINITION_CHARS, definition_problem, repeated_terms, term_keys
from src.schemas import StagePlanItem
from src.stage_content import GlossaryEntry, StageContent
from src.stage_rules import StageRuleError, check_stage
from src.trace import sample_claims
from tests.test_frames import ATTACK, chain_of, chain_pack, stage3
from tests.test_stage_rules import FLOW, NVD, doc, inf, make_pack

WHY = StagePlanItem(number=2, key="why_possible", subject="s", depth="technical", diagram="architecture")
CHAIN_ITEM = StagePlanItem(number=3, key="attack_chain", subject="s", depth="technical",
                           diagram="kill_chain_frames", covers_steps=[1, 2, 3])
OVERVIEW = StagePlanItem(number=1, key="overview", subject="s", depth="overview", diagram="story_flow")


def entry(term, text="It is a made-up thing.", tag="inference", url=None):
    definition = {"value": text, "tag": tag}
    if url:
        definition["source_url"] = url
    return {"term": term, "definition": definition}


def stage(number, key, glossary, blocks=None, diagram_type="architecture"):
    return StageContent.model_validate(
        {"stage_number": number, "key": key, "title": "T",
         "blocks": blocks or [doc("Input is evaluated by the logger")],
         "glossary": glossary, "diagram": {"type": diagram_type, "mermaid": FLOW}}
    )


def why(*glossary, blocks=None):
    return stage(2, "why_possible", list(glossary), blocks)


def overview(*glossary):
    return stage(1, "overview", list(glossary),
                 [doc("Servers were taken over", "https://www.cisa.gov/news-events/alerts/example-incident"),
                  doc("Listed in KEV", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")],
                 diagram_type="story_flow")


# ---- matching terms --------------------------------------------------------------


def test_term_keys_ignore_case_spacing_and_punctuation():
    assert term_keys("  Message   Lookup ") == term_keys("message lookup") == {"message lookup"}
    assert term_keys('"JNDI".') == {"jndi"}


def test_a_plain_trailing_plural_matches_the_singular():
    assert term_keys("endpoints") == term_keys("Endpoint")
    assert term_keys("class") == {"class"} and term_keys("dns") == {"dns"}  # short words and -ss are left alone


def test_a_parenthetical_expansion_is_an_alias():
    assert term_keys("JNDI (Java Naming and Directory Interface)") == {"jndi", "java naming and directory interface"}
    assert term_keys("JNDI") & term_keys("Java Naming and Directory Interface (JNDI)")


def test_different_terms_do_not_match():
    assert not term_keys("LDAP") & term_keys("JNDI")
    assert not term_keys("message lookup") & term_keys("lookup")  # synonyms and parts are not detected


def test_empty_after_trimming_gives_no_keys():
    assert term_keys("()") == set()


# ---- one sentence ----------------------------------------------------------------


@pytest.mark.parametrize("text", [
    "JNDI is a Java feature for looking up names and objects, often on another server.",
    "A directory protocol (for example LDAP, e.g. over port 389) that a lookup can talk to.",
    "Short.",
    "Something written in one go; it has a semicolon but no second sentence.",
])
def test_one_sentence_passes(text):
    assert definition_problem(text) is None


@pytest.mark.parametrize("text", [
    "It is a feature. It is also a risk.",
    "Is it a feature? Yes it is.",
    "First line\nsecond line",
    "x" * (MAX_DEFINITION_CHARS + 1),
])
def test_more_than_one_sentence_or_too_long_is_a_problem(text):
    assert definition_problem(text)


def test_abbreviations_do_not_count_as_a_second_sentence():
    # Known gap (D-025): a real second sentence right after "etc." is not seen, because "etc." is skipped.
    assert definition_problem("A tool, i.e. a client, that sends data to a server, etc. Nothing more.") is None
    assert definition_problem("A tool, i.e. a client, that sends data to a server etc. and vs. a peer.") is None


# ---- the schema ------------------------------------------------------------------


def test_glossary_defaults_to_empty_and_old_stages_still_validate():
    content = StageContent.model_validate(
        {"stage_number": 1, "key": "overview", "title": "t", "blocks": [inf("x")],
         "diagram": {"type": "story_flow", "mermaid": FLOW}}
    )
    assert content.glossary == []


def test_glossary_entry_needs_a_term_and_a_tagged_definition():
    GlossaryEntry.model_validate(entry("JNDI"))
    with pytest.raises(ValidationError):
        GlossaryEntry.model_validate({"term": "", "definition": {"value": "x", "tag": "inference"}})
    with pytest.raises(ValidationError, match="source_url"):
        GlossaryEntry.model_validate(entry("JNDI", tag="documented"))
    with pytest.raises(ValidationError):
        GlossaryEntry.model_validate({"term": "JNDI", "definition": "a plain string"})
    with pytest.raises(ValidationError):
        GlossaryEntry.model_validate(entry("x" * 61))


def test_glossary_entry_definition_must_be_one_sentence():
    with pytest.raises(ValidationError, match="ONE sentence"):
        GlossaryEntry.model_validate(entry("JNDI", "It is a feature. It is also a risk."))


def test_all_tagged_includes_the_glossary_definitions():
    content = why(entry("JNDI"), entry("LDAP"))
    assert len(content.all_blocks()) == 1 and len(content.all_tagged()) == 3


# ---- repeated terms across a run ------------------------------------------------


def test_repeated_terms_names_the_term_and_the_earlier_stage():
    problems = repeated_terms(["ldap"], [(1, ["JNDI"]), (2, ["LDAP (Lightweight Directory Access Protocol)"])])
    assert len(problems) == 1 and "'ldap'" in problems[0] and "stage 2" in problems[0]


def test_a_term_repeated_inside_one_stage_is_a_problem():
    assert "twice in this stage" in repeated_terms(["JNDI", "jndi"], [])[0]


def test_new_terms_pass():
    assert repeated_terms(["JNDI", "LDAP"], [(1, ["Log4j2"])]) == []


# ---- in check_stage ----------------------------------------------------------------


def test_a_new_glossary_passes_and_an_empty_one_is_allowed():
    pack = make_pack()
    check_stage(why(entry("JNDI"), entry("LDAP")), pack, WHY, [overview(entry("Log4j2"))])
    check_stage(why(), pack, WHY, [overview()])


def test_a_term_defined_in_an_earlier_stage_is_rejected_with_the_term_named():
    pack = make_pack()
    with pytest.raises(StageRuleError, match="'JNDI' was already defined in stage 1"):
        check_stage(why(entry("JNDI")), pack, WHY, [overview(entry("jndis"))])


def test_earlier_stages_are_optional_so_old_calls_still_work():
    check_stage(why(entry("JNDI")), make_pack(), WHY)


def test_the_same_term_twice_in_one_stage_is_rejected():
    with pytest.raises(StageRuleError, match="twice in this stage"):
        check_stage(why(entry("JNDI"), entry("JNDI")), make_pack(), WHY)


def test_a_documented_definition_must_cite_a_url_in_the_pack():
    pack = make_pack()
    check_stage(why(entry("JNDI", "A Java naming feature.", "documented", NVD)), pack, WHY)
    with pytest.raises(StageRuleError, match="not in the Knowledge Pack"):
        check_stage(why(entry("JNDI", "A Java naming feature.", "documented", "https://nvd.nist.gov/other")),
                    pack, WHY)


def test_glossary_text_may_not_name_the_pack():
    with pytest.raises(StageRuleError, match="learner has never seen"):
        check_stage(why(entry("JNDI", "The Pack calls it a naming feature.")), make_pack(), WHY)
    with pytest.raises(StageRuleError, match="learner has never seen"):
        check_stage(why(entry("Knowledge Pack")), make_pack(), WHY)


def test_glossary_text_may_not_present_an_attack_as_real_without_documented_exploitation():
    pack = make_pack("not_documented")
    with pytest.raises(StageRuleError, match="describes an attack"):
        check_stage(why(entry("JNDI", "A feature that attackers exploited widely.")), pack, WHY)


# ---- stage 3 ---------------------------------------------------------------------


def stage3_with_glossary(pack, *glossary, **kwargs):
    content = stage3(pack, **kwargs)
    return content.model_copy(update={"glossary": [GlossaryEntry.model_validate(g) for g in glossary]})


def test_stage_3_glossary_is_checked_against_earlier_stages():
    pack = chain_pack()
    earlier = [overview(entry("Log4j2")), why(entry("JNDI"))]
    check_stage(stage3_with_glossary(pack, entry("kill chain")), pack, CHAIN_ITEM, earlier)
    with pytest.raises(StageRuleError, match="already defined in stage 2"):
        check_stage(stage3_with_glossary(pack, entry("JNDI")), pack, CHAIN_ITEM, earlier)


@pytest.mark.parametrize("status", ["not_documented", "unknown"])
def test_the_possible_scenario_wording_does_not_apply_to_definitions(status):
    pack = chain_pack(status)
    content = stage3(pack, blocks=[inf("Possible scenario: an attacker could send input.")],
                     chain=chain_of(pack, detail=lambda n: inf("Possible scenario: an attacker could act.")))
    content = content.model_copy(update={"glossary": [GlossaryEntry.model_validate(entry("Kill chain"))]})
    check_stage(content, pack, CHAIN_ITEM)


def test_documented_definitions_can_be_sampled_by_the_trace_check():
    pack = chain_pack()
    content = stage3_with_glossary(pack, entry("Technique", "An ATT&CK behavior.", "documented", ATTACK))
    claims = sample_claims([content], pack, count=20)
    assert any(c.text == "An ATT&CK behavior." for c in claims)
