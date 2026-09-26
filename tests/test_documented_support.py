"""D-037: a documented sentence that shares almost no words with the Pack entries under its URL is
rejected. Secondary text is only warned about (src/support_check.py). No model, no network."""

import pytest

from src.schemas import KnowledgePack
from src.stage_rules import StageRuleError, check_stage
from src.support_check import DOCUMENTED_LIMIT
from tests.test_stage_rules import NVD, WHY, doc, inf, make_pack, stage2

ENTRY = "Alpha bravo charlie delta echo foxtrot golf hotel india juliet"


def pack_with_entry(text=ENTRY):
    data = make_pack().model_dump(mode="json")
    data["weakness_mechanism"] = [doc(text, NVD)]
    return KnowledgePack.model_validate(data)


def stage(*blocks, **kw):
    return stage2(*blocks, **kw)


def test_limit_is_below_the_warning_threshold():
    from src.support_check import THRESHOLD

    assert DOCUMENTED_LIMIT == 0.3 and DOCUMENTED_LIMIT < THRESHOLD


def test_a_documented_sentence_with_no_support_is_rejected_with_the_sentence_in_the_message():
    text = "Those are consequences after the flow ends, not steps inside it."
    with pytest.raises(StageRuleError, match=r"documented.*Those are consequences.*inference"):
        check_stage(stage(doc(text, NVD)), pack_with_entry(), WHY)


def test_a_supported_documented_sentence_passes():
    check_stage(stage(doc("Alpha bravo charlie delta echo foxtrot golf", NVD)), pack_with_entry(), WHY)


def test_the_limit_is_exact_three_of_ten_words_passes_two_of_ten_is_rejected():
    ten_words_three_found = "Alpha bravo charlie kilo lima mike november oscar papa quebec"
    ten_words_two_found = "Alpha bravo kilo lima mike november oscar papa quebec romeo"
    check_stage(stage(doc(ten_words_three_found, NVD)), pack_with_entry(), WHY)
    with pytest.raises(StageRuleError, match="documented"):
        check_stage(stage(doc(ten_words_two_found, NVD)), pack_with_entry(), WHY)


def test_only_the_unsupported_sentence_is_named_not_the_whole_block():
    block = "Alpha bravo charlie delta echo foxtrot golf. Zulu yankee whiskey victor uniform tango."
    with pytest.raises(StageRuleError) as info:
        check_stage(stage(doc(block, NVD)), pack_with_entry(), WHY)
    assert "Zulu yankee" in str(info.value) and "Alpha bravo" not in str(info.value)


def test_short_sentences_are_not_judged():
    check_stage(stage(doc("Servers were taken over", NVD), doc(ENTRY, NVD)), pack_with_entry(), WHY)


def test_secondary_and_inference_text_is_not_rejected_here():
    from tests.test_stage_rules_secondary import PAGE, sec, technique_pack

    pack = technique_pack()
    unrelated = "Zulu yankee whiskey victor uniform tango sierra romeo quebec papa"
    content = stage(inf("This technique has no CVE or CWE"), sec("Tickets are encrypted with the account's password hash", PAGE),
                    sec(unrelated, PAGE), inf(unrelated))
    check_stage(content, pack, WHY)  # warned about by support_check, never rejected


def test_documented_glossary_definitions_are_checked():
    from src.stage_content import StageContent
    from tests.test_stage_rules import FLOW

    content = StageContent.model_validate({
        "stage_number": 2, "key": "why_possible", "title": "t", "blocks": [doc(ENTRY, NVD)],
        "glossary": [{"term": "Thing", "definition": doc("Zulu yankee whiskey victor uniform tango.", NVD)}],
        "diagram": {"type": "architecture", "mermaid": FLOW},
    })
    with pytest.raises(StageRuleError, match="Zulu yankee"):
        check_stage(content, pack_with_entry(), WHY)


def test_a_url_missing_from_the_pack_is_reported_once_not_twice():
    with pytest.raises(StageRuleError) as info:
        check_stage(stage(doc("Alpha bravo charlie delta echo foxtrot golf", "https://nvd.nist.gov/other")),
                    pack_with_entry(), WHY)
    assert "not in the Knowledge Pack" in str(info.value) and "do not support" not in str(info.value)


def test_pack_entry_helpers_are_still_importable_from_stage_rules():
    from src.pack_entries import pack_entries as moved
    from src.stage_rules import pack_entries, pack_urls

    assert pack_entries is moved and NVD in pack_urls(make_pack())
