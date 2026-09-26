"""D-036: sentences in documented and secondary text that the cited URL's Pack entries do not support.
A heuristic that warns; it never rejects a stage. No model, no network."""

import pytest

from src.frames import build_frames
from src.schemas import KnowledgePack
from src.stage_content import StageContent
from src.support_check import THRESHOLD, content_words, split_sentences, weak_sentences
from tests.test_frames import ATTACK, chain_of, chain_pack
from tests.test_stage_rules import FLOW, doc, inf, stage2
from tests.test_stage_rules_secondary import PAGE, PAGE2, sec

X = "https://attack.mitre.org/techniques/T1558/003"


def pack_with(entries):
    """A technique Pack whose mechanism entries are the given (text, tag, url) triples."""
    return KnowledgePack.model_validate({
        "topic": "T1558.003", "topic_type": "technique", "exploitation_status": "not_applicable",
        "weakness_mechanism": [{"value": v, "tag": t, "source_url": u} for v, t, u in entries],
    })


KERB = pack_with([
    ("Any authenticated domain user can request a Kerberos service ticket for any SPN. "
     "The domain controller does not check whether the requester is authorized to use the service.",
     "secondary", PAGE),
    ("The service ticket is encrypted with a hash derived from the service account's password. "
     "Weak passwords are exposed to offline cracking.", "secondary", PAGE),
    ("Cracking happens offline, so it bypasses account lockouts and generates no further activity "
     "on the network.", "secondary", PAGE2),
])


def weak(*blocks, pack=KERB, **kw):
    return weak_sentences([stage2(*blocks)], pack, **kw)


# ---- the word and sentence helpers ---------------------------------------------------------


def test_content_words_drop_short_and_connective_words():
    words = content_words("As explained in stage 2, the attacker requests tickets and cracks the hashes.")
    for dropped in ("stage", "explain", "explained", "the", "and"):
        assert dropped not in words
    assert "attacker" in words


def test_plural_and_past_tense_forms_count_as_the_same_word():
    assert content_words("tickets") == content_words("ticket")
    assert content_words("cracked") == content_words("cracks")


def test_sentences_split_on_full_stops_semicolons_and_question_marks():
    assert split_sentences("One thing. Another thing; a third? Last") == ["One thing.", "Another thing;", "a third?", "Last"]


# ---- what is flagged --------------------------------------------------------------------------


def test_a_supported_sentence_is_not_flagged():
    text = "Any authenticated domain user can request a service ticket for any service."
    assert weak(sec(text, PAGE)) == []


def test_an_added_clause_is_flagged_with_its_score_and_missing_words():
    text = "That is how the service can confirm the ticket is genuine without asking the domain controller again."
    (found,) = weak(sec(text, PAGE))
    assert found.stage_number == 2 and found.tag == "secondary" and found.source_url == PAGE
    assert found.coverage < THRESHOLD and "genuine" in found.missing


def test_text_credited_to_the_wrong_page_names_the_page_that_holds_it():
    text = "Cracking bypasses account lockouts and generates no further activity."
    (found,) = weak(sec(text, PAGE))
    assert "lockout" in found.missing and found.other_urls == [PAGE2]
    assert weak(sec(text, PAGE2)) == []  # the same sentence under the right page is fine


def test_a_bridging_sentence_that_reuses_supported_words_is_not_flagged():
    text = "As explained in stage 2, the domain controller does not check the user."
    assert weak(sec(text, PAGE)) == []


def test_short_sentences_are_skipped():
    assert weak(sec("Both pages agree.", PAGE)) == []


def test_inference_and_unknown_text_is_ignored():
    unknown = {"value": "Nothing known about this topic at all", "tag": "unknown"}
    assert weak(inf("The attacker could add anything at all here without any support"), unknown) == []


def test_threshold_boundary_is_exact_and_can_be_changed():
    pack = pack_with([("Alpha bravo charlie delta echo foxtrot", "documented", X)])
    at_boundary = "Alpha bravo charlie zulus yankee."  # 3 of 5 content words = 0.6: not flagged
    below = "Alpha bravo zulus yankee whiskey."  # 2 of 5 = 0.4: flagged
    assert weak(doc(at_boundary, X), pack=pack) == []
    (found,) = weak(doc(below, X), pack=pack)
    assert found.coverage == pytest.approx(0.4)
    assert weak(doc(at_boundary, X), pack=pack, threshold=0.7)  # a stricter threshold flags it


def test_results_are_sorted_worst_first():
    pack = pack_with([("Alpha bravo charlie delta echo foxtrot", "documented", X)])
    found = weak(
        doc("Alpha bravo charlie zulus yankee whiskey.", X), doc("Alpha bravo zulus yankee whiskey.", X), pack=pack
    )
    assert len(found) == 2 and found[0].coverage <= found[1].coverage


# ---- which text is checked ----------------------------------------------------------------------


def test_glossary_definitions_are_checked():
    content = StageContent.model_validate({
        "stage_number": 1, "key": "overview", "title": "t", "blocks": [inf("x")],
        "glossary": [{"term": "Ticket", "definition": sec("A ticket proves identity to every printer everywhere.", PAGE)}],
        "diagram": {"type": "story_flow", "mermaid": FLOW},
    })
    (found,) = weak_sentences([content], KERB)
    assert found.stage_number == 1 and "printer" in found.missing


def test_stage_3_step_details_are_checked():
    pack = chain_pack()  # documented steps citing the ATT&CK URL
    bad = {"value": "The attacker whispers passwords to the printer spooler quietly.", "tag": "documented",
           "source_url": ATTACK}
    chain = chain_of(pack, detail=lambda n: bad if n == 1 else doc(f"Step {n} action", ATTACK))
    content = StageContent.model_validate({
        "stage_number": 3, "key": "attack_chain", "title": "t", "blocks": [inf("As explained in stage 2.")],
        "chain": [c.model_dump(mode="json") for c in chain],
        "frames": [f.model_dump(mode="json") for f in build_frames(pack, chain)],
    })
    found = weak_sentences([content], pack)
    assert len(found) == 1 and "printer" in found[0].missing
