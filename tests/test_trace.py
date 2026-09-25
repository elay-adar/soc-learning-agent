"""Tests for src/trace.py and the saved stages file. Never calls a model or the network."""

import random

import pytest
from pydantic import ValidationError

from src.stage_content import StageContent, StagesFile
from src.stage_rules import pack_entries
from src.trace import sample_claims
from tests.test_lecturer import PLAN, STAGE1, stage_json
from tests.test_stage_rules import DOCUMENTED_STAGE1, INC, KEV, NVD, doc, inf, make_pack


def stage_with(blocks, number=1, key="overview", diagram="story_flow"):
    return StageContent.model_validate_json(stage_json(number, key, blocks, diagram))


def test_pack_entries_are_labelled_and_complete():
    labels = [label for label, _ in pack_entries(make_pack())]
    assert "exploitation_evidence" in labels
    assert "weakness_mechanism[0]" in labels
    assert "attack_steps[1]" in labels
    assert any(label.startswith("incidents[0]") for label in labels)


def test_claims_show_the_pack_entries_with_the_same_url():
    claims = sample_claims([STAGE1], make_pack(), count=5, rng=random.Random(1))
    by_url = {c.source_url: c for c in claims}
    assert set(by_url) == {INC, KEV}
    assert any("incidents[0]" in label for label, _ in by_url[INC].matches)
    assert by_url[KEV].matches[0][0] == "exploitation_evidence"


def test_only_documented_blocks_are_sampled_and_the_rest_are_counted():
    stage = stage_with(list(DOCUMENTED_STAGE1) + [inf("An inference")])
    claims, skipped = sample_claims([stage], make_pack(), count=5, rng=random.Random(1), with_counts=True)
    assert len(claims) == 2 and skipped == 1


def test_sample_size_is_capped_and_reproducible():
    blocks = [doc(f"Claim {i}", NVD) for i in range(8)] + list(DOCUMENTED_STAGE1)
    stage = stage_with(blocks)
    a = sample_claims([stage], make_pack(), count=5, rng=random.Random(7))
    b = sample_claims([stage], make_pack(), count=5, rng=random.Random(7))
    assert len(a) == 5 and [c.text for c in a] == [c.text for c in b]


def test_a_claim_whose_url_is_not_in_the_pack_has_no_matches():
    stage = stage_with([doc("Odd", "https://nvd.nist.gov/other")])
    (claim,) = sample_claims([stage], make_pack(), count=5, rng=random.Random(1))
    assert claim.matches == []


# ---- the saved file ----------------------------------------------------------


def test_stages_file_round_trips():
    saved = StagesFile(topic="CVE-0000-0000", plan=PLAN, stages=[STAGE1])
    assert StagesFile.model_validate_json(saved.model_dump_json()) == saved


def test_stages_file_rejects_a_stage_that_differs_from_the_plan():
    wrong = stage_with(DOCUMENTED_STAGE1, number=1, key="why_possible")
    with pytest.raises(ValidationError, match="key"):
        StagesFile(topic="t", plan=PLAN, stages=[wrong])


def test_stages_file_rejects_gaps_and_stages_outside_the_plan():
    two = stage_with(DOCUMENTED_STAGE1, number=2, key="why_possible", diagram="architecture")
    with pytest.raises(ValidationError, match="in order"):
        StagesFile(topic="t", plan=PLAN, stages=[two])
    nine = stage_with(DOCUMENTED_STAGE1, number=9)
    with pytest.raises(ValidationError, match="not in the plan"):
        StagesFile(topic="t", plan=PLAN, stages=[nine])


# ---- ranking of Pack entries -------------------------------------------------------------


def _many_entry_pack():
    data = make_pack().model_dump()
    data["weakness_mechanism"] = [
        doc("The logger evaluates crafted input from a remote LDAP server"),
        doc("Affected versions run from 2.0 through 2.15"),
        doc("Scores are rated critical by NVD"),
        doc("The library writes messages to files"),
        doc("A patch removes the lookup feature entirely"),
    ]
    from src.schemas import KnowledgePack

    return KnowledgePack.model_validate(data)


def test_matches_are_ranked_by_word_overlap_and_capped():
    stage = stage_with([doc("The logger evaluates crafted input from an LDAP server", NVD)])
    (claim,) = sample_claims([stage], _many_entry_pack(), count=1, rng=random.Random(1), max_matches=3)
    assert len(claim.matches) == 3
    assert claim.matches[0][0] == "weakness_mechanism[0]"
    assert claim.same_url_total > 3


def test_ranking_ignores_case_and_short_words():
    stage = stage_with([doc("THE LOGGER EVALUATES CRAFTED INPUT", NVD)])
    (claim,) = sample_claims([stage], _many_entry_pack(), count=1, rng=random.Random(1))
    assert claim.matches[0][0] == "weakness_mechanism[0]"


def test_ties_are_broken_by_label_so_output_is_stable():
    stage = stage_with([doc("Completely unrelated words here", NVD)])
    a = sample_claims([stage], _many_entry_pack(), count=1, rng=random.Random(1))[0].matches
    b = sample_claims([stage], _many_entry_pack(), count=1, rng=random.Random(2))[0].matches
    assert a == b
