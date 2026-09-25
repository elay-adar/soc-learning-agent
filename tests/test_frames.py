"""Tests for src/frames.py, the stage-3 schema and the attack-chain rules. No model, no network."""

import pytest
from pydantic import ValidationError

from src.frames import FrameError, build_frames, frame_mermaid, node_texts
from src.mermaid_check import check_mermaid
from src.schemas import DiagramType, KnowledgePack, StagePlanItem
from src.stage_content import AttackChainDraft, ChainStep, StageContent
from src.stage_rules import StageRuleError, check_stage
from tests.test_stage_rules import FLOW, doc, inf, make_pack

ATTACK = "https://attack.mitre.org/techniques/T1190/"


def chain_pack(status="documented", steps=3):
    data = make_pack(status).model_dump(mode="json")
    techniques = ["T1190", "T1059.007", None]
    data["attack_steps"] = [
        {"number": n, "action": doc(f"Step {n} action", ATTACK), "mitre_technique": techniques[(n - 1) % 3]}
        for n in range(1, steps + 1)
    ]
    return KnowledgePack.model_validate(data)


def chain_of(pack, labels=None, detail=None):
    labels = labels or [f"Label {s.number}" for s in pack.attack_steps]
    return [
        ChainStep(step=s.number, label=label, detail=detail(s.number) if detail else doc(f"Step {s.number} action", ATTACK))
        for s, label in zip(pack.attack_steps, labels)
    ]



# ---- the frame builder ------------------------------------------------------------


def test_number_of_frames_equals_number_of_attack_steps():
    for steps in (1, 2, 3, 6):
        pack = chain_pack(steps=steps)
        assert len(build_frames(pack, chain_of(pack))) == steps


def test_frame_k_shows_exactly_steps_1_to_k_and_marks_step_k_as_new():
    pack = chain_pack()
    frames = build_frames(pack, chain_of(pack))
    for k, frame in enumerate(frames, start=1):
        assert frame.step == k
        for n in range(1, 4):
            assert (f'S{n}["' in frame.mermaid) == (n <= k)
        assert f"class S{k} new" in frame.mermaid
        if k > 1:
            assert f"class {','.join(f'S{i}' for i in range(1, k))} seen" in frame.mermaid


def test_every_frame_passes_the_mermaid_check():
    pack = chain_pack(steps=8)
    for frame in build_frames(pack, chain_of(pack)):
        check_mermaid(frame.mermaid, DiagramType.KILL_CHAIN_FRAMES)


def test_technique_id_comes_from_the_pack_not_the_model():
    pack = chain_pack()
    texts = node_texts(pack, chain_of(pack, ["Sends input", "Runs code", "Moves on"]))
    assert texts == ["1. Sends input (T1190)", "2. Runs code (T1059.007)", "3. Moves on"]


def test_single_step_frame_is_valid():
    pack = chain_pack(steps=1)
    (frame,) = build_frames(pack, chain_of(pack))
    assert "-->" not in frame.mermaid and "class S1 new" in frame.mermaid


def test_a_missing_extra_or_renumbered_step_is_rejected():
    pack = chain_pack()
    chain = chain_of(pack)
    with pytest.raises(FrameError, match="one entry per attack step"):
        build_frames(pack, chain[:2])
    with pytest.raises(FrameError, match="one entry per attack step"):
        build_frames(pack, chain + [ChainStep(step=4, label="Extra", detail=inf("x"))])
    swapped = [chain[1], chain[0], chain[2]]
    with pytest.raises(FrameError, match="one entry per attack step"):
        build_frames(pack, swapped)


@pytest.mark.parametrize("bad", ['Say "hi"', "a<b", "x; y", "# heading", "back`tick", "back\\slash", "two\nlines"])
def test_labels_with_characters_mermaid_cannot_take_are_rejected(bad):
    pack = chain_pack(steps=1)
    with pytest.raises(FrameError, match="label"):
        build_frames(pack, chain_of(pack, [bad]))


def test_more_steps_than_the_mermaid_node_limit_is_reported_not_crashed():
    pack = chain_pack(steps=26)
    with pytest.raises(FrameError, match="too large"):
        build_frames(pack, chain_of(pack))


def test_frame_index_out_of_range():
    with pytest.raises(ValueError):
        frame_mermaid(["1. A"], 2)


# ---- the StageContent schema -----------------------------------------------------


def content_dict(pack, **overrides):
    chain = chain_of(pack)
    data = {
        "stage_number": 3, "key": "attack_chain", "title": "Attack chain",
        "blocks": [doc("Step 1 action", ATTACK)],
        "chain": [c.model_dump(mode="json") for c in chain],
        "frames": [f.model_dump(mode="json") for f in build_frames(pack, chain)],
    }
    data.update(overrides)
    return data


def test_stage_with_frames_and_chain_is_valid():
    assert len(StageContent.model_validate(content_dict(chain_pack())).frames) == 3


def test_stage_needs_a_diagram_or_frames_but_not_both():
    pack = chain_pack()
    with pytest.raises(ValidationError, match="either a diagram or frames"):
        StageContent.model_validate(content_dict(pack, frames=[], chain=[]))
    with pytest.raises(ValidationError, match="either a diagram or frames"):
        StageContent.model_validate(content_dict(pack, diagram={"type": "story_flow", "mermaid": FLOW}))


def test_frames_and_chain_must_line_up():
    pack = chain_pack()
    data = content_dict(pack)
    data["chain"] = data["chain"][:2]
    with pytest.raises(ValidationError, match="one chain entry per frame"):
        StageContent.model_validate(data)
    data = content_dict(pack)
    data["frames"][0]["step"] = 2
    with pytest.raises(ValidationError, match="numbered"):
        StageContent.model_validate(data)


def test_chain_without_frames_is_rejected():
    data = content_dict(chain_pack(), frames=[], diagram={"type": "story_flow", "mermaid": FLOW})
    with pytest.raises(ValidationError, match="only allowed together with frames"):
        StageContent.model_validate(data)


def test_all_blocks_includes_the_chain_details():
    content = StageContent.model_validate(content_dict(chain_pack()))
    assert len(content.all_blocks()) == 1 + 3


def test_draft_schema_has_no_frames_or_diagram():
    props = AttackChainDraft.model_json_schema()["properties"]
    assert "frames" not in props and "diagram" not in props and "chain" in props


# ---- attack-chain rules in check_stage -------------------------------------------

ITEM = StagePlanItem(number=3, key="attack_chain", subject="s", depth="technical",
                     diagram="kill_chain_frames", covers_steps=[1, 2, 3])


def stage3(pack, blocks=None, chain=None, **overrides):
    chain = chain or chain_of(pack)
    data = {
        "stage_number": 3, "key": "attack_chain", "title": "Attack chain",
        "blocks": blocks or [doc("Step 1 action", ATTACK)],
        "chain": [c.model_dump(mode="json") for c in chain],
        "frames": [f.model_dump(mode="json") for f in build_frames(pack, chain)],
    }
    data.update(overrides)
    return StageContent.model_validate(data)


def test_valid_documented_stage3_passes():
    pack = chain_pack()
    check_stage(stage3(pack), pack, ITEM)


def test_frames_that_were_edited_by_hand_are_rejected():
    pack = chain_pack()
    content = stage3(pack)
    content.frames[1].mermaid = content.frames[1].mermaid.replace("Label 2", "Something else")
    with pytest.raises(StageRuleError, match="do not match"):
        check_stage(content, pack, ITEM)


def test_stage3_with_fewer_chain_entries_than_pack_steps_is_rejected():
    pack = chain_pack()
    two_step_pack = chain_pack(steps=2)
    content = stage3(two_step_pack)  # a stage built for a shorter chain than the Pack has
    with pytest.raises(StageRuleError, match="one entry per attack step"):
        check_stage(content, pack, ITEM)


def test_stage3_may_not_carry_a_single_diagram():
    pack = chain_pack()
    data = stage3(pack).model_dump(mode="json")
    data.update(frames=[], chain=[], diagram={"type": "kill_chain_frames", "mermaid": FLOW})
    with pytest.raises(StageRuleError, match="single diagram"):
        check_stage(StageContent.model_validate(data), pack, ITEM)


def test_other_stages_may_not_carry_frames():
    pack = chain_pack()
    item = StagePlanItem(number=3, key="why_possible", subject="s", depth="technical", diagram="architecture")
    data = stage3(pack).model_dump(mode="json")
    data["key"] = "why_possible"
    with pytest.raises(StageRuleError, match="not frames"):
        check_stage(StageContent.model_validate(data), pack, item)


def test_documented_chain_detail_must_cite_a_url_in_the_pack():
    pack = chain_pack()
    chain = chain_of(pack, detail=lambda n: doc("x", "https://nvd.nist.gov/other") if n == 2 else inf("y"))
    with pytest.raises(StageRuleError, match="not in the Knowledge Pack"):
        check_stage(stage3(pack, chain=chain), pack, ITEM)


def test_technique_ids_in_the_text_must_come_from_the_pack():
    pack = chain_pack()
    good = stage3(pack, blocks=[inf("Step 1 maps to T1190 and T1059.001.")])
    check_stage(good, pack, ITEM)  # T1059.001 is a sub-technique of the Pack's T1059.007 parent
    bad = stage3(pack, blocks=[inf("Step 1 maps to T1566.")])
    with pytest.raises(StageRuleError, match="T1566"):
        check_stage(bad, pack, ITEM)


# ---- spec 6.3: no documented exploitation -> possible scenario, inference --------------


def scenario_stage(pack, block_text="Possible scenario: an attacker could send input.",
                   detail_text="Possible scenario: an attacker could run code.", detail_tag="inference"):
    def detail(n):
        if detail_tag == "documented":
            return doc(detail_text, ATTACK)
        return inf(detail_text)

    return stage3(pack, blocks=[inf(block_text)], chain=chain_of(pack, detail=detail))


@pytest.mark.parametrize("status", ["not_documented", "unknown"])
def test_without_documented_exploitation_stage3_passes_as_a_possible_scenario(status):
    pack = chain_pack(status)
    check_stage(scenario_stage(pack), pack, ITEM)


def test_without_documented_exploitation_a_block_must_be_inference():
    pack = chain_pack("not_documented")
    content = stage3(pack, blocks=[doc("Possible scenario: input arrives.", ATTACK)],
                     chain=chain_of(pack, detail=lambda n: inf("Possible scenario: an attacker could act.")))
    with pytest.raises(StageRuleError, match="tagged inference"):
        check_stage(content, pack, ITEM)


def test_without_documented_exploitation_a_chain_detail_must_be_inference_too():
    pack = chain_pack("not_documented")
    with pytest.raises(StageRuleError, match="tagged inference"):
        check_stage(scenario_stage(pack, detail_tag="documented"), pack, ITEM)


def test_without_documented_exploitation_every_text_must_start_with_possible_scenario():
    pack = chain_pack("not_documented")
    with pytest.raises(StageRuleError, match="Possible scenario"):
        check_stage(scenario_stage(pack, block_text="An attacker could send input."), pack, ITEM)
    with pytest.raises(StageRuleError, match="Possible scenario"):
        check_stage(scenario_stage(pack, detail_text="An attacker could run code."), pack, ITEM)


def test_the_start_of_text_check_ignores_case_and_leading_space():
    pack = chain_pack("not_documented")
    check_stage(scenario_stage(pack, block_text="  possible SCENARIO: an attacker could send input."), pack, ITEM)


def test_without_documented_exploitation_a_real_attack_phrase_in_a_chain_detail_is_rejected():
    pack = chain_pack("not_documented")
    content = scenario_stage(pack, detail_text="Possible scenario: attackers exploited the flaw.")
    with pytest.raises(StageRuleError, match="describes an attack"):
        check_stage(content, pack, ITEM)


def test_documented_exploitation_needs_no_scenario_wording():
    pack = chain_pack("documented")
    check_stage(stage3(pack, blocks=[inf("The attacker sends input.")]), pack, ITEM)


# ---- the learner never sees the word "Pack" ----------------------------------------------


@pytest.mark.parametrize("text", ["The Pack records two attack steps.", "The Knowledge Pack gives no id.",
                                  "the pack has nothing"])
def test_text_may_not_mention_the_knowledge_pack(text):
    pack = chain_pack()
    with pytest.raises(StageRuleError, match="learner has never seen"):
        check_stage(stage3(pack, blocks=[inf(text)]), pack, ITEM)


def test_chain_details_and_title_are_checked_for_the_pack_name_too():
    pack = chain_pack()
    detail = chain_of(pack, detail=lambda n: inf("The Pack says so.") if n == 1 else inf("ok"))
    with pytest.raises(StageRuleError, match="learner has never seen"):
        check_stage(stage3(pack, chain=detail), pack, ITEM)
    with pytest.raises(StageRuleError, match="learner has never seen"):
        check_stage(stage3(pack, title="What the Pack says"), pack, ITEM)


@pytest.mark.parametrize("text", ["The official sources checked give no technique for step 2.",
                                  "Network packets carry the request.", "A package manager was used."])
def test_similar_words_and_the_recommended_wording_pass(text):
    pack = chain_pack()
    check_stage(stage3(pack, blocks=[inf(text)]), pack, ITEM)
