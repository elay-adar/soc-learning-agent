"""Rules a stage written by the Lecturer must satisfy, enforced in code (spec section 6.3, D-006).

The Lecturer is a model, so its text is checked here against the Knowledge Pack and the
recorded exploitation status. All problems are reported together and sent back for correction.

Limits, stated plainly: a URL check proves a citation points at something in the Pack, not that
the sentence is supported by it (D-020). The "describes an attack" check is a short list of
phrases, not a reading of meaning.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

from src.frames import FrameError, build_frames
from src.glossary import repeated_terms
from src.mermaid_check import MermaidError, check_mermaid
from src.merge import normalize_url
from src.schemas import (
    DiagramType,
    ExploitationStatus,
    KnowledgePack,
    ProvenanceTag,
    SourcedValue,
    StagePlanItem,
)
from src.stage_content import StageContent

NO_INCIDENT_PHRASE = "No documented incident from official sources"
OVERVIEW_KEY = "overview"
WHY_POSSIBLE_KEY = "why_possible"
ATTACK_CHAIN_KEY = "attack_chain"
POSSIBLE_SCENARIO = "possible scenario"  # spec section 6.3: stage 3 without documented exploitation

# Wording that presents an attack as having really happened.
_REAL_ATTACK = re.compile(
    r"\b(?:was|were|been|got)\s+(?:actively\s+)?exploited\b"
    r"|\bexploited\s+in\s+the\s+wild\b"
    r"|\battackers?\s+(?:have\s+|has\s+)?(?:actively\s+)?(?:exploited|compromised|breached|stole|encrypted)\b"
    r"|\b(?:criminals|threat actors|hackers)\s+(?:have\s+)?exploited\b",
    re.IGNORECASE,
)
# The learner has never seen the Knowledge Pack, so its name must not appear in their text.
_INTERNAL_NAME = re.compile(r"\b(?:knowledge\s+)?pack\b", re.IGNORECASE)
_TECHNIQUE_IN_TEXT = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


class StageRuleError(ValueError):
    """The stage breaks one or more rules. The message lists every problem."""


def pack_entries(pack: KnowledgePack) -> list[tuple[str, SourcedValue]]:
    """Every sourced item in the Pack, with a label saying where it sits."""
    entries: list[tuple[str, SourcedValue | None]] = [("exploitation_evidence", pack.exploitation_evidence)]
    entries += [(f"weakness_mechanism[{i}]", w) for i, w in enumerate(pack.weakness_mechanism)]
    entries += [(f"triage_fields.{name}", f.item) for name, f in pack.triage_fields.items()]
    entries += [(f"incidents[{i}] impact ({inc.name})", inc.impact) for i, inc in enumerate(pack.incidents)]
    entries += [(f"attack_steps[{step.number}]", step.action) for step in pack.attack_steps]
    entries += [(f"detection_items[{i}]", d.content) for i, d in enumerate(pack.detection_items)]
    entries += [(f"response_items[{i}]", r.content) for i, r in enumerate(pack.response_items)]
    for i, conflict in enumerate(pack.conflicts):
        entries += [(f"conflicts[{i}].claims[{j}]", c) for j, c in enumerate(conflict.claims)]
    return [(label, item) for label, item in entries if item is not None]


def pack_urls(pack: KnowledgePack) -> set[str]:
    """Every source URL that appears anywhere in the Pack (trailing slashes ignored)."""
    return {normalize_url(item.source_url) for _, item in pack_entries(pack) if item.source_url}


def check_stage(
    content: StageContent,
    pack: KnowledgePack,
    item: StagePlanItem,
    earlier: Sequence[StageContent] = (),
) -> None:
    """Raise StageRuleError unless the stage matches its plan item and follows the rules.

    `earlier` are the stages already written in this run: a glossary term may not be defined again.
    """
    problems: list[str] = []
    if content.stage_number != item.number:
        problems.append(f"stage_number is {content.stage_number}, expected {item.number}")
    if content.key != item.key:
        problems.append(f"key is '{content.key}', expected '{item.key}'")
    known = pack_urls(pack)
    for block in content.all_tagged():
        if block.tag == ProvenanceTag.DOCUMENTED and normalize_url(block.source_url) not in known:
            problems.append(f"a documented block cites {block.source_url}, which is not in the Knowledge Pack")

    if item.diagram == DiagramType.KILL_CHAIN_FRAMES:
        problems += _frames_problems(content, pack)
    else:
        problems += _diagram_problems(content, item)

    words = [content.title, *(g.term for g in content.glossary), *(b.value for b in content.all_tagged())]
    if _INTERNAL_NAME.search(" ".join(words)):
        problems.append(
            "the text mentions 'the Pack' or 'the Knowledge Pack', which the learner has never seen; "
            "say 'the official sources checked' instead"
        )

    problems += repeated_terms(
        [g.term for g in content.glossary],
        [(stage.stage_number, [g.term for g in stage.glossary]) for stage in earlier],
    )
    problems += _exploitation_problems(content, pack)
    if content.key == WHY_POSSIBLE_KEY:
        problems += _why_possible_problems(content, pack)
    if content.key == ATTACK_CHAIN_KEY:
        problems += _attack_chain_problems(content, pack)

    if problems:
        raise StageRuleError("; ".join(problems))


def _diagram_problems(content: StageContent, item: StagePlanItem) -> list[str]:
    if content.frames:
        return ["this stage must have one diagram, not frames"]
    if content.diagram is None:
        return [f"the stage needs a '{item.diagram.value}' diagram"]
    problems = []
    if content.diagram.type != item.diagram:
        problems.append(
            f"diagram type is '{content.diagram.type.value}', the plan says '{item.diagram.value}'"
        )
    try:
        check_mermaid(content.diagram.mermaid, content.diagram.type)
    except MermaidError as exc:
        problems.append(f"diagram: {exc}")
    return problems


def _frames_problems(content: StageContent, pack: KnowledgePack) -> list[str]:
    """Frames must be exactly what code builds from the chain, so their count equals the steps."""
    if content.diagram is not None:
        return ["this stage has frames, so it must not have a single diagram"]
    if not content.frames:
        return ["the stage needs one frame per attack step"]
    try:
        built = build_frames(pack, content.chain)
    except FrameError as exc:
        return [f"frames: {exc}"]
    if built != content.frames:
        return ["frames: they do not match the ones built from the chain entries and the Pack"]
    return []


def _attack_chain_problems(content: StageContent, pack: KnowledgePack) -> list[str]:
    problems = []
    items = content.all_blocks()
    if pack.exploitation_status != ExploitationStatus.DOCUMENTED:
        # Spec section 6.3: without documented exploitation stage 3 is a possible scenario.
        for block in items:
            if block.tag != ProvenanceTag.INFERENCE:
                problems.append("without documented exploitation every stage 3 text must be tagged inference")
                break
        for block in items:
            if not block.value.strip().lower().startswith(POSSIBLE_SCENARIO):
                problems.append(f"without documented exploitation every stage 3 text must start with '{POSSIBLE_SCENARIO.capitalize()}'")
                break
    allowed = {step.mitre_technique.split(".")[0] for step in pack.attack_steps if step.mitre_technique}
    for block in content.all_tagged():
        for technique in _TECHNIQUE_IN_TEXT.findall(block.value):
            if technique.split(".")[0] not in allowed:
                problems.append(f"the text names ATT&CK technique {technique}, which is not in the Knowledge Pack")
    return problems


def _exploitation_problems(content: StageContent, pack: KnowledgePack) -> list[str]:
    texts = [block.value for block in content.all_tagged()]
    joined = " ".join(texts).lower()
    status = pack.exploitation_status
    problems: list[str] = []

    if status == ExploitationStatus.DOCUMENTED:
        if NO_INCIDENT_PHRASE.lower() in joined:
            problems.append(
                f"the Pack has documented exploitation, so the text must not say '{NO_INCIDENT_PHRASE}'"
            )
        if content.key == OVERVIEW_KEY:
            evidence = {pack.exploitation_evidence.source_url, *(i.impact.source_url for i in pack.incidents)}
            cited = {normalize_url(b.source_url) for b in content.blocks if b.tag == ProvenanceTag.DOCUMENTED}
            if not cited & {normalize_url(u) for u in evidence if u}:
                problems.append(
                    "stage 1 must state the documented incident: cite the exploitation evidence "
                    "or an incident impact URL from the Pack in a documented block"
                )
        return problems

    # not documented, or unknown: nothing may be presented as a real attack
    if any(_REAL_ATTACK.search(text) for text in texts):
        problems.append(
            "the text describes an attack as having happened, but the Pack has no documented "
            "exploitation; use hypothetical wording ('an attacker could ...')"
        )
    if content.key == OVERVIEW_KEY:
        if NO_INCIDENT_PHRASE.lower() not in joined:
            problems.append(f"stage 1 must say '{NO_INCIDENT_PHRASE}'")
        if "potential" not in joined:
            problems.append("stage 1 must label the described impact as potential")
        if status == ExploitationStatus.UNKNOWN and "partial" not in joined:
            problems.append("stage 1 must note that the exploitation check was partial")
    return problems


def _why_possible_problems(content: StageContent, pack: KnowledgePack) -> list[str]:
    documented_weakness = any(w.tag == ProvenanceTag.DOCUMENTED for w in pack.weakness_mechanism)
    has_documented_block = any(b.tag == ProvenanceTag.DOCUMENTED for b in content.blocks)
    if documented_weakness and not has_documented_block:
        return ["the Pack documents the weakness, so stage 2 needs at least one documented block"]
    return []
