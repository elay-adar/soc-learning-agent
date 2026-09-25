"""Rules a stage written by the Lecturer must satisfy, enforced in code (spec section 6.3, D-006).

The Lecturer is a model, so its text is checked here against the Knowledge Pack and the
recorded exploitation status. All problems are reported together and sent back for correction.

Limits, stated plainly: a URL check proves a citation points at something in the Pack, not that
the sentence is supported by it (D-020). The "describes an attack" check is a short list of
phrases, not a reading of meaning.
"""

from __future__ import annotations

import re

from src.mermaid_check import MermaidError, check_mermaid
from src.merge import normalize_url
from src.schemas import ExploitationStatus, KnowledgePack, ProvenanceTag, SourcedValue, StagePlanItem
from src.stage_content import StageContent

NO_INCIDENT_PHRASE = "No documented incident from official sources"
OVERVIEW_KEY = "overview"
WHY_POSSIBLE_KEY = "why_possible"

# Wording that presents an attack as having really happened.
_REAL_ATTACK = re.compile(
    r"\b(?:was|were|been|got)\s+(?:actively\s+)?exploited\b"
    r"|\bexploited\s+in\s+the\s+wild\b"
    r"|\battackers?\s+(?:have\s+|has\s+)?(?:actively\s+)?(?:exploited|compromised|breached|stole|encrypted)\b"
    r"|\b(?:criminals|threat actors|hackers)\s+(?:have\s+)?exploited\b",
    re.IGNORECASE,
)


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


def check_stage(content: StageContent, pack: KnowledgePack, item: StagePlanItem) -> None:
    """Raise StageRuleError unless the stage matches its plan item and follows the rules."""
    problems: list[str] = []
    if content.stage_number != item.number:
        problems.append(f"stage_number is {content.stage_number}, expected {item.number}")
    if content.key != item.key:
        problems.append(f"key is '{content.key}', expected '{item.key}'")
    if content.diagram.type != item.diagram:
        problems.append(
            f"diagram type is '{content.diagram.type.value}', the plan says '{item.diagram.value}'"
        )

    known = pack_urls(pack)
    for block in content.blocks:
        if block.tag == ProvenanceTag.DOCUMENTED and normalize_url(block.source_url) not in known:
            problems.append(f"a documented block cites {block.source_url}, which is not in the Knowledge Pack")

    try:
        check_mermaid(content.diagram.mermaid, content.diagram.type)
    except MermaidError as exc:
        problems.append(f"diagram: {exc}")

    problems += _exploitation_problems(content, pack)
    if content.key == WHY_POSSIBLE_KEY:
        problems += _why_possible_problems(content, pack)

    if problems:
        raise StageRuleError("; ".join(problems))


def _exploitation_problems(content: StageContent, pack: KnowledgePack) -> list[str]:
    texts = [block.value for block in content.blocks]
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
