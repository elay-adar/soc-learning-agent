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
from src.pack_entries import pack_entries, pack_urls
from src.schemas import (
    DiagramType,
    ExploitationStatus,
    FieldStatus,
    KnowledgePack,
    ProvenanceTag,
    SourcedValue,
    StagePlanItem,
    TopicType,
)
from src.sources.secondary import is_secondary_url
from src.stage_content import StageContent
from src.support_check import DOCUMENTED_LIMIT, sentence_scores, url_pools

NO_INCIDENT_PHRASE = "No documented incident from official sources"
OVERVIEW_KEY = "overview"
WHY_POSSIBLE_KEY = "why_possible"
ATTACK_CHAIN_KEY = "attack_chain"
POSSIBLE_SCENARIO = "possible scenario"  # spec section 6.3: stage 3 without documented exploitation
NO_CVE_CWE_PHRASE = "no CVE or CWE"  # D-029: stage 2 says this when the topic has neither

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
# D-028: the learner-facing text never says "kill chain" (a technique is one step, not a chain).
_KILL_CHAIN = re.compile(r"\bkill[\s-]*chain", re.IGNORECASE)
# D-029, D-036: stage 1 is conceptual, so none of these belong in its prose: identifiers, scores,
# and the names of encryption algorithms (which belong to the mechanism in stage 2).
_STAGE1_FORBIDDEN = re.compile(
    r"\bCWE-\d+|\bCVSS\b|\bT\d{4}(?:\.\d{3})?\b|\b(?:RC4|AES(?:[-\s]?\d+)?|3?DES|NTLM|etype)\b",
    re.IGNORECASE,
)
# D-036: stage 2 explains the design flaw; the attacker's numbered procedure is stage 3.
_STEP_LABEL = re.compile(r"^\s*(?:failure\s+mechanism\s*,?\s*)?step\s*\d+\b", re.IGNORECASE)
_CVE_OR_CWE_ID = re.compile(r"\b(?:CVE-\d{4}-\d+|CWE-\d+)\b", re.IGNORECASE)


class StageRuleError(ValueError):
    """The stage breaks one or more rules. The message lists every problem."""


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
    problems += _source_problems(content, pack)
    problems += _documented_support_problems(content, pack)

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
    if _KILL_CHAIN.search(" ".join(words)):
        problems.append("the text says 'kill chain'; a technique is one execution flow, so say 'execution flow'")
    # D-029: a technique-only topic has no incident to be documented or undocumented, so the
    # exploitation rules do not apply to it (an enum value for this is a follow-up, D-032).
    exploitation_applies = pack.topic_type != TopicType.TECHNIQUE
    if exploitation_applies:
        problems += _exploitation_problems(content, pack)
    if content.key == OVERVIEW_KEY:
        problems += _overview_problems(content)
    if content.key == WHY_POSSIBLE_KEY:
        problems += _why_possible_problems(content, pack)
    if content.key == ATTACK_CHAIN_KEY:
        problems += _attack_chain_problems(content, pack, exploitation_applies)

    if problems:
        raise StageRuleError("; ".join(problems))


def has_cve_or_cwe(pack: KnowledgePack) -> bool:
    """True for a CVE topic, or when the Pack holds a weakness (CWE) value from its sources."""
    if pack.topic_type == TopicType.CVE:
        return True
    weakness = pack.triage_fields.get("weakness_type")
    return weakness is not None and weakness.status == FieldStatus.VALUE


def _source_problems(content: StageContent, pack: KnowledgePack) -> list[str]:
    """Each block's tag must match its source: documented blocks cite official pages, secondary
    blocks cite allowlist pages, and both cite a URL the Pack holds. The tag the Pack itself gave
    that URL must agree, so a secondary source cannot be relabelled as official (D-027)."""
    known = pack_urls(pack)
    tags_by_url: dict[str, set[ProvenanceTag]] = {}
    for _, entry in pack_entries(pack):
        if entry.source_url:
            tags_by_url.setdefault(normalize_url(entry.source_url), set()).add(entry.tag)
    problems: list[str] = []
    for block in content.all_tagged():
        if block.tag not in (ProvenanceTag.DOCUMENTED, ProvenanceTag.SECONDARY):
            continue
        url = block.source_url
        if normalize_url(url) not in known:
            problems.append(f"a {block.tag.value} block cites {url}, which is not in the Knowledge Pack")
        elif block.tag == ProvenanceTag.DOCUMENTED and is_secondary_url(url):
            problems.append(f"a documented block cites {url}, which is a secondary source; tag it 'secondary'")
        elif block.tag == ProvenanceTag.SECONDARY and not is_secondary_url(url):
            problems.append(f"a secondary block cites {url}, which is not a secondary-source page")
        elif block.tag == ProvenanceTag.SECONDARY and ProvenanceTag.DOCUMENTED in tags_by_url[normalize_url(url)]:
            problems.append(f"a secondary block cites {url}, which the Knowledge Pack records as documented")
    return problems


def _documented_support_problems(content: StageContent, pack: KnowledgePack) -> list[str]:
    """D-037: documented text restates an official source, so a sentence that shares almost none of
    its words with the Pack entries under its URL is rejected. Secondary text is only warned about
    (src/support_check.py). A URL missing from the Pack is already reported by _source_problems."""
    pools = url_pools(pack)
    problems: list[str] = []
    for block in content.all_tagged():
        if block.tag != ProvenanceTag.DOCUMENTED or normalize_url(block.source_url) not in pools:
            continue
        for sentence, coverage, _ in sentence_scores(block.value, pools[normalize_url(block.source_url)]):
            if coverage < DOCUMENTED_LIMIT:
                problems.append(
                    f'a documented sentence "{sentence[:90]}" shares only {coverage:.0%} of its words with the '
                    f"entries under {block.source_url}; documented text must restate the source, so put your "
                    "own remark in a block tagged inference"
                )
    return problems


def _overview_problems(content: StageContent) -> list[str]:
    texts = (content.title, *(g.term for g in content.glossary), *(b.value for b in content.all_tagged()))
    for text in texts:
        found = _STAGE1_FORBIDDEN.search(text)
        if found:
            return [
                "the stage 1 text must not contain a CWE id, a CVSS mention, an ATT&CK technique id "
                f"or an algorithm name (found '{found.group(0)}'): those belong to later stages"
            ]
    return []


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


def _attack_chain_problems(
    content: StageContent, pack: KnowledgePack, exploitation_applies: bool = True
) -> list[str]:
    problems = []
    items = content.all_blocks()
    if exploitation_applies and pack.exploitation_status != ExploitationStatus.DOCUMENTED:
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
    if pack.topic_type == TopicType.TECHNIQUE:
        allowed.add(pack.topic.split(".")[0])  # the topic itself: secondary steps carry no id (D-034)
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
    problems: list[str] = []
    documented_weakness = any(w.tag == ProvenanceTag.DOCUMENTED for w in pack.weakness_mechanism)
    has_documented_block = any(b.tag == ProvenanceTag.DOCUMENTED for b in content.blocks)
    if documented_weakness and not has_documented_block:
        problems.append("the Pack documents the weakness, so stage 2 needs at least one documented block")

    if any(_STEP_LABEL.match(b.value) for b in content.blocks):
        problems.append(
            "stage 2 lists the attack steps ('Step N: ...'); the attacker's steps belong to stage 3, "
            "so explain how the design flaw works instead"
        )

    joined = " ".join(b.value for b in content.all_tagged())
    says_none = NO_CVE_CWE_PHRASE.lower() in joined.lower()
    if has_cve_or_cwe(pack):
        if says_none:
            problems.append(f"the topic has a CVE or CWE, so stage 2 must not say '{NO_CVE_CWE_PHRASE}'")
        return problems
    if not says_none:
        problems.append(f"the topic has {NO_CVE_CWE_PHRASE}: stage 2 must say so explicitly, then explain the flaw itself")
    for found in _CVE_OR_CWE_ID.findall(joined):
        problems.append(f"stage 2 names {found}, but the topic has {NO_CVE_CWE_PHRASE}")
    secondary_weakness = any(w.tag == ProvenanceTag.SECONDARY for w in pack.weakness_mechanism)
    if secondary_weakness and not any(b.tag == ProvenanceTag.SECONDARY for b in content.blocks):
        problems.append("the flaw comes from a secondary source, so stage 2 needs at least one secondary block")
    return problems
