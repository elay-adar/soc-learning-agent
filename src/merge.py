"""Merge what the Researcher agent proposes onto the facts that code collected (part A).

Code owns the fields that come straight from official sources: topic, topic type,
exploitation status and its evidence, and the triage fields. The agent may only ADD
entries to the lists in `ResearcherAdditions`. Because that model forbids extra keys,
an attempt to set or overwrite a code-owned field is rejected, not silently ignored.
The merged result is then validated as a full KnowledgePack, so the exploitation rules
in src/schemas.py still apply (for example: no incidents unless exploitation is documented).
"""

from __future__ import annotations

import json
from collections.abc import Collection
from typing import Any
from urllib.parse import urlparse

from pydantic import ValidationError

from src.schemas import (
    AttackStep,
    DetectionItem,
    Incident,
    KnowledgePack,
    ResponseItem,
    SourceConflict,
    SourcedValue,
    ProvenanceTag,
    StrictModel,
)
from src.sources.secondary import SECONDARY_DOMAINS, is_secondary_url


# Official sources the Researcher's tools read. A "documented" claim from the agent must cite one
# of these (a subdomain counts, a look-alike such as nvd.nist.gov.example.com does not).
# A "secondary" claim must cite SECONDARY_DOMAINS instead; the two lists are never mixed (D-030).
OFFICIAL_DOMAINS = ("nvd.nist.gov", "cisa.gov", "attack.mitre.org", "cwe.mitre.org", "first.org")


class MergeError(ValueError):
    """The agent's output is not valid, or would break a rule. The message says why, so it
    can be sent back to the agent for one correction."""


class ResearcherAdditions(StrictModel):
    """The only things the agent may contribute. Every list is optional."""

    weakness_mechanism: list[SourcedValue] = []
    attack_steps: list[AttackStep] = []
    incidents: list[Incident] = []
    detection_items: list[DetectionItem] = []
    response_items: list[ResponseItem] = []
    conflicts: list[SourceConflict] = []


def parse_additions(raw: str | dict[str, Any]) -> ResearcherAdditions:
    """Parse the agent's output (JSON text or an already-parsed dict)."""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise MergeError(f"the output is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise MergeError("the output must be a JSON object")
    try:
        return ResearcherAdditions.model_validate(raw)
    except ValidationError as exc:
        raise MergeError(_explain(exc)) from exc


def merge_additions(
    base: KnowledgePack,
    additions: ResearcherAdditions,
    allowed_urls: Collection[str] | None = None,
) -> KnowledgePack:
    """Return a new, fully validated Pack: the base facts plus the agent's additions.

    Lists are appended to whatever the base already holds. The base is never modified.
    If `allowed_urls` is given, every source URL the agent cites must be one of them (the
    URLs the tools returned during this run), on top of being an official domain.
    """
    _check_documented_sources(additions, allowed_urls)
    data = base.model_dump(mode="json")
    for name in ResearcherAdditions.model_fields:
        extra = getattr(additions, name)
        data[name] = data[name] + [item.model_dump(mode="json") for item in extra]
    try:
        return KnowledgePack.model_validate(data)
    except ValidationError as exc:
        raise MergeError(_explain(exc)) from exc


def is_official_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return any(host == d or host.endswith("." + d) for d in OFFICIAL_DOMAINS)


def _sourced_values(additions: ResearcherAdditions) -> list[tuple[str, SourcedValue]]:
    found: list[tuple[str, SourcedValue]] = []
    for i, v in enumerate(additions.weakness_mechanism):
        found.append((f"weakness_mechanism.{i}", v))
    for i, s in enumerate(additions.attack_steps):
        found.append((f"attack_steps.{i}.action", s.action))
    for i, inc in enumerate(additions.incidents):
        found.append((f"incidents.{i}.impact", inc.impact))
    for i, d in enumerate(additions.detection_items):
        found.append((f"detection_items.{i}.content", d.content))
    for i, r in enumerate(additions.response_items):
        found.append((f"response_items.{i}.content", r.content))
    for i, c in enumerate(additions.conflicts):
        for j, claim in enumerate(c.claims):
            found.append((f"conflicts.{i}.claims.{j}", claim))
    return found


def normalize_url(url: str) -> str:
    return url.strip().rstrip("/")


# Where a secondary source may be used at all (D-027, D-029, D-034): explaining the mechanism and
# the execution flow. Detection, response and conflicts need other grounding.
SECONDARY_FIELDS = ("weakness_mechanism", "attack_steps")


def _secondary_scope_problems(additions: ResearcherAdditions) -> list[str]:
    problems: list[str] = []
    for where, value in _sourced_values(additions):
        if value.tag == ProvenanceTag.SECONDARY and where.split(".")[0] not in SECONDARY_FIELDS:
            problems.append(
                f"{where}: a 'secondary' claim is only allowed for weakness_mechanism and attack_steps; "
                "tag this entry 'inference' or leave it out"
            )
    for i, attack_step in enumerate(additions.attack_steps):
        if attack_step.action.tag == ProvenanceTag.SECONDARY and attack_step.mitre_technique:
            problems.append(
                f"attack_steps.{i}.mitre_technique: a step taken from a secondary source cannot carry an "
                "ATT&CK technique id, because the page does not map its steps to ATT&CK; leave it out"
            )
    return problems


def _check_documented_sources(
    additions: ResearcherAdditions, allowed_urls: Collection[str] | None = None
) -> None:
    problems: list[str] = _secondary_scope_problems(additions)
    seen = {normalize_url(u) for u in allowed_urls} if allowed_urls is not None else None
    for where, value in _sourced_values(additions):
        url = value.source_url
        if not url:
            continue
        if value.tag == ProvenanceTag.SECONDARY:
            if not is_secondary_url(url):
                problems.append(
                    f"{where}: a 'secondary' claim must cite an https page on the secondary-source "
                    f"allowlist ({', '.join(SECONDARY_DOMAINS)}), not {url!r}"
                )
                continue
        elif not is_official_url(url):
            hint = " (a secondary source needs the tag 'secondary')" if is_secondary_url(url) else ""
            problems.append(
                f"{where}: source_url {url!r} is not an official source "
                f"(allowed: {', '.join(OFFICIAL_DOMAINS)}){hint}"
            )
            continue
        if seen is not None and normalize_url(url) not in seen:
            problems.append(
                f"{where}: source_url {url!r} was not returned by any tool in this run; "
                "cite only a URL that appears as the source of a tool result"
            )
    if problems:
        raise MergeError("; ".join(problems))


def _explain(exc: ValidationError) -> str:
    lines = []
    for err in exc.errors():
        where = ".".join(str(part) for part in err["loc"]) or "(output)"
        lines.append(f"{where}: {err['msg']}")
    return "; ".join(lines)
