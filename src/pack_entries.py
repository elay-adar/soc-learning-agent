"""Every sourced item in a Knowledge Pack, with a label saying where it sits.

Shared by the stage rules (src/stage_rules.py), the trace check (src/trace.py) and the support check
(src/support_check.py). It lives in its own module so those can use it without importing each other.
"""

from __future__ import annotations

from src.merge import normalize_url
from src.schemas import KnowledgePack, SourcedValue


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
