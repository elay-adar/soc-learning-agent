"""What the user types as a topic: a CVE id or an ATT&CK technique id (D-033)."""

from __future__ import annotations

from src.sources.attack import TECHNIQUE_ID_PATTERN, normalize_technique_id
from src.sources.nvd import normalize_cve_id


def normalize_topic(text: str) -> str:
    """Return the trimmed, upper-cased id (CVE-2021-44228 or T1558.003). Raises ValueError otherwise."""
    if TECHNIQUE_ID_PATTERN.match(text.strip().upper()):
        return normalize_technique_id(text)
    try:
        return normalize_cve_id(text)
    except ValueError as exc:
        raise ValueError(
            f"not a CVE id or an ATT&CK technique id: {text!r} (for example CVE-2021-44228 or T1558.003)"
        ) from exc
