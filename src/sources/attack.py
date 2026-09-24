"""MITRE ATT&CK Enterprise techniques.

The official STIX data file is about 50 MB, far more than needed. It is downloaded
once, reduced to a small index (technique id, name, tactics, description, link),
and only that index is cached (for a week).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from src.sources.http_cache import (
    DEFAULT_CACHE_DIR,
    FetchResult,
    download_json,
    fetch_json_cached,
)

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack.json"
)

TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")

_CITATION = re.compile(r"\(Citation: [^)]*\)")
_MARKDOWN_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_HTML_TAG = re.compile(r"</?[a-z]+>")


class AttackFormatError(ValueError):
    """The ATT&CK data does not have the expected structure."""


@dataclass(frozen=True)
class AttackTechnique:
    technique_id: str
    name: str
    tactics: tuple[str, ...]
    description: str
    url: str
    is_subtechnique: bool


@dataclass(frozen=True)
class AttackIndex:
    version: str
    techniques: dict[str, AttackTechnique]

    def find(self, technique_id: str) -> AttackTechnique | None:
        return self.techniques.get(technique_id.strip().upper())


def clean_description(text: str) -> str:
    """Remove citation markers, markdown links and simple HTML tags."""
    text = _CITATION.sub("", text)
    text = _MARKDOWN_LINK.sub(r"\1", text)
    text = _HTML_TAG.sub("", text)
    return re.sub(r"[ \t]+", " ", text).strip()


def _mitre_reference(obj: dict) -> dict | None:
    for ref in obj.get("external_references") or []:
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref
    return None


def build_index_data(bundle: dict) -> dict:
    """Reduce a STIX bundle to a plain, JSON-friendly index (this is what gets cached)."""
    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        raise AttackFormatError("STIX bundle has no 'objects' list")

    version = "unknown"
    techniques: dict[str, dict] = {}
    for obj in bundle["objects"]:
        if not isinstance(obj, dict):
            continue
        if obj.get("type") == "x-mitre-collection" and obj.get("x_mitre_version"):
            version = str(obj["x_mitre_version"])
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ref = _mitre_reference(obj)
        if ref is None:
            continue
        technique_id = str(ref["external_id"])
        tactics = [
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases") or []
            if phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")
        ]
        techniques[technique_id] = {
            "name": str(obj.get("name", "")),
            "tactics": tactics,
            "description": clean_description(str(obj.get("description", ""))),
            "url": str(ref.get("url", "")),
            "is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False)),
        }
    return {"version": version, "techniques": techniques}


def index_from_data(data: dict) -> AttackIndex:
    try:
        techniques = {
            tid: AttackTechnique(
                technique_id=tid,
                name=t["name"],
                tactics=tuple(t["tactics"]),
                description=t["description"],
                url=t["url"],
                is_subtechnique=t["is_subtechnique"],
            )
            for tid, t in data["techniques"].items()
        }
        return AttackIndex(version=str(data["version"]), techniques=techniques)
    except (KeyError, TypeError, AttributeError) as exc:
        raise AttackFormatError(f"cached ATT&CK index is malformed: {exc}") from exc


def _download_and_reduce(url: str) -> dict:
    return build_index_data(download_json(url, timeout=180.0))


def fetch_attack_index(
    *,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    ttl_seconds: float = 7 * 86_400,
    downloader=_download_and_reduce,
) -> tuple[AttackIndex, FetchResult]:
    """Return the technique index. The first call downloads about 50 MB; later calls read the cache.

    A custom downloader must return the already-reduced index data (see build_index_data).
    """
    result = fetch_json_cached(
        ATTACK_STIX_URL, cache_dir=cache_dir, ttl_seconds=ttl_seconds, downloader=downloader
    )
    return index_from_data(result.data), result
