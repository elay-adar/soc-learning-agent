"""NVD (National Vulnerability Database) CVE API 2.0.

This module only fetches and parses. It never guesses: a field that NVD does not
provide comes back empty or None, and the caller decides how to label it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from src.sources.http_cache import (
    DEFAULT_CACHE_DIR,
    Downloader,
    FetchResult,
    download_json,
    fetch_json_cached,
)

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve_id}"

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Newest scoring system first. Older CVEs only carry v2.
CVSS_KEYS = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


class NvdFormatError(ValueError):
    """The NVD response does not have the expected structure."""


@dataclass(frozen=True)
class CvssScore:
    version: str
    base_score: float
    severity: str | None
    vector: str | None
    scorer: str  # who assigned the score, for example nvd@nist.gov
    kind: str  # Primary or Secondary


@dataclass(frozen=True)
class NvdRecord:
    cve_id: str
    status: str  # Analyzed, Awaiting Analysis, Rejected, ...
    published: str
    last_modified: str
    description: str | None  # English description
    cvss: CvssScore | None
    weaknesses: tuple[str, ...]  # CWE ids, Primary source first
    affected_products: tuple[str, ...]  # "vendor product", from vulnerable CPE entries
    affected_product_total: int
    patch_references: tuple[str, ...]  # URLs tagged Patch or Vendor Advisory
    detail_url: str


def normalize_cve_id(raw: str) -> str:
    cve_id = raw.strip().upper()
    if not CVE_ID_PATTERN.match(cve_id):
        raise ValueError(f"not a valid CVE id: {raw!r} (expected a form like CVE-2021-44228)")
    return cve_id


def _pick_cvss(metrics: dict) -> CvssScore | None:
    for key in CVSS_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        if score is None:
            continue
        # v3/v4 keep the severity inside cvssData, v2 keeps it on the entry
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return CvssScore(
            version=str(data.get("version", "?")),
            base_score=float(score),
            severity=severity,
            vector=data.get("vectorString"),
            scorer=str(entry.get("source", "unknown")),
            kind=str(entry.get("type", "unknown")),
        )
    return None


def _weaknesses(cve: dict) -> tuple[str, ...]:
    ordered = sorted(cve.get("weaknesses") or [], key=lambda w: w.get("type") != "Primary")
    found: list[str] = []
    for weakness in ordered:
        for desc in weakness.get("description") or []:
            value = desc.get("value")
            if desc.get("lang") == "en" and value and value not in found:
                found.append(value)
    return tuple(found)


def _affected_products(cve: dict) -> tuple[tuple[str, ...], int]:
    products: list[str] = []
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                if not match.get("vulnerable"):
                    continue
                parts = str(match.get("criteria", "")).split(":")
                # cpe:2.3:<part>:<vendor>:<product>:...
                if len(parts) > 4 and parts[3] and parts[4]:
                    name = f"{parts[3]} {parts[4]}".replace("_", " ")
                    if name not in products:
                        products.append(name)
    return tuple(products), len(products)


def _patch_references(cve: dict) -> tuple[str, ...]:
    urls: list[str] = []
    for ref in cve.get("references") or []:
        tags = ref.get("tags") or []
        url = ref.get("url")
        if url and ("Patch" in tags or "Vendor Advisory" in tags) and url not in urls:
            urls.append(url)
    return tuple(urls)


def parse_nvd_response(data: dict) -> NvdRecord | None:
    """Turn an NVD API 2.0 response for one CVE into an NvdRecord.

    Returns None when NVD reports that it has no such CVE.
    Raises NvdFormatError when the response is not shaped like an NVD response.
    """
    if not isinstance(data, dict) or "vulnerabilities" not in data:
        raise NvdFormatError("response has no 'vulnerabilities' list")
    vulnerabilities = data["vulnerabilities"]
    if not isinstance(vulnerabilities, list):
        raise NvdFormatError("'vulnerabilities' is not a list")
    if not vulnerabilities:
        return None

    cve = vulnerabilities[0].get("cve") if isinstance(vulnerabilities[0], dict) else None
    if not isinstance(cve, dict) or "id" not in cve:
        raise NvdFormatError("first vulnerability has no 'cve' object with an 'id'")

    description = next(
        (d.get("value") for d in cve.get("descriptions") or [] if d.get("lang") == "en"), None
    )
    products, total = _affected_products(cve)
    cve_id = str(cve["id"])
    return NvdRecord(
        cve_id=cve_id,
        status=str(cve.get("vulnStatus", "unknown")),
        published=str(cve.get("published", "")),
        last_modified=str(cve.get("lastModified", "")),
        description=description,
        cvss=_pick_cvss(cve.get("metrics") or {}),
        weaknesses=_weaknesses(cve),
        affected_products=products,
        affected_product_total=total,
        patch_references=_patch_references(cve),
        detail_url=NVD_DETAIL_URL.format(cve_id=cve_id),
    )


def fetch_nvd_record(
    cve_id: str,
    *,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    ttl_seconds: float = 86_400,
    downloader: Downloader = download_json,
) -> tuple[NvdRecord | None, FetchResult]:
    """Fetch one CVE from NVD. Returns (record or None if unknown to NVD, fetch details)."""
    cve_id = normalize_cve_id(cve_id)
    result = fetch_json_cached(
        NVD_API,
        {"cveId": cve_id},
        cache_dir=cache_dir,
        ttl_seconds=ttl_seconds,
        downloader=downloader,
    )
    return parse_nvd_response(result.data), result
