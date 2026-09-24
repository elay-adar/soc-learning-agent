"""Part A of the Researcher: facts that need no model.

Takes what NVD and CISA KEV report and writes it into a Knowledge Pack, one field at
a time, each with its source. Anything the sources do not say is marked "unknown" or
"not applicable". Nothing is guessed. The parts that need understanding (mechanism,
attack steps, detection, response) are added later, by the model-driven part.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from src.schemas import (
    ExploitationStatus,
    FieldStatus,
    KnowledgePack,
    ProvenanceTag,
    SourcedValue,
    TopicType,
    TriageField,
)
from src.sources.http_cache import DEFAULT_CACHE_DIR, Downloader, FetchError, download_json
from src.sources.kev import KEV_CATALOG_PAGE, KevCatalog, KevEntry, fetch_kev_catalog
from src.sources.nvd import NvdRecord, fetch_nvd_record, normalize_cve_id


MAX_PRODUCTS = 15


class CveNotFoundError(LookupError):
    """NVD has no record for this CVE id."""


class CveRejectedError(ValueError):
    """NVD marks this CVE as rejected, so it is not a real vulnerability."""


@dataclass
class FactsResult:
    pack: KnowledgePack
    notes: list[str] = field(default_factory=list)


def _documented(value: str, url: str) -> SourcedValue:
    return SourcedValue(value=value, tag=ProvenanceTag.DOCUMENTED, source_url=url)


def _field(value: str, url: str) -> TriageField:
    return TriageField(status=FieldStatus.VALUE, item=_documented(value, url))


def _unknown() -> TriageField:
    return TriageField(status=FieldStatus.UNKNOWN)


def _exploitation_field(record: NvdRecord, kev: KevCatalog | None) -> TriageField:
    if kev is None:
        return _unknown()
    entry = kev.find(record.cve_id)
    if entry is not None:
        return _field(
            f"Listed in the CISA KEV catalog, added {entry.date_added}; "
            f"ransomware campaign use in KEV: {entry.ransomware_use}",
            KEV_CATALOG_PAGE,
        )
    return _field(
        f"Not listed in the CISA KEV catalog (catalog version {kev.version}, "
        f"released {kev.date_released[:10]})",
        KEV_CATALOG_PAGE,
    )


def _severity_field(record: NvdRecord) -> TriageField:
    cvss = record.cvss
    if cvss is None:
        return _unknown()
    severity = f" ({cvss.severity})" if cvss.severity else ""
    return _field(
        f"CVSS {cvss.version} base score {cvss.base_score:.1f}{severity}; "
        f"{cvss.kind.lower()} score from {cvss.scorer}",
        record.detail_url,
    )


def _weakness_field(record: NvdRecord) -> TriageField:
    if not record.weaknesses:
        return _unknown()
    return _field(", ".join(record.weaknesses), record.detail_url)


def _squash(text: str) -> str:
    return "".join(ch for ch in text.casefold() if ch.isalnum())


def _matches_kev(product: str, entry: KevEntry) -> bool:
    """True if an NVD "vendor product" name is the product KEV names (same vendor, product
    names equal or one a prefix of the other, e.g. KEV "Log4j2" and NVD "log4j")."""
    vendor, _, name = product.partition(" ")
    kev_vendor, kev_product = _squash(entry.vendor), _squash(entry.product)
    name = _squash(name)
    if not (kev_vendor and kev_product and name) or _squash(vendor) != kev_vendor:
        return False
    return name.startswith(kev_product) or kev_product.startswith(name)


def _products_field(record: NvdRecord, entry: KevEntry | None) -> TriageField:
    if not record.affected_products:
        return _unknown()
    ordered = sorted(record.affected_products, key=str.casefold)
    if entry is not None:  # the product KEV names goes first; sort is stable
        ordered.sort(key=lambda p: not _matches_kev(p, entry))
    shown = ordered[:MAX_PRODUCTS]
    text = ", ".join(shown)
    hidden = record.affected_product_total - len(shown)
    if hidden > 0:
        text += f" (and {hidden} more)"
    return _field(text, record.detail_url)


def _fix_field(record: NvdRecord) -> TriageField:
    refs = record.patch_references
    if not refs:
        return _unknown()
    return _field(
        f"NVD lists {len(refs)} patch or vendor advisory reference(s); first: {refs[0]}",
        record.detail_url,
    )


def assemble_pack(record: NvdRecord, kev: KevCatalog | None) -> KnowledgePack:
    """Build a partial Knowledge Pack from an NVD record and, if available, the KEV catalog.

    kev=None means the catalog could not be checked, which is different from "checked and
    not listed". The first gives exploitation status UNKNOWN, the second NOT_DOCUMENTED.
    """
    if record.status.lower().startswith("rejected"):
        raise CveRejectedError(f"{record.cve_id} is marked as rejected in NVD")

    entry = kev.find(record.cve_id) if kev is not None else None
    evidence: SourcedValue | None = None
    if kev is None:
        status = ExploitationStatus.UNKNOWN
    elif entry is not None:
        status = ExploitationStatus.DOCUMENTED
        evidence = _documented(
            f"CISA KEV lists {record.cve_id} as exploited in the wild (added {entry.date_added})",
            KEV_CATALOG_PAGE,
        )
    else:
        status = ExploitationStatus.NOT_DOCUMENTED

    triage = {
        "exploited_in_the_wild": _exploitation_field(record, kev),
        "severity_cvss": _severity_field(record),
        "weakness_type": _weakness_field(record),
        "affected_products": _products_field(record, entry),
        "fix_status": _fix_field(record),
        "published": _field(record.published[:10], record.detail_url)
        if record.published
        else _unknown(),
        "nvd_analysis_status": _field(record.status, record.detail_url),
    }

    descriptions: list[SourcedValue] = []
    if record.description:
        descriptions.append(_documented(f"NVD description: {record.description}", record.detail_url))
    if entry is not None and entry.short_description:
        descriptions.append(
            _documented(f"CISA KEV description: {entry.short_description}", KEV_CATALOG_PAGE)
        )

    return KnowledgePack(
        topic=record.cve_id,
        topic_type=TopicType.CVE,
        exploitation_status=status,
        exploitation_evidence=evidence,
        triage_fields=triage,
        weakness_mechanism=descriptions,
    )


def collect_facts(
    cve_id: str,
    *,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    nvd_downloader: Downloader = download_json,
    kev_downloader: Downloader = download_json,
) -> FactsResult:
    """Fetch NVD and KEV data for one CVE and return a partial Knowledge Pack plus notes.

    Raises ValueError for a malformed id, CveNotFoundError if NVD has no such CVE,
    CveRejectedError for rejected CVEs, and FetchError if NVD cannot be reached
    (NVD is required; KEV is optional and its absence is reported in the notes).
    """
    cve_id = normalize_cve_id(cve_id)
    notes: list[str] = []

    record, nvd_fetch = fetch_nvd_record(cve_id, cache_dir=cache_dir, downloader=nvd_downloader)
    if record is None:
        raise CveNotFoundError(f"NVD has no record for {cve_id}")
    if nvd_fetch.stale:
        notes.append(f"NVD could not be reached; using cached data from {nvd_fetch.fetched_at}")

    kev: KevCatalog | None = None
    try:
        kev, kev_fetch = fetch_kev_catalog(cache_dir=cache_dir, downloader=kev_downloader)
        if kev_fetch.stale:
            notes.append(f"KEV could not be reached; using cached data from {kev_fetch.fetched_at}")
    except FetchError as exc:
        notes.append(f"{exc}. Exploitation status is set to unknown.")

    if record.cvss is None:
        notes.append(f"NVD has no CVSS score for this CVE yet (analysis status: {record.status})")
    if not record.weaknesses:
        notes.append("NVD lists no weakness type (CWE) for this CVE yet")

    return FactsResult(pack=assemble_pack(record, kev), notes=notes)
