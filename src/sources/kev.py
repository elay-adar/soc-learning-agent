"""CISA Known Exploited Vulnerabilities (KEV) catalog.

The catalog is a single JSON file of about 1.7 MB. It is cached for a day.
The primary feed is on cisa.gov. The cisagov GitHub repository publishes the same
catalog and is used as a fallback.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from src.sources.http_cache import (
    DEFAULT_CACHE_DIR,
    Downloader,
    FetchError,
    FetchResult,
    download_json,
    fetch_json_cached,
)

KEV_CATALOG_PAGE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"

KEV_FEED_URLS = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
)


class KevFormatError(ValueError):
    """The KEV file does not have the expected structure."""


@dataclass(frozen=True)
class KevEntry:
    cve_id: str
    vendor: str
    product: str
    name: str
    date_added: str
    short_description: str
    required_action: str
    due_date: str
    ransomware_use: str  # "Known" or "Unknown" in the catalog
    cwes: tuple[str, ...]


@dataclass(frozen=True)
class KevCatalog:
    version: str
    date_released: str
    entries: dict[str, KevEntry]

    def find(self, cve_id: str) -> KevEntry | None:
        return self.entries.get(cve_id.strip().upper())


def parse_kev_catalog(data: dict) -> KevCatalog:
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise KevFormatError("KEV data has no 'vulnerabilities' list")
    entries: dict[str, KevEntry] = {}
    for raw in data["vulnerabilities"]:
        if not isinstance(raw, dict) or "cveID" not in raw:
            raise KevFormatError("a KEV entry has no 'cveID'")
        cve_id = str(raw["cveID"]).upper()
        entries[cve_id] = KevEntry(
            cve_id=cve_id,
            vendor=str(raw.get("vendorProject", "")),
            product=str(raw.get("product", "")),
            name=str(raw.get("vulnerabilityName", "")),
            date_added=str(raw.get("dateAdded", "")),
            short_description=str(raw.get("shortDescription", "")),
            required_action=str(raw.get("requiredAction", "")),
            due_date=str(raw.get("dueDate", "")),
            ransomware_use=str(raw.get("knownRansomwareCampaignUse", "Unknown")),
            cwes=tuple(str(c) for c in raw.get("cwes") or []),
        )
    return KevCatalog(
        version=str(data.get("catalogVersion", "unknown")),
        date_released=str(data.get("dateReleased", "unknown")),
        entries=entries,
    )


def fetch_kev_catalog(
    *,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    ttl_seconds: float = 86_400,
    downloader: Downloader = download_json,
    urls: tuple[str, ...] = KEV_FEED_URLS,
) -> tuple[KevCatalog, FetchResult]:
    """Fetch the catalog, trying each feed URL in order."""
    errors: list[str] = []
    for url in urls:
        try:
            result = fetch_json_cached(
                url, cache_dir=cache_dir, ttl_seconds=ttl_seconds, downloader=downloader
            )
            return parse_kev_catalog(result.data), result
        except (FetchError, KevFormatError) as exc:
            errors.append(str(exc))
    raise FetchError("KEV catalog unavailable: " + " | ".join(errors))
