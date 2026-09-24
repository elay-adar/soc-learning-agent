"""Tests for src/sources/kev.py, using a trimmed sample of the real CISA catalog."""

import json
from pathlib import Path

import pytest

from src.sources.http_cache import FetchError
from src.sources.kev import KevFormatError, fetch_kev_catalog, parse_kev_catalog

FIXTURES = Path(__file__).parent / "fixtures"


def load() -> dict:
    return json.loads((FIXTURES / "kev_sample.json").read_text(encoding="utf-8"))


def test_catalog_header_and_entries_are_parsed():
    catalog = parse_kev_catalog(load())
    assert catalog.version and catalog.date_released
    assert set(catalog.entries) == {"CVE-2021-44228", "CVE-2021-34527"}


def test_known_entry_is_found_case_insensitively():
    catalog = parse_kev_catalog(load())
    entry = catalog.find(" cve-2021-44228 ")
    assert entry is not None
    assert entry.vendor == "Apache" and entry.product == "Log4j2"
    assert entry.date_added == "2021-12-10"
    assert entry.ransomware_use == "Known"
    assert "CWE-502" in entry.cwes


def test_cve_not_in_catalog_returns_none():
    assert parse_kev_catalog(load()).find("CVE-2099-0001") is None


@pytest.mark.parametrize("bad", [{}, {"vulnerabilities": "x"}, {"vulnerabilities": [{"no_id": 1}]}, []])
def test_malformed_catalog_is_rejected(bad):
    with pytest.raises(KevFormatError):
        parse_kev_catalog(bad)


def test_second_feed_url_is_used_when_the_first_fails(tmp_path):
    tried = []

    def downloader(url):
        tried.append(url)
        if len(tried) == 1:
            raise FetchError("first feed down")
        return load()

    catalog, _ = fetch_kev_catalog(cache_dir=tmp_path, downloader=downloader, urls=("u1", "u2"))
    assert tried == ["u1", "u2"]
    assert catalog.find("CVE-2021-44228") is not None


def test_error_when_every_feed_fails(tmp_path):
    def downloader(url):
        raise FetchError("down")

    with pytest.raises(FetchError):
        fetch_kev_catalog(cache_dir=tmp_path, downloader=downloader, urls=("u1", "u2"))
