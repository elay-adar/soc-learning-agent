"""Tests for src/sources/nvd.py, using synthetic fixtures shaped like NVD 2.0 responses."""

import json
from pathlib import Path

import pytest

from src.sources.nvd import (
    NvdFormatError,
    fetch_nvd_record,
    normalize_cve_id,
    parse_nvd_response,
)

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_fully_analyzed_record_is_parsed():
    record = parse_nvd_response(load("nvd_synthetic_analyzed.json"))
    assert record.cve_id == "CVE-2099-0001"
    assert record.status == "Analyzed"
    assert record.published.startswith("2099-01-02")
    assert record.description.startswith("Example flaw in ExampleCorp Widget")  # English, not Spanish
    assert record.detail_url == "https://nvd.nist.gov/vuln/detail/CVE-2099-0001"


def test_primary_cvss_v31_is_preferred_over_secondary_and_v2():
    cvss = parse_nvd_response(load("nvd_synthetic_analyzed.json")).cvss
    assert (cvss.version, cvss.base_score, cvss.severity) == ("3.1", 10.0, "CRITICAL")
    assert (cvss.kind, cvss.scorer) == ("Primary", "nvd@nist.gov")


def test_v2_only_record_reads_severity_from_the_entry():
    cvss = parse_nvd_response(load("nvd_synthetic_v2only.json")).cvss
    assert (cvss.version, cvss.base_score, cvss.severity) == ("2.0", 7.2, "HIGH")


def test_primary_weakness_comes_first():
    record = parse_nvd_response(load("nvd_synthetic_analyzed.json"))
    assert record.weaknesses == ("CWE-917", "CWE-20")


def test_affected_products_come_only_from_vulnerable_cpe_entries():
    record = parse_nvd_response(load("nvd_synthetic_analyzed.json"))
    assert record.affected_products == ("examplecorp widget", "examplecorp widget server")
    assert record.affected_product_total == 2  # the non-vulnerable CPE is not counted


def test_all_affected_products_are_kept_with_no_cap():
    data = load("nvd_synthetic_analyzed.json")
    matches = [
        {"vulnerable": True, "criteria": f"cpe:2.3:a:examplecorp:prod{n}:*:*:*:*:*:*:*:*"}
        for n in range(20)
    ]
    data["vulnerabilities"][0]["cve"]["configurations"] = [{"nodes": [{"cpeMatch": matches}]}]
    record = parse_nvd_response(data)
    assert len(record.affected_products) == record.affected_product_total == 20


def test_patch_references_are_deduplicated_and_filtered_by_tag():
    record = parse_nvd_response(load("nvd_synthetic_analyzed.json"))
    assert record.patch_references == ("https://example.com/advisory/2099-0001",)


def test_record_awaiting_analysis_has_empty_fields_not_guesses():
    record = parse_nvd_response(load("nvd_synthetic_awaiting.json"))
    assert record.status == "Awaiting Analysis"
    assert record.cvss is None
    assert record.weaknesses == ()
    assert record.affected_products == ()
    assert record.patch_references == ()


def test_rejected_status_is_reported_as_is():
    assert parse_nvd_response(load("nvd_synthetic_rejected.json")).status == "Rejected"


def test_empty_result_means_unknown_cve():
    assert parse_nvd_response(load("nvd_synthetic_empty.json")) is None


@pytest.mark.parametrize(
    "bad",
    [
        {},
        {"vulnerabilities": "nope"},
        {"vulnerabilities": [{"not_cve": {}}]},
        {"vulnerabilities": [{"cve": {"no_id": True}}]},
        [],
    ],
)
def test_malformed_response_is_rejected(bad):
    with pytest.raises(NvdFormatError):
        parse_nvd_response(bad)


def test_cve_id_is_normalized_and_validated():
    assert normalize_cve_id("  cve-2021-44228 ") == "CVE-2021-44228"
    for bad in ["2021-44228", "CVE-21-44228", "CVE-2021-1", "CVE-2021-44228; DROP TABLE", ""]:
        with pytest.raises(ValueError):
            normalize_cve_id(bad)


def test_fetch_uses_the_cve_id_as_a_query_parameter_and_the_cache(tmp_path):
    seen = []

    def downloader(url):
        seen.append(url)
        return load("nvd_synthetic_analyzed.json")

    record, first = fetch_nvd_record("cve-2099-0001", cache_dir=tmp_path, downloader=downloader)
    _, second = fetch_nvd_record("CVE-2099-0001", cache_dir=tmp_path, downloader=downloader)
    assert record.cve_id == "CVE-2099-0001"
    assert seen == ["https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-0001"]
    assert first.from_cache is False and second.from_cache is True
