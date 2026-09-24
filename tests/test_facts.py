"""Tests for src/facts.py: from NVD and KEV data to a partial Knowledge Pack."""

import json
from pathlib import Path

import pytest

from src.facts import (
    CveNotFoundError,
    CveRejectedError,
    assemble_pack,
    collect_facts,
)
from src.schemas import ExploitationStatus, FieldStatus, KnowledgePack, ProvenanceTag
from src.sources.http_cache import FetchError
from src.sources.kev import KEV_CATALOG_PAGE, parse_kev_catalog
from src.sources.nvd import parse_nvd_response

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def nvd(name: str = "nvd_synthetic_analyzed.json"):
    return parse_nvd_response(load(name))


def kev_catalog():
    return parse_kev_catalog(load("kev_sample.json"))


def real_kev_record_like(cve_id: str):
    """An NVD record for a CVE that is really in the KEV sample, built from the analyzed fixture."""
    data = load("nvd_synthetic_analyzed.json")
    data["vulnerabilities"][0]["cve"]["id"] = cve_id
    return parse_nvd_response(data)


# ---- exploitation status -----------------------------------------------------


def test_cve_listed_in_kev_gives_documented_status_with_evidence():
    pack = assemble_pack(real_kev_record_like("CVE-2021-44228"), kev_catalog())
    assert pack.exploitation_status == ExploitationStatus.DOCUMENTED
    assert pack.exploitation_evidence.tag == ProvenanceTag.DOCUMENTED
    assert pack.exploitation_evidence.source_url == KEV_CATALOG_PAGE
    field = pack.triage_fields["exploited_in_the_wild"]
    assert field.status == FieldStatus.VALUE and "added 2021-12-10" in field.item.value


def test_cve_checked_and_not_listed_gives_not_documented_with_wording_about_the_catalog_only():
    pack = assemble_pack(nvd(), kev_catalog())
    assert pack.exploitation_status == ExploitationStatus.NOT_DOCUMENTED
    assert pack.exploitation_evidence is None
    value = pack.triage_fields["exploited_in_the_wild"].item.value
    assert value.startswith("Not listed in the CISA KEV catalog")  # not "not exploited"


def test_catalog_that_could_not_be_checked_gives_unknown_not_not_documented():
    pack = assemble_pack(nvd(), None)
    assert pack.exploitation_status == ExploitationStatus.UNKNOWN
    assert pack.triage_fields["exploited_in_the_wild"].status == FieldStatus.UNKNOWN


# ---- triage fields ---------------------------------------------------------------


def test_triage_fields_carry_values_and_sources():
    fields = assemble_pack(nvd(), kev_catalog()).triage_fields
    assert "CVSS 3.1 base score 10.0 (CRITICAL)" in fields["severity_cvss"].item.value
    assert fields["weakness_type"].item.value == "CWE-917, CWE-20"
    assert fields["affected_products"].item.value == "examplecorp widget, examplecorp widget server"
    assert fields["published"].item.value == "2099-01-02"
    assert "1 patch or vendor advisory" in fields["fix_status"].item.value
    for name, field in fields.items():
        if field.status == FieldStatus.VALUE:
            assert field.item.tag == ProvenanceTag.DOCUMENTED, name
            assert field.item.source_url.startswith("https://"), name


def record_with_products(cve_id: str, products: list[str]):
    """An NVD record whose vulnerable CPE entries are the given (vendor, product) pairs, in order."""
    data = load("nvd_synthetic_analyzed.json")
    cve = data["vulnerabilities"][0]["cve"]
    cve["id"] = cve_id
    matches = [
        {"vulnerable": True, "criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"}
        for vendor, product in products
    ]
    cve["configurations"] = [{"nodes": [{"cpeMatch": matches}]}]
    return parse_nvd_response(data)


# 20 products; the one KEV names for CVE-2021-44228 is 19th in NVD order and would sort after
# the "aaavendor" ones, so only the KEV rule can put it first.
MANY_PRODUCTS = (
    [("aaavendor", f"prod{n:02d}") for n in range(1, 19)]
    + [("apache", "log4j"), ("apache", "zebra")]
)
FILLER = [f"aaavendor prod{n:02d}" for n in range(1, 19)]


def test_product_named_by_kev_goes_first_rest_alphabetical_and_count_kept():
    record = record_with_products("CVE-2021-44228", MANY_PRODUCTS)
    value = assemble_pack(record, kev_catalog()).triage_fields["affected_products"].item.value
    expected = ["apache log4j"] + FILLER[:14]  # 15 shown: KEV product, then the rest sorted
    assert value == ", ".join(expected) + " (and 5 more)"


def test_products_are_alphabetical_when_the_cve_is_not_in_kev_or_kev_was_not_checked():
    record = record_with_products("CVE-2099-0001", MANY_PRODUCTS)
    expected = ", ".join(FILLER[:15]) + " (and 5 more)"
    for kev in (kev_catalog(), None):
        value = assemble_pack(record, kev).triage_fields["affected_products"].item.value
        assert value == expected


def test_nothing_is_pinned_when_no_product_matches_the_kev_entry():
    record = record_with_products("CVE-2021-34527", MANY_PRODUCTS)  # KEV says Microsoft Windows
    value = assemble_pack(record, kev_catalog()).triage_fields["affected_products"].item.value
    assert value == ", ".join(FILLER[:15]) + " (and 5 more)"


def test_missing_data_becomes_unknown_never_a_guess():
    fields = assemble_pack(nvd("nvd_synthetic_awaiting.json"), kev_catalog()).triage_fields
    for name in ("severity_cvss", "weakness_type", "affected_products", "fix_status"):
        assert fields[name].status == FieldStatus.UNKNOWN, name
    assert fields["nvd_analysis_status"].item.value == "Awaiting Analysis"


def test_official_descriptions_are_stored_with_their_sources():
    pack = assemble_pack(real_kev_record_like("CVE-2021-44228"), kev_catalog())
    values = [item.value for item in pack.weakness_mechanism]
    assert values[0].startswith("NVD description:")
    assert values[1].startswith("CISA KEV description:")
    assert all(item.tag == ProvenanceTag.DOCUMENTED and item.source_url for item in pack.weakness_mechanism)


def test_rejected_cve_is_refused():
    with pytest.raises(CveRejectedError):
        assemble_pack(nvd("nvd_synthetic_rejected.json"), kev_catalog())


def test_pack_is_a_valid_knowledge_pack_and_survives_json():
    pack = assemble_pack(nvd(), kev_catalog())
    assert KnowledgePack.model_validate_json(pack.model_dump_json()) == pack
    assert pack.attack_steps == [] and pack.detection_items == []  # model-driven parts come later


# ---- collect_facts end to end, offline ---------------------------------------------


def downloaders(*, nvd_data=None, kev_fails=False, nvd_fails=False):
    def nvd_dl(url):
        if nvd_fails:
            raise FetchError("nvd down")
        return nvd_data if nvd_data is not None else load("nvd_synthetic_analyzed.json")

    def kev_dl(url):
        if kev_fails:
            raise FetchError("kev down")
        return load("kev_sample.json")

    return nvd_dl, kev_dl


def test_collect_facts_happy_path(tmp_path):
    nvd_dl, kev_dl = downloaders()
    result = collect_facts("CVE-2099-0001", cache_dir=tmp_path, nvd_downloader=nvd_dl, kev_downloader=kev_dl)
    assert result.pack.topic == "CVE-2099-0001"
    assert result.pack.exploitation_status == ExploitationStatus.NOT_DOCUMENTED
    assert result.notes == []


def test_collect_facts_survives_kev_outage_and_says_so(tmp_path):
    nvd_dl, kev_dl = downloaders(kev_fails=True)
    result = collect_facts("CVE-2099-0001", cache_dir=tmp_path, nvd_downloader=nvd_dl, kev_downloader=kev_dl)
    assert result.pack.exploitation_status == ExploitationStatus.UNKNOWN
    assert any("KEV catalog unavailable" in note for note in result.notes)


def test_collect_facts_fails_when_nvd_is_down_and_nothing_is_cached(tmp_path):
    nvd_dl, kev_dl = downloaders(nvd_fails=True)
    with pytest.raises(FetchError):
        collect_facts("CVE-2099-0001", cache_dir=tmp_path, nvd_downloader=nvd_dl, kev_downloader=kev_dl)


def test_collect_facts_unknown_cve(tmp_path):
    nvd_dl, kev_dl = downloaders(nvd_data=load("nvd_synthetic_empty.json"))
    with pytest.raises(CveNotFoundError):
        collect_facts("CVE-2099-0001", cache_dir=tmp_path, nvd_downloader=nvd_dl, kev_downloader=kev_dl)


def test_collect_facts_rejects_a_malformed_id_before_any_network_call(tmp_path):
    def boom(url):
        raise AssertionError("network must not be touched")

    with pytest.raises(ValueError):
        collect_facts("not-a-cve", cache_dir=tmp_path, nvd_downloader=boom, kev_downloader=boom)


def test_collect_facts_notes_missing_scores(tmp_path):
    nvd_dl, kev_dl = downloaders(nvd_data=load("nvd_synthetic_awaiting.json"))
    result = collect_facts("CVE-2099-0002", cache_dir=tmp_path, nvd_downloader=nvd_dl, kev_downloader=kev_dl)
    assert any("no CVSS score" in note for note in result.notes)
    assert any("no weakness type" in note for note in result.notes)
