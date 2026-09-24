"""Tests for src/sources/attack.py, using real ATT&CK technique objects (trimmed)."""

import json
from pathlib import Path

import pytest

from src.sources.attack import (
    AttackFormatError,
    build_index_data,
    clean_description,
    fetch_attack_index,
    index_from_data,
)

FIXTURES = Path(__file__).parent / "fixtures"


def bundle() -> dict:
    return json.loads((FIXTURES / "attack_bundle_sample.json").read_text(encoding="utf-8"))


def index():
    return index_from_data(build_index_data(bundle()))


def test_version_is_read_from_the_collection_object():
    assert index().version == "19.2"


def test_only_active_techniques_are_indexed():
    ids = set(index().techniques)
    assert ids == {"T1558.003", "T1558", "T1055.011"}  # revoked T1066, deprecated T1153 and malware are out


def test_subtechnique_fields():
    technique = index().find("T1558.003")
    assert technique.name == "Kerberoasting"
    assert technique.tactics == ("credential-access",)
    assert technique.is_subtechnique is True
    assert technique.url == "https://attack.mitre.org/techniques/T1558/003"


def test_parent_technique_is_not_marked_as_subtechnique():
    assert index().find("T1558").is_subtechnique is False


def test_technique_in_several_tactics_keeps_all_of_them():
    assert len(index().find("T1055.011").tactics) >= 2


def test_lookup_ignores_case_and_spaces_and_unknown_ids_return_none():
    idx = index()
    assert idx.find(" t1558.003 ").technique_id == "T1558.003"
    assert idx.find("T9999") is None


def test_description_has_no_citation_markers_or_markdown_links():
    text = index().find("T1558.003").description
    assert "(Citation:" not in text
    assert "](" not in text
    assert "Brute Force" in text  # the link text is kept


def test_clean_description_examples():
    assert clean_description("See [Brute Force](https://x.test/T1110).(Citation: A B 2016) Done.") == (
        "See Brute Force. Done."
    )
    assert clean_description("Use <code>net user</code>.") == "Use net user."


def test_index_survives_a_json_round_trip():
    data = build_index_data(bundle())
    again = index_from_data(json.loads(json.dumps(data)))
    assert again.find("T1558.003") == index().find("T1558.003")


@pytest.mark.parametrize("bad", [{}, {"objects": "x"}, []])
def test_malformed_bundle_is_rejected(bad):
    with pytest.raises(AttackFormatError):
        build_index_data(bad)


def test_malformed_cached_index_is_rejected():
    with pytest.raises(AttackFormatError):
        index_from_data({"version": "1", "techniques": {"T1": {"name": "x"}}})


def test_fetch_caches_the_reduced_index(tmp_path):
    calls = []

    def downloader(url):
        calls.append(url)
        return build_index_data(bundle())

    first_index, first = fetch_attack_index(cache_dir=tmp_path, downloader=downloader)
    _, second = fetch_attack_index(cache_dir=tmp_path, downloader=downloader)
    assert len(calls) == 1
    assert first.from_cache is False and second.from_cache is True
    assert first_index.find("T1558.003") is not None
