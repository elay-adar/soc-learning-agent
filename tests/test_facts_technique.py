"""Tests for the technique-only facts (D-033). ATT&CK fixture only: no model, no network."""

import json
from pathlib import Path

import pytest

from src.facts import TechniqueNotFoundError, collect_technique_facts
from src.schemas import ExploitationStatus, FieldStatus, ProvenanceTag, TopicType
from src.sources.attack import build_index_data, normalize_technique_id
from src.sources.http_cache import FetchError

FIXTURES = Path(__file__).parent / "fixtures"
URL = "https://attack.mitre.org/techniques/T1558/003"


def downloader(url):
    return build_index_data(json.loads((FIXTURES / "attack_bundle_sample.json").read_text(encoding="utf-8")))


def facts(technique_id="T1558.003", tmp_path=None):
    return collect_technique_facts(technique_id, cache_dir=tmp_path, downloader=downloader)


def test_technique_pack_is_a_valid_technique_topic(tmp_path):
    pack = facts(tmp_path=tmp_path).pack
    assert pack.topic == "T1558.003" and pack.topic_type == TopicType.TECHNIQUE
    assert pack.exploitation_status == ExploitationStatus.NOT_APPLICABLE
    assert pack.exploitation_evidence is None and pack.incidents == []


def test_technique_name_and_tactic_are_documented_with_the_attack_url(tmp_path):
    field = facts(tmp_path=tmp_path).pack.triage_fields["attack_technique"]
    assert field.status == FieldStatus.VALUE
    assert field.item.tag == ProvenanceTag.DOCUMENTED and field.item.source_url == URL
    assert "T1558.003" in field.item.value and "credential-access" in field.item.value


@pytest.mark.parametrize(
    "name",
    ["exploited_in_the_wild", "severity_cvss", "weakness_type", "affected_products",
     "fix_status", "published", "nvd_analysis_status"],
)
def test_nvd_kev_and_cwe_fields_are_not_applicable_not_skipped(tmp_path, name):
    field = facts(tmp_path=tmp_path).pack.triage_fields[name]
    assert field.status == FieldStatus.NOT_APPLICABLE and field.item is None


def test_attack_description_is_recorded_as_documented(tmp_path):
    pack = facts(tmp_path=tmp_path).pack
    assert len(pack.weakness_mechanism) == 1
    item = pack.weakness_mechanism[0]
    assert item.value.startswith("ATT&CK description:") and item.tag == ProvenanceTag.DOCUMENTED
    assert item.source_url == URL


def test_agent_owned_lists_start_empty(tmp_path):
    pack = facts(tmp_path=tmp_path).pack
    assert pack.attack_steps == [] and pack.detection_items == [] and pack.response_items == []


def test_technique_id_is_normalized_and_bad_ids_are_rejected(tmp_path):
    assert facts(" t1558.003 ", tmp_path).pack.topic == "T1558.003"
    assert normalize_technique_id("t1558") == "T1558"
    for bad in ("Kerberoasting", "T15", "CVE-2021-44228", "T1558.3"):
        with pytest.raises(ValueError):
            collect_technique_facts(bad, cache_dir=tmp_path, downloader=downloader)


def test_unknown_technique_id_is_an_error_not_a_guess(tmp_path):
    with pytest.raises(TechniqueNotFoundError):
        facts("T9999", tmp_path)


def test_unreachable_attack_data_is_a_fetch_error(tmp_path):
    def failing(url):
        raise FetchError("network down")

    with pytest.raises(FetchError):
        collect_technique_facts("T1558.003", cache_dir=tmp_path, downloader=failing)
