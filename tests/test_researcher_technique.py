"""The Researcher run for a technique-only topic (D-033). Fake client and fake downloaders:
no model call, no network. The NVD and KEV downloaders raise if they are ever called."""

import asyncio
import json
from pathlib import Path

import pytest
from claude_agent_sdk import TextBlock, ToolResultBlock, ToolUseBlock, UserMessage

from src.facts import TechniqueNotFoundError
from src.researcher import (
    ApiKeyPresentError,
    ResearcherFailedError,
    SourceUrlError,
    build_system_prompt,
    run_researcher,
)
from src.researcher_tools import TECHNIQUE_ALLOWED_TOOL_NAMES, wrap_untrusted
from src.schemas import ExploitationStatus, FieldStatus, ProvenanceTag, TopicType
from src.settings import ResearcherSettings
from src.sources.attack import build_index_data
from tests.fakes import FakeClient, assistant, result

FIXTURES = Path(__file__).parent / "fixtures"
SETTINGS = ResearcherSettings(model="sonnet-5", effort="medium", max_turns=20, max_schema_retries=2)
PAGE = "https://www.crowdstrike.com/en-us/cybersecurity-101/kerberoasting/"
PAGE2 = "https://www.picussecurity.com/resource/blog/kerberoasting"
ATTACK = "https://attack.mitre.org/techniques/T1558/003"
TECH = "T1558.003"


def attack_downloader(url):
    return build_index_data(json.loads((FIXTURES / "attack_bundle_sample.json").read_text(encoding="utf-8")))


def must_not_be_called(url):
    raise AssertionError(f"a technique run must never fetch {url}")


def tool_result(url):
    return UserMessage(content=[ToolResultBlock(tool_use_id="t1", content=wrap_untrusted(url, "page text"))])


def secondary(text, url=PAGE, tag="secondary"):
    return {"value": text, "tag": tag, "source_url": url}


def steps_answer(url=PAGE, tag="secondary"):
    return json.dumps({
        "weakness_mechanism": [secondary("Service tickets are encrypted with the account's password hash", url)],
        "attack_steps": [
            {"number": 1, "action": secondary("The attacker lists service accounts", url, tag), "mitre_technique": TECH},
            {"number": 2, "action": secondary("The attacker requests a service ticket", url, tag), "mitre_technique": TECH},
        ],
    })


def reading(url=PAGE, text=None):
    return [
        assistant(ToolUseBlock(id="t1", name="get_secondary_source", input={"url": url})),
        tool_result(url),
        assistant(TextBlock(text="done")),
        result(text if text is not None else steps_answer(url)),
    ]


def run(scripts, tmp_path, source_urls=(PAGE,), topic=TECH, environ=None, factory=None):
    client = FakeClient(scripts)
    outcome = asyncio.run(
        run_researcher(
            topic,
            SETTINGS,
            client_factory=factory or client.factory(),
            cache_dir=tmp_path,
            nvd_downloader=must_not_be_called,
            kev_downloader=must_not_be_called,
            attack_downloader=attack_downloader,
            source_urls=source_urls,
            environ=environ or {},
        )
    )
    return outcome, client


def test_happy_path_builds_a_technique_pack_with_secondary_steps(tmp_path):
    outcome, client = run([reading()], tmp_path)
    pack = outcome.pack
    assert pack.topic == TECH and pack.topic_type == TopicType.TECHNIQUE
    assert pack.exploitation_status == ExploitationStatus.NOT_APPLICABLE
    assert [s.action.tag for s in pack.attack_steps] == [ProvenanceTag.SECONDARY] * 2
    assert pack.triage_fields["weakness_type"].status == FieldStatus.NOT_APPLICABLE
    assert PAGE.rstrip("/") in outcome.tool_urls and outcome.metrics.attempts == 1
    # code's ATT&CK description stays first, the agent's secondary claim is appended
    assert pack.weakness_mechanism[0].tag == ProvenanceTag.DOCUMENTED
    assert pack.weakness_mechanism[-1].tag == ProvenanceTag.SECONDARY


def test_only_the_attack_and_secondary_tools_are_allowed_and_prompts_name_the_pages(tmp_path):
    _, client = run([reading()], tmp_path, source_urls=(PAGE, PAGE2))
    assert client.options.allowed_tools == list(TECHNIQUE_ALLOWED_TOOL_NAMES)
    assert client.options.tools == [] and client.options.permission_mode == "dontAsk"
    assert TECH in client.prompts[0] and PAGE in client.prompts[0] and PAGE2 in client.prompts[0]
    assert "get_nvd_record" not in client.options.system_prompt
    assert "get_kev_entry" not in client.options.system_prompt


def test_technique_system_prompt_states_the_technique_rules():
    prompt = build_system_prompt(TopicType.TECHNIQUE)
    for phrase in ("no CVE", "get_secondary_source", '"secondary"', "never output incidents", "untrusted_source_data"):
        assert phrase in prompt
    assert "get_nvd_record" not in prompt


def test_a_step_citing_a_page_no_tool_returned_is_rejected_then_corrected(tmp_path):
    scripts = [reading(text=steps_answer(PAGE2)), reading()[2:]]
    outcome, client = run(scripts, tmp_path)
    assert outcome.metrics.attempts == 2 and "was not returned by any tool" in client.prompts[1]


def test_a_secondary_page_cannot_be_tagged_documented(tmp_path):
    scripts = [reading(text=steps_answer(tag="documented")), reading()[2:]]
    outcome, client = run(scripts, tmp_path)
    assert "not an official source" in client.prompts[1] and "tag 'secondary'" in client.prompts[1]
    assert outcome.pack.attack_steps[0].action.tag == ProvenanceTag.SECONDARY


def test_empty_attack_steps_are_rejected_then_corrected(tmp_path):
    scripts = [reading(text="{}"), reading()[2:]]
    outcome, client = run(scripts, tmp_path)
    assert outcome.metrics.attempts == 2
    assert "attack_steps is empty" in client.prompts[1]


def test_gives_up_when_the_steps_stay_empty(tmp_path):
    with pytest.raises(ResearcherFailedError) as info:
        run([reading(text="{}"), [result("{}")], [result("{}")]], tmp_path)
    assert len(info.value.errors) == 3 and "attack_steps is empty" in info.value.errors[-1]


def no_model(options):
    raise AssertionError("the model must not be started")


def test_a_technique_run_needs_at_least_one_source_page_and_never_starts_the_model(tmp_path):
    with pytest.raises(SourceUrlError, match="at least one"):
        run([], tmp_path, source_urls=(), factory=no_model)


@pytest.mark.parametrize(
    "url", ["https://abnormal.ai/blog/kerberoasting", "http://www.crowdstrike.com/x", "https://crowdstrike.com.evil.example/x"]
)
def test_source_pages_must_be_on_the_allowlist(tmp_path, url):
    with pytest.raises(SourceUrlError, match="allowlist"):
        run([], tmp_path, source_urls=(url,), factory=no_model)


def test_unknown_technique_stops_before_the_model(tmp_path):
    with pytest.raises(TechniqueNotFoundError):
        run([], tmp_path, topic="T9999", factory=no_model)


def test_api_key_still_stops_a_technique_run(tmp_path):
    with pytest.raises(ApiKeyPresentError):
        run([], tmp_path, environ={"ANTHROPIC_API_KEY": "x"}, factory=no_model)


def test_source_urls_are_ignored_for_a_cve_run_only_by_being_rejected(tmp_path):
    # A CVE run takes no secondary pages: giving some is a mistake, not something to drop silently.
    with pytest.raises(SourceUrlError, match="only for a technique"):
        asyncio.run(
            run_researcher("CVE-2099-0001", SETTINGS, client_factory=no_model, cache_dir=tmp_path,
                           source_urls=(PAGE,), environ={})
        )
