"""Tests for src/single_call.py. A fake client stands in for the SDK."""

import asyncio

import pytest
from claude_agent_sdk import ToolUseBlock

from src.researcher import AgentRunError, ApiKeyPresentError, TurnLimitError
from src.settings import SingleCallSettings
from src.single_call import (
    OutputError,
    SingleCallFailedError,
    UnsafeOptionsError,
    assert_single_call_options,
    build_single_call_options,
    run_single_call,
)
from tests.fakes import FakeClient, assistant, reply, result

SETTINGS = SingleCallSettings(model="claude-sonnet-5", effort="medium", max_schema_retries=2)


def parse(raw):
    if raw != '{"ok": true}':
        raise OutputError("not ok")
    return "parsed"


def run(scripts, settings=SETTINGS, environ=None):
    client = FakeClient(scripts)
    outcome = asyncio.run(
        run_single_call(
            settings, "system", "first prompt", parse,
            client_factory=client.factory(), environ=environ or {},
        )
    )
    return outcome, client


# ---- options ---------------------------------------------------------------


def test_options_have_no_tools_and_one_turn():
    options = build_single_call_options(SETTINGS, "system")
    assert options.tools == [] and options.allowed_tools == []
    assert not options.mcp_servers
    assert options.setting_sources == [] and options.skills == []
    assert options.max_turns == 1
    assert options.permission_mode == "dontAsk"
    assert (options.model, options.effort) == ("claude-sonnet-5", "medium")


@pytest.mark.parametrize(
    "change",
    [
        {"tools": ["Bash"]},
        {"allowed_tools": ["Read"]},
        {"mcp_servers": {"x": {}}},
        {"setting_sources": ["user"]},
        {"permission_mode": "acceptEdits"},
        {"max_turns": 5},
    ],
)
def test_tampered_options_are_rejected(change):
    options = build_single_call_options(SETTINGS, "system")
    for name, value in change.items():
        setattr(options, name, value)
    with pytest.raises(UnsafeOptionsError):
        assert_single_call_options(options)


# ---- the run ---------------------------------------------------------------


def test_valid_first_answer():
    (value, metrics), client = run([reply('{"ok": true}')])
    assert value == "parsed"
    assert metrics.attempts == 1 and metrics.turns == 1 and metrics.tool_calls == 0
    assert client.prompts == ["first prompt"]


def test_json_in_a_code_fence_is_extracted():
    (value, _), _ = run([reply('Here it is:\n```json\n{"ok": true}\n```')])
    assert value == "parsed"


def test_rejected_output_is_sent_back_with_the_reason_then_accepted():
    (value, metrics), client = run([reply("{}"), reply('{"ok": true}')])
    assert value == "parsed" and metrics.attempts == 2
    assert "not ok" in client.prompts[1]
    assert "nothing was saved" in client.prompts[1]


def test_gives_up_after_the_retry_cap():
    scripts = [reply("{}")] * 3  # 1 attempt + 2 corrections
    with pytest.raises(SingleCallFailedError) as info:
        run(scripts)
    assert len(info.value.errors) == 3


def test_zero_retries_means_one_attempt():
    settings = SingleCallSettings(model="m", effort="low", max_schema_retries=0)
    with pytest.raises(SingleCallFailedError):
        run([reply("{}")], settings=settings)


def test_tool_use_in_the_reply_is_an_error():
    script = [assistant(ToolUseBlock(id="t", name="Bash", input={})), result(None)]
    with pytest.raises(AgentRunError, match="tool"):
        run([script])


def test_sdk_error_is_reported():
    script = [assistant(), result(None, is_error=True, subtype="error_during_execution", errors=["boom"])]
    with pytest.raises(AgentRunError, match="boom"):
        run([script])


def test_max_turns_stop_is_reported():
    script = [assistant(), result(None, is_error=True, subtype="error_max_turns")]
    with pytest.raises(TurnLimitError):
        run([script])


def test_api_key_stops_the_run_before_any_call():
    client = FakeClient([])
    with pytest.raises(ApiKeyPresentError):
        asyncio.run(
            run_single_call(
                SETTINGS, "s", "p", parse,
                client_factory=client.factory(), environ={"ANTHROPIC_API_KEY": "x"},
            )
        )
    assert client.prompts == []


def test_usage_is_recorded():
    (_, metrics), _ = run([reply('{"ok": true}')])
    assert metrics.usage == [{"output_tokens": 5}] and metrics.duration_ms == 10
