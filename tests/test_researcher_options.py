"""Tests that the Researcher agent is locked down to the three read-only tools."""

import asyncio
import dataclasses
import json

import pytest

from src.researcher import (
    ResearcherFailedError,
    UnsafeOptionsError,
    assert_read_only,
    build_researcher_options,
    validate_with_retries,
)
from src.researcher_tools import ALLOWED_TOOL_NAMES
from src.settings import ResearcherSettings
from tests.test_merge import base_pack, step

SETTINGS = ResearcherSettings(model="sonnet-5", effort="medium", max_turns=20, max_schema_retries=2)


def options():
    return build_researcher_options(SETTINGS, "system prompt")


def test_settings_are_passed_through():
    o = options()
    assert (o.model, o.effort, o.max_turns) == ("sonnet-5", "medium", 20)
    assert o.system_prompt == "system prompt"


def test_only_the_three_tools_and_no_built_ins():
    o = options()
    assert o.tools == []
    assert o.allowed_tools == list(ALLOWED_TOOL_NAMES)
    assert list(o.mcp_servers) == ["researcher"] and o.strict_mcp_config
    assert o.disallowed_tools == []  # nothing to subtract: the built-ins are never loaded


def test_nothing_is_loaded_from_settings_skills_plugins_or_subagents():
    o = options()
    assert o.setting_sources == [] and o.skills == [] and o.plugins == [] and not o.agents


def test_unapproved_tool_use_is_denied_not_prompted():
    assert options().permission_mode == "dontAsk"


@pytest.mark.parametrize(
    "change",
    [
        {"tools": None},
        {"tools": ["Bash"]},
        {"allowed_tools": ["Bash", *ALLOWED_TOOL_NAMES]},
        {"allowed_tools": []},
        {"mcp_servers": {}},
        {"strict_mcp_config": False},
        {"setting_sources": None},
        {"skills": "all"},
        {"agents": {"x": object()}},
        {"permission_mode": "bypassPermissions"},
        {"max_turns": None},
    ],
)
def test_any_loosening_is_rejected(change):
    with pytest.raises(UnsafeOptionsError):
        assert_read_only(dataclasses.replace(options(), **change))


def test_the_real_options_pass_the_check():
    assert_read_only(options())


# ---- validate-and-correct loop ----

GOOD = json.dumps({"attack_steps": [step(1)]})
BAD = json.dumps({"exploitation_status": "documented"})  # code-owned field: rejected


def scripted(outputs):
    """A fake agent that returns the given outputs in order and records the feedback it got."""
    calls = []

    async def ask(feedback):
        calls.append(feedback)
        return outputs[len(calls) - 1]

    return ask, calls


def test_valid_first_output_needs_one_attempt():
    ask, calls = scripted([GOOD])
    outcome = asyncio.run(validate_with_retries(base_pack(False), ask, 2))
    assert outcome.attempts == 1 and outcome.corrections == [] and calls == [None]
    assert len(outcome.pack.attack_steps) == 1


def test_invalid_then_valid_sends_the_reason_back_once():
    ask, calls = scripted([BAD, GOOD])
    outcome = asyncio.run(validate_with_retries(base_pack(False), ask, 2))
    assert outcome.attempts == 2 and len(outcome.corrections) == 1
    assert calls[0] is None and "exploitation_status" in calls[1]


def test_a_third_attempt_is_allowed_with_two_retries():
    ask, calls = scripted([BAD, "not json", GOOD])
    assert asyncio.run(validate_with_retries(base_pack(False), ask, 2)).attempts == 3


def test_gives_up_after_the_cap_and_never_asks_a_fourth_time():
    ask, calls = scripted([BAD, BAD, BAD, GOOD])
    with pytest.raises(ResearcherFailedError) as info:
        asyncio.run(validate_with_retries(base_pack(False), ask, 2))
    assert len(calls) == 3 and len(info.value.errors) == 3


def test_zero_retries_means_a_single_attempt():
    ask, calls = scripted([BAD, GOOD])
    with pytest.raises(ResearcherFailedError):
        asyncio.run(validate_with_retries(base_pack(False), ask, 0))
    assert len(calls) == 1
