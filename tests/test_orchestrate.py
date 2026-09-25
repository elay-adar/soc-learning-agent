"""Tests for src/orchestrate.py. A fake client stands in for the SDK: no model, no network."""

import asyncio
import json

import pytest

from src.orchestrate import run_stages
from src.settings import SingleCallSettings
from src.single_call import SingleCallFailedError
from src.stages_config import DEFAULT_STAGES_PATH, load_stages_config
from tests.fakes import FakeClient, reply
from tests.test_lecturer import DOCUMENTED_STAGE1, FLOW, stage_json
from tests.test_planner import THREE, plan_json
from tests.test_stage_rules import doc, make_pack

CONFIG = load_stages_config(DEFAULT_STAGES_PATH)
SETTINGS = SingleCallSettings(model="claude-sonnet-5", effort="medium", max_schema_retries=1)

STAGE2 = stage_json(2, "why_possible", [doc("Input is evaluated by the logger")], "architecture")


def run(scripts, pack=None, environ=None):
    client = FakeClient(scripts)
    outcome = asyncio.run(
        run_stages(
            pack or make_pack(), SETTINGS, SETTINGS, CONFIG,
            client_factory=client.factory(), environ=environ or {},
        )
    )
    return outcome, client


def test_plans_then_writes_stages_1_and_2_in_order():
    outcome, client = run([reply(plan_json(*THREE)), reply(stage_json()), reply(STAGE2)])
    saved = outcome.file
    assert saved.topic == "CVE-0000-0000"
    assert [s.key for s in saved.plan.stages] == list(THREE)
    assert [s.stage_number for s in saved.stages] == [1, 2]
    assert len(client.prompts) == 3
    assert "Servers were taken over" in client.prompts[2]  # stage 2 read stage 1
    assert outcome.not_built == ["response_prevention"]


def test_metrics_are_kept_per_call():
    outcome, _ = run([reply(plan_json(*THREE)), reply(stage_json()), reply(STAGE2)])
    assert outcome.planner_metrics.attempts == 1
    assert [m.attempts for m in outcome.stage_metrics] == [1, 1]


def test_a_stage_that_never_passes_stops_the_run():
    with pytest.raises(SingleCallFailedError):
        run([reply(plan_json(*THREE)), reply("bad"), reply("bad")])


def test_a_plan_that_never_passes_stops_before_any_stage_is_written():
    client = FakeClient([reply("bad"), reply("bad")])
    with pytest.raises(SingleCallFailedError):
        asyncio.run(
            run_stages(make_pack(), SETTINGS, SETTINGS, CONFIG, client_factory=client.factory(), environ={})
        )
    assert len(client.prompts) == 2


def test_api_key_stops_everything():
    from src.researcher import ApiKeyPresentError

    with pytest.raises(ApiKeyPresentError):
        run([], environ={"ANTHROPIC_API_KEY": "x"})
