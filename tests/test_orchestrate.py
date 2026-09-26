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


def test_a_plan_with_an_attack_chain_writes_stage_3_from_stage_2():
    import json

    from tests.test_frames import chain_pack
    from tests.test_lecturer import chain_json

    pack = chain_pack()
    outcome, client = run(
        [reply(plan_json("overview", "why_possible", "attack_chain", "response_prevention", covers=(1, 2, 3))),
         reply(stage_json()), reply(STAGE2), reply(chain_json(pack))],
        pack=pack,
    )
    saved = outcome.file
    assert [s.stage_number for s in saved.stages] == [1, 2, 3]
    assert len(saved.stages[2].frames) == len(pack.attack_steps)
    assert "Input is evaluated by the logger" in client.prompts[3]
    assert outcome.not_built == ["response_prevention"]
    json.loads(saved.model_dump_json())  # the whole file serialises


# ---- writing one stage again from a saved run -----------------------------------------------


def saved_three_stages():
    from src.stage_content import StagesFile
    from tests.test_frames import chain_pack, stage3
    from tests.test_lecturer import ATTACK_PLAN, STAGE1, STAGE2 as STAGE2_CONTENT

    pack = chain_pack()
    return pack, StagesFile(topic=pack.topic, plan=ATTACK_PLAN, stages=[STAGE1, STAGE2_CONTENT, stage3(pack)])


def rerun(number, saved, pack, scripts):
    from src.orchestrate import rerun_stage

    client = FakeClient(scripts)
    outcome = asyncio.run(
        rerun_stage(pack, saved, number, SETTINGS, CONFIG, client_factory=client.factory(), environ={})
    )
    return outcome, client


def test_rerun_replaces_the_last_stage_without_planning_or_touching_earlier_stages():
    from tests.test_lecturer import chain_json

    pack, saved = saved_three_stages()
    (new_file, metrics), client = rerun(3, saved, pack, [reply(chain_json(pack, blocks=[doc("A different introduction", "https://attack.mitre.org/techniques/T1190/")]))])
    assert len(client.prompts) == 1  # one Lecturer call, no Planner call
    assert new_file.stages[:2] == saved.stages[:2] and new_file.plan == saved.plan
    assert new_file.stages[2] != saved.stages[2] and metrics.attempts == 1
    assert "Input is evaluated by the logger" in client.prompts[0]  # it read stage 2


def test_rerun_can_add_the_next_stage_but_not_skip_ahead():
    pack, saved = saved_three_stages()
    two = saved.model_copy(update={"stages": saved.stages[:2]})
    with pytest.raises(ValueError, match="cannot be written now"):
        rerun(4, two, pack, [])
    with pytest.raises(ValueError, match="cannot be written now"):
        rerun(0, saved, pack, [])


def test_rerun_refuses_to_replace_a_stage_that_later_stages_depend_on():
    pack, saved = saved_three_stages()
    with pytest.raises(ValueError, match="only the last saved stage"):
        rerun(2, saved, pack, [])


def test_rerun_refuses_a_pack_for_another_topic():
    pack, saved = saved_three_stages()
    other = pack.model_copy(update={"topic": "CVE-1999-0001"})
    with pytest.raises(ValueError, match="CVE-1999-0001"):
        rerun(3, saved, other, [])


def test_stages_are_written_with_every_earlier_glossary_in_view():
    import json

    from tests.test_frames import chain_pack
    from tests.test_lecturer import chain_json, with_glossary

    pack = chain_pack()
    s1 = with_glossary(stage_json(), ("Log4j2", "A Java logging library."))
    s2 = with_glossary(STAGE2, ("JNDI", "A Java naming feature."))
    s3 = with_glossary(chain_json(pack), ("Attack step", "The ordered steps of an attack."))
    outcome, client = run(
        [reply(plan_json("overview", "why_possible", "attack_chain", "response_prevention", covers=(1, 2, 3))),
         reply(s1), reply(s2), reply(s3)],
        pack=pack,
    )
    assert "Log4j2" in client.prompts[2] and "Terms already defined" in client.prompts[2]
    assert "Log4j2; JNDI" in client.prompts[3]
    assert [g.term for g in outcome.file.stages[2].glossary] == ["Attack step"]
    json.loads(outcome.file.model_dump_json())


def test_rerun_of_stage_3_sees_the_glossaries_of_the_kept_stages():
    from tests.test_lecturer import chain_json, with_glossary

    pack, saved = saved_three_stages()
    from src.stage_content import GlossaryEntry, StagesFile

    kept1 = saved.stages[0].model_copy(update={"glossary": [GlossaryEntry.model_validate(
        {"term": "Log4j2", "definition": {"value": "A Java logging library.", "tag": "inference"}})]})
    saved = StagesFile(topic=saved.topic, plan=saved.plan, stages=[kept1, *saved.stages[1:]])
    repeat = with_glossary(chain_json(pack), ("log4j2", "A Java logging library."))
    with pytest.raises(SingleCallFailedError):
        rerun(3, saved, pack, [reply(repeat)] * 3)
    (new_file, _), client = rerun(3, saved, pack, [reply(chain_json(pack))])
    assert "Log4j2" in client.prompts[0]
