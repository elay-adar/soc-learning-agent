"""The Orchestrator so far: plain code that runs Planner, then Lecturer, in a fixed order.

Milestone 3 covers the Planner and stages 1 and 2. Each stage is written only after the
previous one passed its checks, and stage N reads stage N-1. Stages the Lecturer cannot write
yet are listed in `not_built`, not skipped silently.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from claude_agent_sdk import ClaudeSDKClient

from src.lecturer import BUILT_KEYS, run_lecturer
from src.planner import run_planner
from src.researcher import RunMetrics
from src.schemas import KnowledgePack
from src.settings import SingleCallSettings
from src.stage_content import StageContent, StagesFile
from src.stages_config import StagesConfig


@dataclass
class StagesRun:
    file: StagesFile
    planner_metrics: RunMetrics
    stage_metrics: list[RunMetrics] = field(default_factory=list)
    not_built: list[str] = field(default_factory=list)  # keys of planned stages not written yet


async def rerun_stage(
    pack: KnowledgePack,
    saved: StagesFile,
    stage_number: int,
    lecturer_settings: SingleCallSettings,
    config: StagesConfig | None = None,
    *,
    client_factory: Any = ClaudeSDKClient,
    environ: Mapping[str, str] = os.environ,
) -> tuple[StagesFile, RunMetrics]:
    """Write one stage again from a saved run, without planning again.

    Only the last saved stage can be replaced (later stages would depend on the old text), and
    only the next stage can be added. The stage before it is read as its previous stage.
    """
    written = len(saved.stages)
    if not 1 <= stage_number <= min(written + 1, saved.plan.stage_count):
        raise ValueError(
            f"stage {stage_number} cannot be written now: {written} stages are saved "
            f"and the plan has {saved.plan.stage_count}"
        )
    if stage_number < written:
        raise ValueError(f"only the last saved stage ({written}) can be written again")
    if saved.topic != pack.topic:
        raise ValueError(f"the saved stages are for {saved.topic}, the Pack is for {pack.topic}")
    kept = saved.stages[: stage_number - 1]
    lecture = await run_lecturer(
        pack, saved.plan, stage_number, lecturer_settings, config,
        previous=kept[-1] if kept else None,
        earlier=kept,
        client_factory=client_factory, environ=environ,
    )
    return StagesFile(topic=saved.topic, plan=saved.plan, stages=[*kept, lecture.content]), lecture.metrics


async def run_stages(
    pack: KnowledgePack,
    planner_settings: SingleCallSettings,
    lecturer_settings: SingleCallSettings,
    config: StagesConfig | None = None,
    *,
    client_factory: Any = ClaudeSDKClient,
    environ: Mapping[str, str] = os.environ,
) -> StagesRun:
    """Plan, then write every planned stage the Lecturer can build. Stops on the first failure."""
    planned = await run_planner(
        pack, planner_settings, config, client_factory=client_factory, environ=environ
    )
    plan = planned.plan
    written: list[StageContent] = []
    metrics: list[RunMetrics] = []
    for item in plan.stages:
        if item.key not in BUILT_KEYS:
            break
        lecture = await run_lecturer(
            pack, plan, item.number, lecturer_settings, config,
            previous=written[-1] if written else None,
            earlier=written,
            client_factory=client_factory, environ=environ,
        )
        written.append(lecture.content)
        metrics.append(lecture.metrics)
    not_built = [item.key for item in plan.stages[len(written):]]
    return StagesRun(
        file=StagesFile(topic=pack.topic, plan=plan, stages=written),
        planner_metrics=planned.metrics,
        stage_metrics=metrics,
        not_built=not_built,
    )
