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
