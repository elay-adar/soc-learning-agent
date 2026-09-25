"""The Lecturer's output for one stage.

Every block of text carries a provenance tag (spec section 8), so it reuses SourcedValue:
a 'documented' block must have a source URL. Rules that need the Knowledge Pack are in
src/stage_rules.py.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from src.schemas import DiagramType, SourcedValue, StagePlan, StrictModel


class Diagram(StrictModel):
    type: DiagramType
    mermaid: str = Field(min_length=1)


class StageContent(StrictModel):
    stage_number: int = Field(ge=1)  # position in the plan
    key: str = Field(min_length=1)  # which stage definition this is
    title: str = Field(min_length=1)
    blocks: list[SourcedValue] = Field(min_length=1)  # paragraphs, in reading order
    diagram: Diagram


class StagesFile(StrictModel):
    """What scripts/run_stages.py saves: the plan and the stages written so far."""

    topic: str = Field(min_length=1)
    plan: StagePlan
    stages: list[StageContent] = []

    @model_validator(mode="after")
    def check_stages_match_plan(self) -> StagesFile:
        for content in self.stages:
            if not 1 <= content.stage_number <= self.plan.stage_count:
                raise ValueError(f"stage {content.stage_number} is not in the plan")
            if self.plan.stages[content.stage_number - 1].key != content.key:
                raise ValueError(f"stage {content.stage_number} has a key that differs from the plan")
        numbers = [c.stage_number for c in self.stages]
        if numbers != list(range(1, len(numbers) + 1)):
            raise ValueError("stages must be saved in order from stage 1 without gaps")
        return self
