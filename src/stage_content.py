"""The Lecturer's output for one stage.

Every block of text carries a provenance tag (spec section 8), so it reuses SourcedValue:
a 'documented' block must have a source URL. Rules that need the Knowledge Pack are in
src/stage_rules.py.

Stages 1 and 2 have one `diagram`. Stage 3 (attack chain) has `frames` instead: one Mermaid
diagram per attack step, built in code by src/frames.py from the model's `chain` entries
(spec section 7). The model never writes frame Mermaid itself.
"""

from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from src.glossary import MAX_TERM_CHARS, definition_problem
from src.schemas import DiagramType, SourcedValue, StagePlan, StrictModel


class Diagram(StrictModel):
    type: DiagramType
    mermaid: str = Field(min_length=1)


class DiagramFrame(StrictModel):
    """Frame k shows attack steps 1..k, with step k marked as new."""

    step: int = Field(ge=1)
    mermaid: str = Field(min_length=1)


class GlossaryEntry(StrictModel):
    """A term this stage introduces, with a one-sentence definition (D-025).

    The definition is tagged like any block, so provenance and the URL check apply to it.
    """

    term: str = Field(min_length=1, max_length=MAX_TERM_CHARS)
    definition: SourcedValue

    @field_validator("definition")
    @classmethod
    def check_one_sentence(cls, value: SourcedValue) -> SourcedValue:
        problem = definition_problem(value.value)
        if problem:
            raise ValueError(problem)
        return value


class ChainStep(StrictModel):
    """What the model writes for one attack step: a short frame label and a tagged description."""

    step: int = Field(ge=1)  # the attack step number in the Knowledge Pack
    label: str = Field(min_length=1, max_length=60)
    detail: SourcedValue


class AttackChainDraft(StrictModel):
    """What the Lecturer model returns for stage 3. Code turns it into a StageContent with frames."""

    stage_number: int = Field(ge=1)
    key: str = Field(min_length=1)
    title: str = Field(min_length=1)
    blocks: list[SourcedValue] = Field(min_length=1)
    glossary: list[GlossaryEntry] = []
    chain: list[ChainStep] = Field(min_length=1)


class StageContent(StrictModel):
    stage_number: int = Field(ge=1)  # position in the plan
    key: str = Field(min_length=1)  # which stage definition this is
    title: str = Field(min_length=1)
    blocks: list[SourcedValue] = Field(min_length=1)  # paragraphs, in reading order
    glossary: list[GlossaryEntry] = []  # terms first defined in this stage (D-025)
    diagram: Diagram | None = None  # stages 1, 2, 4 and 5
    frames: list[DiagramFrame] = []  # stage 3: one frame per attack step
    chain: list[ChainStep] = []  # stage 3: the text the frames were built from

    @model_validator(mode="after")
    def check_diagram_or_frames(self) -> StageContent:
        if (self.diagram is None) == (not self.frames):
            raise ValueError("a stage has either a diagram or frames, not both and not neither")
        if self.frames:
            steps = list(range(1, len(self.frames) + 1))
            if [f.step for f in self.frames] != steps:
                raise ValueError("frames must be numbered 1, 2, 3... in order")
            if [c.step for c in self.chain] != steps:
                raise ValueError("a stage with frames needs one chain entry per frame, in order")
        elif self.chain:
            raise ValueError("chain entries are only allowed together with frames")
        return self

    def all_blocks(self) -> list[SourcedValue]:
        """The stage's text: the blocks, then each chain step's description."""
        return [*self.blocks, *(c.detail for c in self.chain)]

    def all_tagged(self) -> list[SourcedValue]:
        """Every tagged text in the stage, glossary definitions included."""
        return [*self.all_blocks(), *(g.definition for g in self.glossary)]


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
