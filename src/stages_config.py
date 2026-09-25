"""Load the stage definitions from config/stages.toml (spec section 6.2).

Same approach as src/settings.py: read with tomllib, check with Pydantic, fail loudly at
start-up. Depths and diagram types must come from the closed lists in src/schemas.py.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from src.schemas import Depth, DiagramType

DEFAULT_STAGES_PATH = Path(__file__).resolve().parent.parent / "config" / "stages.toml"


class StagesConfigError(ValueError):
    """The stages file is missing, is not valid TOML, or has invalid values."""


class StageDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    number: int = Field(ge=1)
    key: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    allowed_depths: list[Depth] = Field(min_length=1)
    allowed_diagrams: list[DiagramType] = Field(min_length=1)
    content: str = Field(min_length=1)


class StagesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stages: list[StageDefinition] = Field(min_length=1, alias="stage")

    @model_validator(mode="after")
    def check_stages(self) -> StagesConfig:
        numbers = [s.number for s in self.stages]
        if numbers != list(range(1, len(numbers) + 1)):
            raise ValueError("stage numbers must run 1, 2, 3... without gaps")
        keys = [s.key for s in self.stages]
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate stage key")
        return self

    def stage(self, number: int) -> StageDefinition:
        """The definition for one stage number. Raises KeyError if there is none."""
        for definition in self.stages:
            if definition.number == number:
                return definition
        raise KeyError(number)

    def stage_by_key(self, key: str) -> StageDefinition:
        """The definition with this key. Raises KeyError if there is none."""
        for definition in self.stages:
            if definition.key == key:
                return definition
        raise KeyError(key)


def load_stages_config(path: Path = DEFAULT_STAGES_PATH) -> StagesConfig:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise StagesConfigError(f"stages file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise StagesConfigError(f"{path} is not valid TOML: {exc}") from exc
    try:
        return StagesConfig.model_validate(raw)
    except ValidationError as exc:
        raise StagesConfigError(f"invalid stages in {path}:\n{exc}") from exc
