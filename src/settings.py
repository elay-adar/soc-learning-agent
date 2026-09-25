"""Load model and effort settings per agent role from config/settings.toml.

The file is read with the standard library (tomllib) and checked with Pydantic, so a
typo or a bad number fails loudly at start-up instead of deep inside a run.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

DEFAULT_SETTINGS_PATH = Path(__file__).resolve().parent.parent / "config" / "settings.toml"


class SettingsError(ValueError):
    """The settings file is missing, is not valid TOML, or has invalid values."""


class ResearcherSettings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    model: str = Field(min_length=1)
    effort: Literal["low", "medium", "high", "xhigh", "max"]
    max_turns: int = Field(ge=1)  # hard stop on turns per run, across all tools
    max_schema_retries: int = Field(ge=0)  # corrections allowed after an invalid Pack


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    researcher: ResearcherSettings


def load_settings(path: Path = DEFAULT_SETTINGS_PATH) -> Settings:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise SettingsError(f"settings file not found: {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise SettingsError(f"{path} is not valid TOML: {exc}") from exc
    try:
        return Settings.model_validate(raw)
    except ValidationError as exc:
        raise SettingsError(f"invalid settings in {path}:\n{exc}") from exc
