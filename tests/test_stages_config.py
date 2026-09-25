"""Tests for src/stages_config.py. Uses temporary files, never a model or the network."""

import pytest

from src.schemas import Depth, DiagramType
from src.stages_config import DEFAULT_STAGES_PATH, StagesConfigError, load_stages_config

ONE = """
[[stage]]
number = 1
key = "overview"
subject = "Overview"
allowed_depths = ["overview"]
allowed_diagrams = ["story_flow"]
content = "The story."
"""

TWO = ONE + """
[[stage]]
number = 2
key = "why_possible"
subject = "Why it is possible"
allowed_depths = ["conceptual", "technical"]
allowed_diagrams = ["architecture", "sequence"]
content = "The mechanism."
"""


def write(tmp_path, text):
    path = tmp_path / "stages.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_file_is_loaded(tmp_path):
    config = load_stages_config(write(tmp_path, TWO))
    assert [s.number for s in config.stages] == [1, 2]
    assert config.stage(2).allowed_diagrams == [DiagramType.ARCHITECTURE, DiagramType.SEQUENCE]
    assert config.stage(1).allowed_depths == [Depth.OVERVIEW]


def test_real_file_matches_spec_table():
    config = load_stages_config(DEFAULT_STAGES_PATH)
    assert [s.key for s in config.stages] == [
        "overview", "why_possible", "attack_chain", "analyst_view", "response_prevention"
    ]
    assert config.stage(1).allowed_diagrams == [DiagramType.STORY_FLOW]
    assert config.stage(3).allowed_diagrams == [DiagramType.KILL_CHAIN_FRAMES]
    assert config.stage(5).allowed_diagrams == [DiagramType.DECISION_TREE]


def test_unknown_stage_number_is_reported(tmp_path):
    config = load_stages_config(write(tmp_path, ONE))
    with pytest.raises(KeyError):
        config.stage(9)


def test_missing_file_is_reported(tmp_path):
    with pytest.raises(StagesConfigError, match="not found"):
        load_stages_config(tmp_path / "nope.toml")


def test_invalid_toml_is_reported(tmp_path):
    with pytest.raises(StagesConfigError, match="not valid TOML"):
        load_stages_config(write(tmp_path, "[[stage]\nnumber ="))


def test_no_stages_is_rejected(tmp_path):
    with pytest.raises(StagesConfigError):
        load_stages_config(write(tmp_path, "title = 'x'\n"))


def test_gap_in_numbers_is_rejected(tmp_path):
    with pytest.raises(StagesConfigError, match="1, 2, 3"):
        load_stages_config(write(tmp_path, TWO.replace("number = 2", "number = 3")))


def test_duplicate_key_is_rejected(tmp_path):
    with pytest.raises(StagesConfigError, match="duplicate"):
        load_stages_config(write(tmp_path, TWO.replace('key = "why_possible"', 'key = "overview"')))


@pytest.mark.parametrize(
    "old, new",
    [
        ('allowed_diagrams = ["story_flow"]', 'allowed_diagrams = ["pie_chart"]'),
        ('allowed_diagrams = ["story_flow"]', "allowed_diagrams = []"),
        ('allowed_depths = ["overview"]', 'allowed_depths = ["expert"]'),
        ('allowed_depths = ["overview"]', "allowed_depths = []"),
        ('subject = "Overview"', 'subject = ""'),
        ("number = 1", "number = 0"),
    ],
)
def test_bad_values_are_rejected(tmp_path, old, new):
    with pytest.raises(StagesConfigError):
        load_stages_config(write(tmp_path, ONE.replace(old, new)))


def test_unknown_key_is_rejected(tmp_path):
    with pytest.raises(StagesConfigError):
        load_stages_config(write(tmp_path, ONE + "colour = 'red'\n"))


def test_stage_by_key(tmp_path):
    config = load_stages_config(write(tmp_path, TWO))
    assert config.stage_by_key("why_possible").number == 2
    with pytest.raises(KeyError):
        config.stage_by_key("nope")
