"""Tests for src/settings.py. Uses temporary files, never a model or the network."""

import pytest

from src.settings import DEFAULT_SETTINGS_PATH, SettingsError, load_settings

VALID = """
[researcher]
model = "sonnet-5"
effort = "medium"
max_turns = 20
max_schema_retries = 2
"""


def write(tmp_path, text):
    path = tmp_path / "settings.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_valid_file_is_loaded(tmp_path):
    r = load_settings(write(tmp_path, VALID)).researcher
    assert (r.model, r.effort, r.max_turns, r.max_schema_retries) == ("sonnet-5", "medium", 20, 2)


def test_real_settings_file_is_valid():
    assert load_settings(DEFAULT_SETTINGS_PATH).researcher.max_turns == 20


def test_missing_file_is_reported(tmp_path):
    with pytest.raises(SettingsError, match="not found"):
        load_settings(tmp_path / "nope.toml")


def test_invalid_toml_is_reported(tmp_path):
    with pytest.raises(SettingsError, match="not valid TOML"):
        load_settings(write(tmp_path, "[researcher\nmodel ="))


def test_missing_key_is_rejected(tmp_path):
    with pytest.raises(SettingsError):
        load_settings(write(tmp_path, VALID.replace("max_turns = 20\n", "")))


@pytest.mark.parametrize(
    "old, new",
    [
        ("max_turns = 20", "max_turns = 0"),
        ("max_turns = 20", 'max_turns = "many"'),
        ("max_schema_retries = 2", "max_schema_retries = -1"),
        ('effort = "medium"', 'effort = "extreme"'),
        ('model = "sonnet-5"', 'model = ""'),
    ],
)
def test_bad_values_are_rejected(tmp_path, old, new):
    with pytest.raises(SettingsError):
        load_settings(write(tmp_path, VALID.replace(old, new)))


def test_unknown_key_is_rejected(tmp_path):
    with pytest.raises(SettingsError):
        load_settings(write(tmp_path, VALID + "max_turnz = 5\n"))
