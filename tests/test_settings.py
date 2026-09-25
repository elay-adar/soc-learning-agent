"""Tests for src/settings.py. Uses temporary files, never a model or the network."""

import pytest

from src.settings import DEFAULT_SETTINGS_PATH, SettingsError, load_settings

VALID = """
[researcher]
model = "sonnet-5"
effort = "medium"
max_turns = 20
max_schema_retries = 2

[planner]
model = "sonnet-5"
effort = "medium"
max_schema_retries = 2

[lecturer]
model = "sonnet-5"
effort = "low"
max_schema_retries = 1
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


def test_planner_and_lecturer_are_loaded(tmp_path):
    s = load_settings(write(tmp_path, VALID))
    assert (s.planner.model, s.planner.effort, s.planner.max_schema_retries) == ("sonnet-5", "medium", 2)
    assert (s.lecturer.effort, s.lecturer.max_schema_retries) == ("low", 1)


def test_real_file_has_planner_and_lecturer():
    s = load_settings(DEFAULT_SETTINGS_PATH)
    assert s.planner.model and s.lecturer.model


@pytest.mark.parametrize("role", ["planner", "lecturer"])
def test_single_call_roles_have_no_turn_cap(tmp_path, role):
    # These roles make single calls with no tools, so max_turns is not a valid key.
    text = VALID.replace(f"[{role}]\n", f"[{role}]\nmax_turns = 5\n")
    with pytest.raises(SettingsError):
        load_settings(write(tmp_path, text))


@pytest.mark.parametrize("role", ["planner", "lecturer"])
def test_missing_role_section_is_rejected(tmp_path, role):
    text = VALID.split(f"[{role}]")[0] + ("[lecturer]" + VALID.split("[lecturer]")[1] if role == "planner" else "")
    with pytest.raises(SettingsError):
        load_settings(write(tmp_path, text))


@pytest.mark.parametrize(
    "old, new",
    [
        ("max_schema_retries = 1", "max_schema_retries = -1"),
        ('effort = "low"', 'effort = "extreme"'),
    ],
)
def test_bad_lecturer_values_are_rejected(tmp_path, old, new):
    with pytest.raises(SettingsError):
        load_settings(write(tmp_path, VALID.replace(old, new)))


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
