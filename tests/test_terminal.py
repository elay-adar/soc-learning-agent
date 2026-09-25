"""Tests for src/demo.py, src/terminal.py and scripts/serve_stages.py. No model, no network."""

import importlib.util
from pathlib import Path

import pytest

from src.demo import demo_pack, demo_plan, demo_stages_file
from src.plan_rules import check_plan
from src.server import PageState
from src.stage_rules import check_stage
from src.stages_config import DEFAULT_STAGES_PATH, load_stages_config
from src.terminal import HELP, handle_command


# ---- the demo data follows the real rules ----------------------------------------


def test_demo_plan_passes_the_plan_rules():
    check_plan(demo_plan(), demo_pack(), load_stages_config(DEFAULT_STAGES_PATH))


def test_demo_stages_pass_the_stage_rules():
    file = demo_stages_file()
    for stage in file.stages:
        check_stage(stage, demo_pack(), file.plan.stages[stage.stage_number - 1], file.stages[: stage.stage_number - 1])
    assert [len(s.glossary) for s in file.stages] == [0, 2, 1]  # the demo shows the "New terms" list


def test_demo_stage_3_has_one_frame_per_attack_step_and_is_clearly_sample_data():
    file = demo_stages_file()
    assert len(file.stages[2].frames) == len(demo_pack().attack_steps) == 4
    assert "DEMO" in file.topic
    assert all(b.tag.value == "inference" for s in file.stages for b in s.all_blocks())


# ---- commands --------------------------------------------------------------------


@pytest.fixture
def state():
    return PageState(demo_stages_file())


def test_empty_line_does_nothing(state):
    assert handle_command(state, "   ").message == "" and state.revealed == 0


def test_next_shows_stages_in_order_and_then_says_what_is_left(state):
    first = handle_command(state, "next").message
    assert "stage 1" in first.lower() and "1 of 3" in first
    handle_command(state, "next")
    handle_command(state, "NEXT")
    assert state.revealed == 3
    done = handle_command(state, "next").message
    assert "3 written stages" in done and "plan has 4" in done and "not built yet" in done
    assert state.revealed == 3


def test_repeat_scrolls_to_a_shown_stage(state):
    handle_command(state, "next")
    result = handle_command(state, "repeat 1")
    assert "stage 1" in result.message and state.snapshot()["focus"] == {"stage": 1, "seq": 1}


def test_repeat_of_an_unseen_stage_is_explained_not_raised(state):
    result = handle_command(state, "repeat 2")
    assert "Cannot repeat" in result.message and "none yet" in result.message
    assert state.snapshot()["focus"]["seq"] == 0


@pytest.mark.parametrize("line", ["repeat", "repeat x", "repeat 1 2", "repeat -1", "repeat 1.5"])
def test_repeat_with_bad_arguments_shows_usage(state, line):
    handle_command(state, "next")
    assert "Usage" in handle_command(state, line).message


def test_repeat_never_reveals_a_stage(state):
    handle_command(state, "next")
    handle_command(state, "repeat 1")
    assert state.revealed == 1


def test_help_and_unknown_commands(state):
    assert handle_command(state, "help").message == HELP
    unknown = handle_command(state, "exam").message
    assert "Unknown command 'exam'" in unknown and "Commands:" in unknown


@pytest.mark.parametrize("word", ["quit", "exit", "q", "QUIT"])
def test_quit_words(state, word):
    assert handle_command(state, word).quit is True


def test_other_commands_do_not_quit(state):
    assert not handle_command(state, "next").quit and not handle_command(state, "help").quit


# ---- the script ------------------------------------------------------------------


def load_script():
    path = Path(__file__).resolve().parents[1] / "scripts" / "serve_stages.py"
    spec = importlib.util.spec_from_file_location("serve_stages", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_script_demo_run_prints_one_address_and_stops_on_quit(monkeypatch, capsys):
    script = load_script()
    monkeypatch.setattr("builtins.input", scripted(["next", "repeat 1", "quit"]))
    assert script.main(["--demo", "--port", "0"]) == 0
    out = capsys.readouterr().out
    assert out.count("http://127.0.0.1:") == 1 and "?token=" in out
    assert "Showing stage 1" in out and "Scrolling the page to stage 1" in out and "Stopping." in out


def test_script_stops_cleanly_when_input_ends(monkeypatch):
    script = load_script()

    def eof(_prompt=""):
        raise EOFError

    monkeypatch.setattr("builtins.input", eof)
    assert script.main(["--demo", "--port", "0"]) == 0


def test_script_without_a_topic_or_demo_explains(capsys):
    assert load_script().main([]) == 1
    assert "--demo" in capsys.readouterr().out


def test_script_reports_missing_and_invalid_saved_stages(monkeypatch, tmp_path, capsys):
    script = load_script()
    monkeypatch.setattr(script, "SESSIONS", tmp_path)
    assert script.main(["CVE-2021-44228"]) == 1
    assert "run_stages.py" in capsys.readouterr().out
    (tmp_path / "CVE-2021-44228.stages.json").write_text("{}", encoding="utf-8")
    assert script.main(["CVE-2021-44228"]) == 1
    assert "not valid" in capsys.readouterr().out
    assert script.main(["not-a-cve"]) == 1


def test_script_loads_a_saved_stages_file(monkeypatch, tmp_path):
    script = load_script()
    monkeypatch.setattr(script, "SESSIONS", tmp_path)
    (tmp_path / "CVE-2021-44228.stages.json").write_text(demo_stages_file().model_dump_json(), encoding="utf-8")
    monkeypatch.setattr("builtins.input", scripted(["quit"]))
    assert script.main(["CVE-2021-44228", "--port", "0"]) == 0


def scripted(lines):
    """A stand-in for input() that types the given lines."""
    typed = iter(lines)
    return lambda _prompt="": next(typed)
