"""The terminal commands for the local page (spec section 10). No model call happens here.

`next` shows the next written stage, `repeat N` scrolls the page to stage N, `help` lists the
commands, `quit` stops. The final list of commands is still open (spec section 15, question 8).
"""

from __future__ import annotations

from dataclasses import dataclass

from src.server import PageState, PageStateError

HELP = (
    "Commands: next (show the next stage), repeat N (go back to stage N), "
    "help (this list), quit (stop the agent and close the page)."
)


@dataclass
class CommandResult:
    message: str
    quit: bool = False


def handle_command(state: PageState, line: str) -> CommandResult:
    """Carry out one typed command and say what happened. Never raises for bad input."""
    words = line.strip().lower().split()
    if not words:
        return CommandResult("")
    command, args = words[0], words[1:]

    if command in ("quit", "exit", "q"):
        return CommandResult("Stopping.", quit=True)
    if command == "help":
        return CommandResult(HELP)
    if command == "next":
        stage = state.reveal_next()
        if stage is not None:
            return CommandResult(f"Showing stage {stage.stage_number}: {stage.title}. ({state.revealed} of {state.stage_count} written stages shown.)")
        return CommandResult(_nothing_more(state))
    if command == "repeat":
        if len(args) != 1 or not args[0].isdigit():
            return CommandResult("Usage: repeat N  (for example: repeat 2)")
        try:
            state.repeat(int(args[0]))
        except PageStateError as exc:
            return CommandResult(f"Cannot repeat: {exc}.")
        return CommandResult(f"Scrolling the page to stage {args[0]}.")
    return CommandResult(f"Unknown command '{command}'. {HELP}")


def _nothing_more(state: PageState) -> str:
    planned = state.file.plan.stage_count
    if state.stage_count < planned:
        return (
            f"All {state.stage_count} written stages are shown. The plan has {planned}: "
            "the rest are not built yet (later milestones)."
        )
    return "All stages are shown."
