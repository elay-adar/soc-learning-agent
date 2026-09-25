"""Shared machinery for roles that make single calls with no tools (Planner, Lecturer).

Unlike the Researcher, these roles cannot read the web or any file. The options below remove
every tool, and code checks that on every run. The model's reply is parsed and validated by a
function the role supplies; a rejected reply is sent back with the reason, up to the retry cap
in config/settings.toml.
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, TypeVar

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ClaudeSDKClient,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
)

from src.researcher import (
    AgentRunError,
    ApiKeyPresentError,
    RunMetrics,
    TurnLimitError,
    extract_json,
)
from src.settings import SingleCallSettings

T = TypeVar("T")


class UnsafeOptionsError(RuntimeError):
    """The options would give a single-call role tools, settings or more than one turn."""


class OutputError(ValueError):
    """The model's output is not valid or breaks a rule. The message says why, so it can be
    sent back for a correction."""


class SingleCallFailedError(RuntimeError):
    """The output was still invalid after every allowed attempt."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(f"the output was still invalid after {len(errors)} attempt(s): {errors[-1]}")


def build_single_call_options(settings: SingleCallSettings, system_prompt: str) -> ClaudeAgentOptions:
    """Options for one tool-less call: no tools, no servers, no settings, one turn."""
    options = ClaudeAgentOptions(
        model=settings.model,
        effort=settings.effort,
        max_turns=1,
        system_prompt=system_prompt,
        tools=[],
        allowed_tools=[],
        mcp_servers={},
        strict_mcp_config=True,
        setting_sources=[],
        skills=[],
        plugins=[],
        agents=None,
        permission_mode="dontAsk",
    )
    assert_single_call_options(options)
    return options


def assert_single_call_options(options: ClaudeAgentOptions) -> None:
    """Raise UnsafeOptionsError unless the options match the tool-less setup."""
    problems: list[str] = []
    if options.tools != []:
        problems.append(f"built-in tools are not disabled (tools={options.tools!r})")
    if options.allowed_tools:
        problems.append(f"allowed_tools is {options.allowed_tools!r}")
    if options.mcp_servers:
        problems.append(f"MCP servers are {sorted(options.mcp_servers)!r}")
    if options.setting_sources != []:
        problems.append("filesystem settings are not disabled")
    if options.skills != [] or options.plugins or options.agents:
        problems.append("skills, plugins or subagents are enabled")
    if options.permission_mode != "dontAsk":
        problems.append(f"permission_mode is {options.permission_mode!r}")
    if options.max_turns != 1:
        problems.append(f"max_turns is {options.max_turns!r}, expected 1")
    if problems:
        raise UnsafeOptionsError("; ".join(problems))


def correction_request(error: str) -> str:
    return (
        "Your output was rejected by the validator and nothing was saved. Reason: "
        f"{error}\n"
        "Return the complete corrected JSON object again, and nothing else. "
        "Do not add facts that are not in the Knowledge Pack."
    )


@dataclass
class _Session:
    """One conversation. Every call to `ask` is one prompt and its full reply."""

    client: Any
    first_prompt: str
    metrics: RunMetrics
    errors: list[str] = field(default_factory=list)

    async def ask(self, feedback: str | None) -> str:
        await self.client.query(feedback if feedback is not None else self.first_prompt)
        last_text = ""
        async for message in self.client.receive_response():
            if isinstance(message, AssistantMessage):
                self.metrics.turns += 1
                if any(isinstance(b, ToolUseBlock) for b in message.content):
                    raise AgentRunError("the model tried to use a tool, but none are available")
                texts = [b.text for b in message.content if isinstance(b, TextBlock)]
                if texts:
                    last_text = "".join(texts)
            elif isinstance(message, ResultMessage):
                self.metrics.duration_ms += message.duration_ms
                if message.total_cost_usd is not None:
                    self.metrics.cost_usd = (self.metrics.cost_usd or 0.0) + message.total_cost_usd
                if message.usage:
                    self.metrics.usage.append(message.usage)
                if message.subtype == "error_max_turns":
                    raise TurnLimitError("the SDK stopped the single call at its turn limit")
                if message.is_error:
                    detail = "; ".join(message.errors or []) or message.result
                    raise AgentRunError(f"{message.subtype}: {detail}")
                if isinstance(message.result, str) and message.result.strip():
                    last_text = message.result
        return extract_json(last_text)


async def retry_until_valid(
    ask: Callable[[str | None], Awaitable[str]],
    parse: Callable[[str], T],
    max_schema_retries: int,
) -> tuple[T, int]:
    """Ask, parse, and on OutputError ask again with the reason. Returns (value, attempts).

    At most max_schema_retries corrections, so at most max_schema_retries + 1 attempts.
    """
    errors: list[str] = []
    feedback: str | None = None
    for attempt in range(1, max_schema_retries + 2):
        raw = await ask(feedback)
        try:
            return parse(raw), attempt
        except OutputError as exc:
            errors.append(str(exc))
            feedback = correction_request(str(exc))
    raise SingleCallFailedError(errors)


async def run_single_call(
    settings: SingleCallSettings,
    system_prompt: str,
    first_prompt: str,
    parse: Callable[[str], T],
    *,
    client_factory: Callable[[ClaudeAgentOptions], Any] = ClaudeSDKClient,
    environ: Mapping[str, str] = os.environ,
) -> tuple[T, RunMetrics]:
    """Run one tool-less call with validate-and-correct. Returns (parsed value, metrics).

    Raises ApiKeyPresentError, TurnLimitError, AgentRunError or SingleCallFailedError.
    """
    if environ.get("ANTHROPIC_API_KEY"):
        raise ApiKeyPresentError(
            "ANTHROPIC_API_KEY is set. Remove it so usage draws from the subscription, "
            "not an API account."
        )
    options = build_single_call_options(settings, system_prompt)
    metrics = RunMetrics()
    async with client_factory(options) as client:
        session = _Session(client, first_prompt, metrics)
        value, attempts = await retry_until_valid(session.ask, parse, settings.max_schema_retries)
    metrics.attempts = attempts
    return value, metrics
