"""Milestone 0: minimal Agent SDK check.

Sends one short prompt, prints the reply, and prints the usage fields the SDK
reports. Refuses to run if ANTHROPIC_API_KEY is set, so a run can never be
billed to an API account by accident.
"""

import asyncio
import os
import sys

from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    query,
)


async def main() -> None:
    if os.environ.get("ANTHROPIC_API_KEY"):
        print("Stop: ANTHROPIC_API_KEY is set. Remove it so usage draws from the subscription.")
        sys.exit(1)

    options = ClaudeAgentOptions(
        system_prompt="You are a connectivity check. Answer in one short sentence.",
        max_turns=1,
    )

    async for message in query(prompt="Reply with the word: ready", options=options):
        if isinstance(message, AssistantMessage):
            print("model:", getattr(message, "model", "unknown"))
            for block in message.content:
                if isinstance(block, TextBlock):
                    print("reply:", block.text)
        elif isinstance(message, ResultMessage):
            print("--- result ---")
            print("is_error:", getattr(message, "is_error", None))
            print("turns:", getattr(message, "num_turns", None))
            print("duration_ms:", getattr(message, "duration_ms", None))
            print("usage:", getattr(message, "usage", None))
            print("reported_cost_usd:", getattr(message, "total_cost_usd", None))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as exc:  # show the exact failure type for diagnosis
        print(f"Failed: {type(exc).__name__}: {exc}")
        sys.exit(1)
