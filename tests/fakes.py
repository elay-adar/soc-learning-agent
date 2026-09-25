"""Shared test doubles. A fake client stands in for the SDK: no model call, no network."""

from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock


def assistant(*blocks):
    return AssistantMessage(content=list(blocks), model="fake")


def reply(text):
    """One scripted answer: an assistant message with text, then a successful result."""
    return [assistant(TextBlock(text=text)), result(None)]


def result(text=None, **kw):
    fields = dict(
        subtype="success", duration_ms=10, duration_api_ms=8, is_error=False, num_turns=1,
        session_id="s", total_cost_usd=0.0, usage={"output_tokens": 5}, result=text,
    )
    fields.update(kw)
    return ResultMessage(**fields)


class FakeClient:
    """Plays one scripted list of messages per client.query() call."""

    def __init__(self, scripts):
        self.scripts, self.prompts, self.options = list(scripts), [], None

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def query(self, prompt):
        self.prompts.append(prompt)
        self._current = self.scripts[len(self.prompts) - 1]

    async def receive_response(self):
        for message in self._current:
            yield message

    def factory(self):
        def make(options):
            self.options = options
            return self

        return make
