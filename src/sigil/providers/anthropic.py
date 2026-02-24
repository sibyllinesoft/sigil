"""Anthropic Claude provider -- no tool use, no privileges."""

import anthropic

from sigil.providers.base import Provider


class AnthropicProvider(Provider):
    """Anthropic Claude API provider.

    Sends only system + user message. No tools, no computer use,
    no privileges -- the model is a pure text-in/text-out responder.
    """

    def __init__(
        self,
        model: str = "claude-haiku-4-5-20251001",
        max_tokens: int = 1024,
    ):
        self._client = anthropic.AsyncAnthropic()
        self._model = model
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        return f"anthropic:{self._model}"

    async def complete(self, system_prompt: str, user_message: str) -> str:
        response = await self._client.messages.create(
            model=self._model,
            max_tokens=self._max_tokens,
            system=system_prompt,
            messages=[{"role": "user", "content": user_message}],
        )
        return response.content[0].text
