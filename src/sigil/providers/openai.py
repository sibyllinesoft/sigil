"""OpenAI GPT provider."""

import openai

from sigil.providers.base import Provider


class OpenAIProvider(Provider):
    """OpenAI GPT API provider."""

    def __init__(self, model: str = "gpt-4o", max_tokens: int = 1024):
        self._client = openai.AsyncOpenAI()
        self._model = model
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        return f"openai:{self._model}"

    async def complete(self, system_prompt: str, user_message: str) -> str:
        response = await self._client.chat.completions.create(
            model=self._model,
            max_tokens=self._max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        )
        return response.choices[0].message.content or ""
