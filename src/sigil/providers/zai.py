"""Z.AI GLM provider (OpenAI-compatible API)."""

import os

import openai

from sigil.providers.base import Provider


class ZAIProvider(Provider):
    """Z.AI GLM API provider."""

    def __init__(self, model: str = "glm-4.7", max_tokens: int = 1024):
        self._client = openai.AsyncOpenAI(
            api_key=os.environ["ZAI_API_KEY"],
            base_url="https://api.z.ai/api/coding/paas/v4/",
        )
        self._model = model
        self._max_tokens = max_tokens

    @property
    def name(self) -> str:
        return f"zai:{self._model}"

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
