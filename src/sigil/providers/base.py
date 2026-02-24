"""Abstract LLM provider interface."""

from abc import ABC, abstractmethod


class Provider(ABC):
    """Abstract base for LLM providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Provider name for reporting."""

    @abstractmethod
    async def complete(self, system_prompt: str, user_message: str) -> str:
        """Send a message to the LLM and return the response text."""
