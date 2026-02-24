"""Base protocol interface for Sigil challenge-response protocols."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ProtocolMessage:
    """A message wrapped with protocol challenge elements."""

    original_message: str
    wrapped_message: str
    challenge_data: dict = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Result of verifying a response against protocol expectations."""

    passed: bool
    violations: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)  # soft issues (e.g. checksum)
    raw_response: str = ""


class Protocol(ABC):
    """Abstract base for Sigil challenge-response protocols."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable protocol name."""

    @abstractmethod
    def wrap_message(self, message: str) -> ProtocolMessage:
        """Wrap an outgoing message with challenge elements."""

    @abstractmethod
    def build_system_prompt(self, challenge_data: dict) -> str:
        """System prompt instructing the agent how to respond within protocol."""

    @abstractmethod
    def verify_response(self, response: str, expected: ProtocolMessage) -> VerificationResult:
        """Verify the response satisfies protocol requirements."""
