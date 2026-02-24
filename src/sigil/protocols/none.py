"""No-protection passthrough protocol for baseline comparison."""

from sigil.protocol import Protocol, ProtocolMessage, VerificationResult


class NoneProtocol(Protocol):
    """Passthrough with no protection. Baseline for measuring attack impact."""

    @property
    def name(self) -> str:
        return "none"

    def wrap_message(self, message: str) -> ProtocolMessage:
        return ProtocolMessage(
            original_message=message,
            wrapped_message=message,
            challenge_data={},
        )

    def build_system_prompt(self, challenge_data: dict) -> str:
        return "You are a helpful assistant. Respond to the user's message."

    def verify_response(self, response: str, expected: ProtocolMessage) -> VerificationResult:
        # No protocol to verify — always passes
        return VerificationResult(
            passed=True,
            raw_response=response,
        )
