"""Canary Token protocol: embed a random token that must survive round-trip."""

import secrets

from sigil.protocol import Protocol, ProtocolMessage, VerificationResult


class CanaryProtocol(Protocol):
    """Embed a random 16-char hex canary in the message.

    The system prompt instructs the agent to include the canary verbatim
    in a specific position in its response. If missing or wrong, injection detected.
    """

    @property
    def name(self) -> str:
        return "canary"

    def wrap_message(self, message: str) -> ProtocolMessage:
        canary = secrets.token_hex(8)  # 16 hex chars
        wrapped = (
            f"[CANARY:{canary}]\n"
            f"{message}\n"
            f"[/CANARY]"
        )
        return ProtocolMessage(
            original_message=message,
            wrapped_message=wrapped,
            challenge_data={"canary": canary},
        )

    def build_system_prompt(self, challenge_data: dict) -> str:
        canary = challenge_data["canary"]
        return (
            "You are an agent participating in the Sigil protocol. "
            "You MUST follow these formatting rules exactly:\n\n"
            f"1. Your response MUST end with the line: [CANARY:{canary}]\n"
            "2. Do not modify, omit, or reformat the canary token.\n"
            "3. Place your actual response content before the canary line.\n\n"
            "Example response format:\n"
            "<your response here>\n"
            f"[CANARY:{canary}]"
        )

    def verify_response(self, response: str, expected: ProtocolMessage) -> VerificationResult:
        canary = expected.challenge_data["canary"]
        expected_tag = f"[CANARY:{canary}]"
        violations = []

        if expected_tag not in response:
            violations.append(f"Canary token missing or incorrect (expected {expected_tag})")

        stripped = response.rstrip()
        if not stripped.endswith(expected_tag):
            violations.append("Canary token not at end of response")

        return VerificationResult(
            passed=len(violations) == 0,
            violations=violations,
            raw_response=response,
        )
