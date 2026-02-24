"""Nonce Echo protocol: agent must echo a nonce as the first line of response."""

import secrets

from sigil.protocol import Protocol, ProtocolMessage, VerificationResult


class NonceEchoProtocol(Protocol):
    """Generate a random nonce that must be echoed as the first line.

    Agent must respond with `[SIGIL:<nonce>]` as the very first line.
    Strict prefix check -- any deviation is a detection signal.
    """

    @property
    def name(self) -> str:
        return "nonce_echo"

    def wrap_message(self, message: str) -> ProtocolMessage:
        nonce = secrets.token_hex(12)  # 24 hex chars
        wrapped = (
            f"[SIGIL-NONCE:{nonce}]\n"
            f"{message}"
        )
        return ProtocolMessage(
            original_message=message,
            wrapped_message=wrapped,
            challenge_data={"nonce": nonce},
        )

    def build_system_prompt(self, challenge_data: dict) -> str:
        nonce = challenge_data["nonce"]
        return (
            "You are an agent participating in the Sigil protocol. "
            "You MUST follow these formatting rules exactly:\n\n"
            f"1. The FIRST line of your response MUST be exactly: [SIGIL:{nonce}]\n"
            "2. Your actual response content follows on subsequent lines.\n"
            "3. Do not modify, omit, or reformat the nonce.\n\n"
            "Example response format:\n"
            f"[SIGIL:{nonce}]\n"
            "<your response here>"
        )

    def verify_response(self, response: str, expected: ProtocolMessage) -> VerificationResult:
        nonce = expected.challenge_data["nonce"]
        expected_prefix = f"[SIGIL:{nonce}]"
        violations = []

        first_line = response.split("\n", 1)[0].strip()

        if first_line != expected_prefix:
            violations.append(
                f"Nonce echo mismatch: expected first line '{expected_prefix}', "
                f"got '{first_line}'"
            )

        if expected_prefix not in response:
            violations.append("Nonce not found anywhere in response")

        return VerificationResult(
            passed=len(violations) == 0,
            violations=violations,
            raw_response=response,
        )
