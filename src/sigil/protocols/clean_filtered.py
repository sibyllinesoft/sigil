"""Clean-filtered protocol: pre-filters with sibylline-clean, then delegates.

Wraps any inner protocol with a Clean injection detection pre-filter.
Detected injection spans are redacted from the message before it reaches
the LLM, providing a defense-in-depth layer on top of protocol verification.
"""

from sibylline_clean import InjectionDetector

from sigil.protocol import Protocol, ProtocolMessage, VerificationResult


class CleanFilteredProtocol(Protocol):
    """Wraps an inner protocol with Clean injection pre-filtering.

    The message is scanned by Clean before wrapping. Detected injection
    spans are redacted (replaced with [REDACTED]). The inner protocol
    then wraps and verifies as normal.

    This tests whether input sanitization + protocol verification
    together outperform either alone.
    """

    def __init__(
        self,
        inner: Protocol,
        threshold: float = 0.5,
        method: str = "semi-markov-crf",
    ):
        self._inner = inner
        self._detector = InjectionDetector(
            method=method,
            threshold=threshold,
            lazy_load=True,
        )

    @property
    def name(self) -> str:
        return f"clean+{self._inner.name}"

    def _redact(self, text: str) -> tuple[str, bool]:
        """Scan text and redact detected injection spans.

        Returns (redacted_text, was_flagged).
        """
        result = self._detector.analyze(text, include_matches=True)

        if not result.flagged or not result.matched_spans:
            return text, result.flagged

        # Sort spans by start position, descending, to redact from end
        spans = sorted(result.matched_spans, key=lambda s: s[0], reverse=True)
        redacted = text
        for start, end in spans:
            redacted = redacted[:start] + "[REDACTED]" + redacted[end:]

        return redacted, result.flagged

    def wrap_message(self, message: str) -> ProtocolMessage:
        """Scan and redact, then delegate to inner protocol."""
        redacted, flagged = self._redact(message)
        proto_msg = self._inner.wrap_message(redacted)
        # Store original + redaction metadata for verification
        proto_msg.challenge_data["_clean_flagged"] = flagged
        proto_msg.challenge_data["_clean_original"] = message
        return proto_msg

    def build_system_prompt(self, challenge_data: dict) -> str:
        return self._inner.build_system_prompt(challenge_data)

    def verify_response(self, response: str, expected: ProtocolMessage) -> VerificationResult:
        """Verify via inner protocol only. Clean acts as input filter."""
        return self._inner.verify_response(response, expected)
