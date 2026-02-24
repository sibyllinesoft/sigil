"""Schema Strict protocol: agent must respond in a strict JSON schema."""

import json
import secrets

from sigil.protocol import Protocol, ProtocolMessage, VerificationResult


def compute_fingerprint(text: str) -> str:
    """Compute a response fingerprint: 'word_count:first_word:last_word'.

    Designed to be computable by an LLM but tightly coupled to the response
    content -- if injection alters the response, the fingerprint breaks.
    """
    words = text.split()
    if not words:
        return "0::"
    return f"{len(words)}:{words[0]}:{words[-1]}"


def _strip_punctuation(word: str) -> str:
    """Strip leading/trailing punctuation from a word for fuzzy matching."""
    return word.strip(".,;:!?\"'`()[]{}…—-")


def verify_fingerprint(response_text: str, claimed_fp: str) -> list[str]:
    """Verify fingerprint components independently.

    First/last word use punctuation-stripped comparison (LLMs often strip
    or include trailing periods inconsistently). Word count uses a tolerance
    of 20% or 3, whichever is larger, since LLMs miscount more on longer text.

    Returns a list of violation strings (empty = passed).
    """
    violations = []
    parts = claimed_fp.split(":", 2)
    if len(parts) != 3:
        violations.append(
            f"Fingerprint format invalid: expected 'count:first:last', got '{claimed_fp}'"
        )
        return violations

    claimed_count_str, claimed_first, claimed_last = parts
    words = response_text.split()
    actual_count = len(words)
    actual_first = words[0] if words else ""
    actual_last = words[-1] if words else ""

    try:
        claimed_count = int(claimed_count_str)
    except ValueError:
        violations.append(f"Fingerprint word count not an integer: '{claimed_count_str}'")
        return violations

    # Tolerance: 30% of actual count or 3, whichever is larger
    tolerance = max(3, int(actual_count * 0.3))
    if abs(claimed_count - actual_count) > tolerance:
        violations.append(
            f"Fingerprint word count off: claimed {claimed_count}, "
            f"actual {actual_count} (tolerance {tolerance})"
        )

    # Punctuation-stripped comparison for first/last word
    if _strip_punctuation(claimed_first) != _strip_punctuation(actual_first):
        violations.append(
            f"Fingerprint first word mismatch: claimed '{claimed_first}', "
            f"actual '{actual_first}'"
        )

    if _strip_punctuation(claimed_last) != _strip_punctuation(actual_last):
        violations.append(
            f"Fingerprint last word mismatch: claimed '{claimed_last}', "
            f"actual '{actual_last}'"
        )

    return violations


class SchemaStrictProtocol(Protocol):
    """Enforce a strict JSON response schema with fingerprint verification.

    Agent must respond with:
    {"sigil_version": 1, "nonce": "<echo>", "response": "<content>",
     "fingerprint": "<word_count>:<first_word>:<last_word>"}

    Any parse failure, missing field, or fingerprint mismatch = detection.
    """

    REQUIRED_FIELDS = {"sigil_version", "nonce", "response", "fingerprint"}

    @property
    def name(self) -> str:
        return "schema_strict"

    def wrap_message(self, message: str) -> ProtocolMessage:
        nonce = secrets.token_hex(8)
        wrapped = (
            f"[SIGIL-SCHEMA nonce={nonce}]\n"
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
            "You MUST respond with ONLY a JSON object matching this exact schema:\n\n"
            "{\n"
            '  "sigil_version": 1,\n'
            f'  "nonce": "{nonce}",\n'
            '  "response": "<your actual response text here>",\n'
            '  "fingerprint": "<word_count>:<first_word>:<last_word>"\n'
            "}\n\n"
            "Rules:\n"
            "1. Output ONLY the JSON object. No markdown, no explanation, no wrapping.\n"
            "2. sigil_version must be exactly 1 (integer).\n"
            f'3. nonce must be exactly "{nonce}".\n'
            "4. response contains your actual answer to the message.\n"
            "5. fingerprint is derived from your response field:\n"
            "   - Count the words in your response (split on whitespace)\n"
            "   - Take the first word and the last word\n"
            "   - Format: word_count:first_word:last_word\n"
            '   - Example: if response is "The quick brown fox", fingerprint is "4:The:fox"\n'
            '   - Example: if response is "Hello", fingerprint is "1:Hello:Hello"\n'
        )

    def verify_response(self, response: str, expected: ProtocolMessage) -> VerificationResult:
        nonce = expected.challenge_data["nonce"]
        violations = []

        # Try to extract JSON from the response
        stripped = response.strip()
        # Handle markdown code blocks
        if stripped.startswith("```"):
            lines = stripped.split("\n")
            json_lines = []
            in_block = False
            for line in lines:
                if line.strip().startswith("```") and not in_block:
                    in_block = True
                    continue
                elif line.strip() == "```" and in_block:
                    break
                elif in_block:
                    json_lines.append(line)
            stripped = "\n".join(json_lines).strip()

        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as e:
            violations.append(f"Response is not valid JSON: {e}")
            return VerificationResult(passed=False, violations=violations, raw_response=response)

        if not isinstance(data, dict):
            violations.append(f"Response is not a JSON object (got {type(data).__name__})")
            return VerificationResult(passed=False, violations=violations, raw_response=response)

        missing = self.REQUIRED_FIELDS - set(data.keys())
        if missing:
            violations.append(f"Missing required fields: {missing}")

        if data.get("sigil_version") != 1:
            violations.append(
                f"sigil_version must be 1, got {data.get('sigil_version')!r}"
            )

        if data.get("nonce") != nonce:
            violations.append(
                f"Nonce mismatch: expected '{nonce}', got '{data.get('nonce')}'"
            )

        # Verify fingerprint components independently
        # Word count gets tolerance (LLMs miscount), first/last word are exact
        if "response" in data and "fingerprint" in data:
            fp_violations = verify_fingerprint(
                str(data["response"]), str(data.get("fingerprint", ""))
            )
            violations.extend(fp_violations)

        return VerificationResult(
            passed=len(violations) == 0,
            violations=violations,
            raw_response=response,
        )
