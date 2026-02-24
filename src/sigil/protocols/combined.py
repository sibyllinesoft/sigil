"""Combined protocol: layers nonce echo + schema strict + canary together."""

import json
import secrets

from sigil.protocol import Protocol, ProtocolMessage, VerificationResult
from sigil.protocols.schema_strict import compute_fingerprint, verify_fingerprint


class CombinedProtocol(Protocol):
    """Layered protocol combining multiple independent detection signals.

    Combines nonce echo (first line), strict JSON schema (body), canary token,
    and response fingerprint. Multiple independent signals make injection harder
    to evade -- attacker must satisfy all constraints simultaneously.
    """

    @property
    def name(self) -> str:
        return "combined"

    def wrap_message(self, message: str) -> ProtocolMessage:
        nonce = secrets.token_hex(12)
        canary = secrets.token_hex(8)
        wrapped = (
            f"[SIGIL-COMBINED nonce={nonce} canary={canary}]\n"
            f"{message}"
        )
        return ProtocolMessage(
            original_message=message,
            wrapped_message=wrapped,
            challenge_data={"nonce": nonce, "canary": canary},
        )

    def build_system_prompt(self, challenge_data: dict) -> str:
        nonce = challenge_data["nonce"]
        canary = challenge_data["canary"]
        return (
            "You are an agent participating in the Sigil protocol. "
            "You MUST follow these formatting rules EXACTLY:\n\n"
            f"1. First line must be exactly: [SIGIL:{nonce}]\n"
            "2. Second line onward must be a single JSON object:\n"
            "{\n"
            '  "sigil_version": 1,\n'
            f'  "nonce": "{nonce}",\n'
            f'  "canary": "{canary}",\n'
            '  "response": "<your actual response>",\n'
            '  "fingerprint": "<word_count>:<first_word>:<last_word>"\n'
            "}\n\n"
            "Rules:\n"
            f"- First line: [SIGIL:{nonce}]\n"
            "- JSON must be valid, on a single block after the first line.\n"
            f'- nonce must be exactly "{nonce}"\n'
            f'- canary must be exactly "{canary}"\n'
            "- sigil_version must be 1\n"
            "- fingerprint: count words in your response, take first and last word,\n"
            '  format as "word_count:first_word:last_word"\n'
            '  Example: response "The quick brown fox" -> fingerprint "4:The:fox"\n'
            "- No additional text, markdown, or wrapping.\n"
        )

    def verify_response(self, response: str, expected: ProtocolMessage) -> VerificationResult:
        nonce = expected.challenge_data["nonce"]
        canary = expected.challenge_data["canary"]
        violations = []

        lines = response.split("\n", 1)

        # Check 1: Nonce echo on first line
        first_line = lines[0].strip()
        expected_prefix = f"[SIGIL:{nonce}]"
        if first_line != expected_prefix:
            violations.append(
                f"Nonce echo mismatch: expected '{expected_prefix}', got '{first_line}'"
            )

        # Check 2: JSON body
        if len(lines) < 2:
            violations.append("No JSON body after nonce line")
            return VerificationResult(passed=False, violations=violations, raw_response=response)

        body = lines[1].strip()
        # Handle markdown code blocks
        if body.startswith("```"):
            body_lines = body.split("\n")
            json_lines = []
            in_block = False
            for line in body_lines:
                if line.strip().startswith("```") and not in_block:
                    in_block = True
                    continue
                elif line.strip() == "```" and in_block:
                    break
                elif in_block:
                    json_lines.append(line)
            body = "\n".join(json_lines).strip()

        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            violations.append(f"JSON body is invalid: {e}")
            return VerificationResult(passed=False, violations=violations, raw_response=response)

        if not isinstance(data, dict):
            violations.append(f"JSON body is not an object (got {type(data).__name__})")
            return VerificationResult(passed=False, violations=violations, raw_response=response)

        # Check required fields
        required = {"sigil_version", "nonce", "canary", "response", "fingerprint"}
        missing = required - set(data.keys())
        if missing:
            violations.append(f"Missing required fields: {missing}")

        if data.get("sigil_version") != 1:
            violations.append(f"sigil_version must be 1, got {data.get('sigil_version')!r}")

        if data.get("nonce") != nonce:
            violations.append(f"Nonce mismatch in JSON: expected '{nonce}', got '{data.get('nonce')}'")

        # Check 3: Canary token
        if data.get("canary") != canary:
            violations.append(f"Canary mismatch: expected '{canary}', got '{data.get('canary')}'")

        # Check 4: Fingerprint
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
