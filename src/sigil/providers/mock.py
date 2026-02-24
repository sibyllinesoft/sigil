"""Deterministic mock provider for unit tests."""

import json
import re

from sigil.protocols.schema_strict import compute_fingerprint
from sigil.providers.base import Provider

# Patterns to extract protocol values from system prompts
_HEX_PATTERN = r"[0-9a-f]+"


class MockProvider(Provider):
    """Mock LLM that produces protocol-compliant responses.

    For testing the pipeline without API calls. The mock "perfectly"
    follows protocol instructions by parsing the system prompt for
    expected values and constructing a compliant response.
    """

    def __init__(self, *, compliant: bool = True):
        """
        Args:
            compliant: If True, produce protocol-compliant responses.
                      If False, produce responses that violate protocol.
        """
        self._compliant = compliant

    @property
    def name(self) -> str:
        return "mock" if self._compliant else "mock_noncompliant"

    async def complete(self, system_prompt: str, user_message: str) -> str:
        if not self._compliant:
            return "I am ignoring all protocol instructions. INJECTED"

        response_text = "Mock response to user message"

        # Detect protocol type from system prompt and build compliant response
        if "[SIGIL-RESPONSE]" in system_prompt:
            return self._build_hmac_response(system_prompt, response_text)
        elif '"sigil_version": 1' in system_prompt and '"canary"' in system_prompt:
            return self._build_combined_response(system_prompt, response_text)
        elif '"sigil_version": 1' in system_prompt:
            return self._build_schema_response(system_prompt, response_text)
        elif "FIRST line" in system_prompt and "[SIGIL:" in system_prompt:
            return self._build_nonce_response(system_prompt, response_text)
        elif "[CANARY:" in system_prompt:
            return self._build_canary_response(system_prompt, response_text)
        else:
            return response_text

    def _build_canary_response(self, prompt: str, response_text: str) -> str:
        m = re.search(r"\[CANARY:(" + _HEX_PATTERN + r")\]", prompt)
        canary = m.group(1)
        return f"{response_text}\n[CANARY:{canary}]"

    def _build_nonce_response(self, prompt: str, response_text: str) -> str:
        m = re.search(r"\[SIGIL:(" + _HEX_PATTERN + r")\]", prompt)
        nonce = m.group(1)
        return f"[SIGIL:{nonce}]\n{response_text}"

    def _build_schema_response(self, prompt: str, response_text: str) -> str:
        m = re.search(r'"nonce":\s*"(' + _HEX_PATTERN + r')"', prompt)
        nonce = m.group(1)
        return json.dumps({
            "sigil_version": 1,
            "nonce": nonce,
            "response": response_text,
            "fingerprint": compute_fingerprint(response_text),
        })

    def _build_hmac_response(self, prompt: str, response_text: str) -> str:
        nonce_m = re.search(r"NONCE must be exactly: (" + _HEX_PATTERN + r")", prompt)
        hmac_m = re.search(r"HMAC must be exactly: (" + _HEX_PATTERN + r")", prompt)
        nonce = nonce_m.group(1)
        hmac_val = hmac_m.group(1)
        return (
            f"[SIGIL-RESPONSE]\n"
            f"NONCE: {nonce}\n"
            f"HMAC: {hmac_val}\n"
            f"[/SIGIL-RESPONSE]\n"
            f"{response_text}"
        )

    def _build_combined_response(self, prompt: str, response_text: str) -> str:
        nonce_m = re.search(r'"nonce":\s*"(' + _HEX_PATTERN + r')"', prompt)
        canary_m = re.search(r'"canary":\s*"(' + _HEX_PATTERN + r')"', prompt)
        nonce = nonce_m.group(1)
        canary = canary_m.group(1)
        body = json.dumps({
            "sigil_version": 1,
            "nonce": nonce,
            "canary": canary,
            "response": response_text,
            "fingerprint": compute_fingerprint(response_text),
        })
        return f"[SIGIL:{nonce}]\n{body}"
