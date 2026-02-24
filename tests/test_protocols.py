"""Unit tests for protocol logic (no LLM calls)."""

import json

import pytest

from sigil.protocol import ProtocolMessage
from sigil.protocols.canary import CanaryProtocol
from sigil.protocols.nonce_echo import NonceEchoProtocol
from sigil.protocols.schema_strict import SchemaStrictProtocol, compute_fingerprint
from sigil.protocols.hmac_challenge import HMACChallengeProtocol
from sigil.protocols.combined import CombinedProtocol


class TestCanaryProtocol:
    def test_wrap_message(self, canary_protocol):
        msg = canary_protocol.wrap_message("Hello world")
        assert msg.original_message == "Hello world"
        assert "[CANARY:" in msg.wrapped_message
        assert "canary" in msg.challenge_data
        assert len(msg.challenge_data["canary"]) == 16

    def test_verify_correct_response(self, canary_protocol):
        msg = canary_protocol.wrap_message("test")
        canary = msg.challenge_data["canary"]
        response = f"Here is my response.\n[CANARY:{canary}]"
        result = canary_protocol.verify_response(response, msg)
        assert result.passed
        assert result.violations == []

    def test_verify_missing_canary(self, canary_protocol):
        msg = canary_protocol.wrap_message("test")
        result = canary_protocol.verify_response("No canary here", msg)
        assert not result.passed
        assert len(result.violations) > 0

    def test_verify_wrong_canary(self, canary_protocol):
        msg = canary_protocol.wrap_message("test")
        result = canary_protocol.verify_response("Response\n[CANARY:deadbeefdeadbeef]", msg)
        assert not result.passed

    def test_verify_canary_not_at_end(self, canary_protocol):
        msg = canary_protocol.wrap_message("test")
        canary = msg.challenge_data["canary"]
        response = f"[CANARY:{canary}]\nExtra text after"
        result = canary_protocol.verify_response(response, msg)
        assert not result.passed

    def test_system_prompt_contains_canary(self, canary_protocol):
        msg = canary_protocol.wrap_message("test")
        prompt = canary_protocol.build_system_prompt(msg.challenge_data)
        assert msg.challenge_data["canary"] in prompt


class TestNonceEchoProtocol:
    def test_wrap_message(self, nonce_protocol):
        msg = nonce_protocol.wrap_message("Hello")
        assert msg.original_message == "Hello"
        assert "nonce" in msg.challenge_data
        assert len(msg.challenge_data["nonce"]) == 24

    def test_verify_correct_response(self, nonce_protocol):
        msg = nonce_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        response = f"[SIGIL:{nonce}]\nHere is the response."
        result = nonce_protocol.verify_response(response, msg)
        assert result.passed

    def test_verify_missing_nonce(self, nonce_protocol):
        msg = nonce_protocol.wrap_message("test")
        result = nonce_protocol.verify_response("No nonce here", msg)
        assert not result.passed

    def test_verify_nonce_wrong_position(self, nonce_protocol):
        msg = nonce_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        response = f"Some text first\n[SIGIL:{nonce}]"
        result = nonce_protocol.verify_response(response, msg)
        assert not result.passed


class TestFingerprint:
    def test_basic(self):
        assert compute_fingerprint("The quick brown fox") == "4:The:fox"

    def test_single_word(self):
        assert compute_fingerprint("Hello") == "1:Hello:Hello"

    def test_empty(self):
        assert compute_fingerprint("") == "0::"

    def test_two_words(self):
        assert compute_fingerprint("Hello world") == "2:Hello:world"


class TestSchemaStrictProtocol:
    def test_wrap_message(self, schema_protocol):
        msg = schema_protocol.wrap_message("test")
        assert "nonce" in msg.challenge_data

    def test_verify_correct_response(self, schema_protocol):
        msg = schema_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        response_text = "This is my response"
        fp = compute_fingerprint(response_text)
        response = json.dumps({
            "sigil_version": 1,
            "nonce": nonce,
            "response": response_text,
            "fingerprint": fp,
        })
        result = schema_protocol.verify_response(response, msg)
        assert result.passed, f"Violations: {result.violations}"

    def test_verify_invalid_json(self, schema_protocol):
        msg = schema_protocol.wrap_message("test")
        result = schema_protocol.verify_response("not json at all", msg)
        assert not result.passed
        assert any("not valid JSON" in v for v in result.violations)

    def test_verify_missing_fields(self, schema_protocol):
        msg = schema_protocol.wrap_message("test")
        result = schema_protocol.verify_response('{"sigil_version": 1}', msg)
        assert not result.passed

    def test_verify_wrong_version(self, schema_protocol):
        msg = schema_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        response = json.dumps({
            "sigil_version": 2,
            "nonce": nonce,
            "response": "test",
            "fingerprint": "1:test:test",
        })
        result = schema_protocol.verify_response(response, msg)
        assert not result.passed

    def test_verify_wrong_fingerprint(self, schema_protocol):
        msg = schema_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        response = json.dumps({
            "sigil_version": 1,
            "nonce": nonce,
            "response": "three word response",
            "fingerprint": "99:wrong:wrong",
        })
        result = schema_protocol.verify_response(response, msg)
        assert not result.passed
        assert any("Fingerprint" in v or "fingerprint" in v for v in result.violations)

    def test_verify_correct_fingerprint(self, schema_protocol):
        msg = schema_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        response = json.dumps({
            "sigil_version": 1,
            "nonce": nonce,
            "response": "three word response",
            "fingerprint": "3:three:response",
        })
        result = schema_protocol.verify_response(response, msg)
        assert result.passed


class TestHMACChallengeProtocol:
    def test_wrap_message(self, hmac_protocol):
        msg = hmac_protocol.wrap_message("test")
        assert "nonce" in msg.challenge_data
        assert "secret" in msg.challenge_data
        assert "expected_hmac" in msg.challenge_data

    def test_verify_correct_response(self, hmac_protocol):
        msg = hmac_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        expected_hmac = msg.challenge_data["expected_hmac"]
        response = (
            f"[SIGIL-RESPONSE]\n"
            f"NONCE: {nonce}\n"
            f"HMAC: {expected_hmac}\n"
            f"[/SIGIL-RESPONSE]\n"
            f"Here is the answer."
        )
        result = hmac_protocol.verify_response(response, msg)
        assert result.passed, f"Violations: {result.violations}"

    def test_verify_missing_header(self, hmac_protocol):
        msg = hmac_protocol.wrap_message("test")
        result = hmac_protocol.verify_response("No header here", msg)
        assert not result.passed

    def test_verify_wrong_hmac(self, hmac_protocol):
        msg = hmac_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        response = (
            f"[SIGIL-RESPONSE]\n"
            f"NONCE: {nonce}\n"
            f"HMAC: wrong_hmac_value\n"
            f"[/SIGIL-RESPONSE]\n"
            f"Answer"
        )
        result = hmac_protocol.verify_response(response, msg)
        assert not result.passed

    def test_hmac_deterministic(self, hmac_protocol):
        """Same nonce + secret should produce same HMAC."""
        hmac1 = HMACChallengeProtocol.compute_hmac("nonce123", "secret")
        hmac2 = HMACChallengeProtocol.compute_hmac("nonce123", "secret")
        assert hmac1 == hmac2
        # Different nonce should produce different HMAC
        hmac3 = HMACChallengeProtocol.compute_hmac("nonce456", "secret")
        assert hmac1 != hmac3


class TestCombinedProtocol:
    def test_wrap_message(self, combined_protocol):
        msg = combined_protocol.wrap_message("test")
        assert "nonce" in msg.challenge_data
        assert "canary" in msg.challenge_data

    def test_verify_correct_response(self, combined_protocol):
        msg = combined_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        canary = msg.challenge_data["canary"]
        response_text = "The answer is here"
        fp = compute_fingerprint(response_text)
        body = json.dumps({
            "sigil_version": 1,
            "nonce": nonce,
            "canary": canary,
            "response": response_text,
            "fingerprint": fp,
        })
        response = f"[SIGIL:{nonce}]\n{body}"
        result = combined_protocol.verify_response(response, msg)
        assert result.passed, f"Violations: {result.violations}"

    def test_verify_wrong_nonce_prefix(self, combined_protocol):
        msg = combined_protocol.wrap_message("test")
        canary = msg.challenge_data["canary"]
        body = json.dumps({
            "sigil_version": 1,
            "nonce": "wrong",
            "canary": canary,
            "response": "test",
            "fingerprint": "1:test:test",
        })
        response = f"[SIGIL:wrong]\n{body}"
        result = combined_protocol.verify_response(response, msg)
        assert not result.passed

    def test_verify_missing_canary(self, combined_protocol):
        msg = combined_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        body = json.dumps({
            "sigil_version": 1,
            "nonce": nonce,
            "canary": "wrong_canary",
            "response": "test",
            "fingerprint": "1:test:test",
        })
        response = f"[SIGIL:{nonce}]\n{body}"
        result = combined_protocol.verify_response(response, msg)
        assert not result.passed

    def test_verify_no_json_body(self, combined_protocol):
        msg = combined_protocol.wrap_message("test")
        nonce = msg.challenge_data["nonce"]
        result = combined_protocol.verify_response(f"[SIGIL:{nonce}]", msg)
        assert not result.passed


class TestMockProviderCompliance:
    """Test that mock provider produces compliant responses for all protocols."""

    @pytest.mark.asyncio
    async def test_canary_compliance(self, canary_protocol, mock_provider):
        msg = canary_protocol.wrap_message("test message")
        prompt = canary_protocol.build_system_prompt(msg.challenge_data)
        response = await mock_provider.complete(prompt, msg.wrapped_message)
        result = canary_protocol.verify_response(response, msg)
        assert result.passed, f"Mock failed canary: {result.violations}"

    @pytest.mark.asyncio
    async def test_nonce_compliance(self, nonce_protocol, mock_provider):
        msg = nonce_protocol.wrap_message("test message")
        prompt = nonce_protocol.build_system_prompt(msg.challenge_data)
        response = await mock_provider.complete(prompt, msg.wrapped_message)
        result = nonce_protocol.verify_response(response, msg)
        assert result.passed, f"Mock failed nonce: {result.violations}"

    @pytest.mark.asyncio
    async def test_schema_compliance(self, schema_protocol, mock_provider):
        msg = schema_protocol.wrap_message("test message")
        prompt = schema_protocol.build_system_prompt(msg.challenge_data)
        response = await mock_provider.complete(prompt, msg.wrapped_message)
        result = schema_protocol.verify_response(response, msg)
        assert result.passed, f"Mock failed schema: {result.violations}"

    @pytest.mark.asyncio
    async def test_hmac_compliance(self, hmac_protocol, mock_provider):
        msg = hmac_protocol.wrap_message("test message")
        prompt = hmac_protocol.build_system_prompt(msg.challenge_data)
        response = await mock_provider.complete(prompt, msg.wrapped_message)
        result = hmac_protocol.verify_response(response, msg)
        assert result.passed, f"Mock failed hmac: {result.violations}"

    @pytest.mark.asyncio
    async def test_combined_compliance(self, combined_protocol, mock_provider):
        msg = combined_protocol.wrap_message("test message")
        prompt = combined_protocol.build_system_prompt(msg.challenge_data)
        response = await mock_provider.complete(prompt, msg.wrapped_message)
        result = combined_protocol.verify_response(response, msg)
        assert result.passed, f"Mock failed combined: {result.violations}"
