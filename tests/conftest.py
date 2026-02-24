"""Shared test fixtures."""

import pytest

from sigil.protocols.canary import CanaryProtocol
from sigil.protocols.nonce_echo import NonceEchoProtocol
from sigil.protocols.schema_strict import SchemaStrictProtocol
from sigil.protocols.hmac_challenge import HMACChallengeProtocol
from sigil.protocols.combined import CombinedProtocol
from sigil.providers.mock import MockProvider


@pytest.fixture
def canary_protocol():
    return CanaryProtocol()


@pytest.fixture
def nonce_protocol():
    return NonceEchoProtocol()


@pytest.fixture
def schema_protocol():
    return SchemaStrictProtocol()


@pytest.fixture
def hmac_protocol():
    return HMACChallengeProtocol(secret="test_secret_key")


@pytest.fixture
def combined_protocol():
    return CombinedProtocol()


@pytest.fixture
def mock_provider():
    return MockProvider(compliant=True)


@pytest.fixture
def noncompliant_provider():
    return MockProvider(compliant=False)
