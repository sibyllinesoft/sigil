"""Benchmark fixtures and configuration."""

import pytest

from sigil.attacks.catalog import get_all_payloads
from sigil.protocols import ALL_PROTOCOLS
from sigil.providers.mock import MockProvider


@pytest.fixture
def all_protocols():
    """All protocol instances."""
    return [cls() for cls in ALL_PROTOCOLS]


@pytest.fixture
def all_attacks():
    """All attack payloads."""
    return get_all_payloads()


@pytest.fixture
def mock_provider():
    return MockProvider(compliant=True)


@pytest.fixture
def noncompliant_provider():
    return MockProvider(compliant=False)
