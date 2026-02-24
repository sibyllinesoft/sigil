"""Full benchmark: each protocol x each attack x each provider."""

import json
from pathlib import Path

import pytest

from sigil.attacks.catalog import get_all_payloads
from sigil.evaluation.metrics import BenchmarkMetrics
from sigil.evaluation.runner import BenchmarkRunner, RunConfig
from sigil.evaluation.reporter import Reporter
from sigil.protocols import ALL_PROTOCOLS
from sigil.protocols.none import NoneProtocol
from sigil.providers.mock import MockProvider

# Protocols that actually verify responses (excludes NoneProtocol)
VERIFYING_PROTOCOLS = [cls for cls in ALL_PROTOCOLS if cls is not NoneProtocol]

RESULTS_DIR = Path(__file__).parent / "results"


@pytest.mark.mock
@pytest.mark.asyncio
async def test_mock_compliant_benchmark():
    """Full benchmark with compliant mock provider.

    Expects: 100% protocol compliance, 0% false positives.
    """
    provider = MockProvider(compliant=True)
    protocols = [cls() for cls in ALL_PROTOCOLS]
    attacks = get_all_payloads()

    config = RunConfig(protocols=protocols, attacks=attacks, providers=[provider])
    runner = BenchmarkRunner(config)
    results = await runner.run_all()

    reporter = Reporter(results)
    metrics = reporter.compute_metrics()

    # With compliant mock, clean trials should all pass
    assert metrics.protocol_compliance_rate == 1.0, (
        f"Mock compliance {metrics.protocol_compliance_rate:.1%} != 100%"
    )
    assert metrics.false_positive_rate == 0.0, (
        f"Mock FP rate {metrics.false_positive_rate:.1%} != 0%"
    )

    # Save results
    reporter.save_json(RESULTS_DIR / "mock_compliant.json")
    print("\n" + reporter.format_terminal())


@pytest.mark.mock
@pytest.mark.asyncio
async def test_mock_noncompliant_benchmark():
    """Full benchmark with noncompliant mock provider.

    Expects: 100% detection rate (all responses violate protocol).
    Uses only verifying protocols (excludes NoneProtocol which always passes).
    """
    provider = MockProvider(compliant=False)
    protocols = [cls() for cls in VERIFYING_PROTOCOLS]
    attacks = get_all_payloads()

    config = RunConfig(protocols=protocols, attacks=attacks, providers=[provider])
    runner = BenchmarkRunner(config)
    results = await runner.run_all()

    reporter = Reporter(results)
    metrics = reporter.compute_metrics()

    # With noncompliant mock, all attack trials should be detected
    assert metrics.detection_rate == 1.0, (
        f"Noncompliant detection {metrics.detection_rate:.1%} != 100%"
    )
    # Clean trials should also fail (noncompliant ignores protocol)
    assert metrics.protocol_compliance_rate == 0.0, (
        f"Noncompliant compliance {metrics.protocol_compliance_rate:.1%} != 0%"
    )

    reporter.save_json(RESULTS_DIR / "mock_noncompliant.json")
    print("\n" + reporter.format_terminal())


@pytest.mark.mock
@pytest.mark.asyncio
async def test_benchmark_per_protocol_metrics():
    """Verify per-protocol metrics computation."""
    provider = MockProvider(compliant=True)
    protocols = [cls() for cls in ALL_PROTOCOLS]
    attacks = get_all_payloads()

    config = RunConfig(protocols=protocols, attacks=attacks, providers=[provider])
    runner = BenchmarkRunner(config)
    results = await runner.run_all()

    reporter = Reporter(results)
    by_protocol = reporter.compute_metrics_by_protocol()

    assert len(by_protocol) == len(ALL_PROTOCOLS)
    for name, metrics in by_protocol.items():
        assert metrics.total_trials > 0, f"Protocol {name} had no trials"
        assert metrics.protocol_compliance_rate == 1.0, (
            f"Protocol {name} compliance {metrics.protocol_compliance_rate:.1%}"
        )


@pytest.mark.mock
@pytest.mark.asyncio
async def test_benchmark_per_category_metrics():
    """Verify per-category metrics computation."""
    provider = MockProvider(compliant=True)
    protocols = [cls() for cls in ALL_PROTOCOLS]
    attacks = get_all_payloads()

    config = RunConfig(protocols=protocols, attacks=attacks, providers=[provider])
    runner = BenchmarkRunner(config)
    results = await runner.run_all()

    reporter = Reporter(results)
    by_category = reporter.compute_metrics_by_category()

    # Should have all 9 attack categories + "clean"
    assert "clean" in by_category
    assert len(by_category) >= 10  # 9 categories + clean
