"""Results formatting: terminal tables and JSON output."""

import json
from dataclasses import asdict
from pathlib import Path

from sigil.evaluation.metrics import BenchmarkMetrics, TrialResult


class Reporter:
    """Formats and outputs benchmark results."""

    def __init__(self, results: list[TrialResult]):
        self.results = results

    def compute_metrics(self) -> BenchmarkMetrics:
        """Compute aggregate metrics."""
        return BenchmarkMetrics.compute(self.results)

    def compute_metrics_by_protocol(self) -> dict[str, BenchmarkMetrics]:
        """Compute metrics grouped by protocol."""
        by_protocol: dict[str, list[TrialResult]] = {}
        for r in self.results:
            by_protocol.setdefault(r.protocol_name, []).append(r)
        return {name: BenchmarkMetrics.compute(rs) for name, rs in by_protocol.items()}

    def compute_metrics_by_category(self) -> dict[str, BenchmarkMetrics]:
        """Compute metrics grouped by attack category."""
        by_category: dict[str, list[TrialResult]] = {}
        for r in self.results:
            key = r.attack_category or "clean"
            by_category.setdefault(key, []).append(r)
        return {name: BenchmarkMetrics.compute(rs) for name, rs in by_category.items()}

    def format_terminal(self) -> str:
        """Format results as a terminal-friendly table."""
        overall = self.compute_metrics()
        by_protocol = self.compute_metrics_by_protocol()

        lines = [
            "=" * 80,
            "SIGIL BENCHMARK RESULTS",
            "=" * 80,
            "",
            f"Total trials: {overall.total_trials}",
            f"  Attack trials:      {overall.total_attack_trials}",
            f"  Clean trials:       {overall.total_clean_trials}",
            f"  Propagation trials: {overall.total_propagation_trials}",
            "",
            "OVERALL METRICS:",
            f"  Detection Rate:          {overall.detection_rate:.1%}",
            f"  False Positive Rate:     {overall.false_positive_rate:.1%}",
            f"  Attack Success Rate:     {overall.attack_success_rate:.1%}",
            f"  Propagation Rate:        {overall.propagation_rate:.1%}",
            f"  Protocol Compliance:     {overall.protocol_compliance_rate:.1%}",
            "",
            "-" * 80,
            f"{'Protocol':<18} {'Detect%':>8} {'FP%':>6} {'ASR%':>6} {'Prop%':>6} {'Comply%':>8}",
            "-" * 80,
        ]

        for name, m in sorted(by_protocol.items()):
            prop = f"{m.propagation_rate:>5.1%}" if m.total_propagation_trials else "  n/a"
            lines.append(
                f"{name:<18} {m.detection_rate:>7.1%} {m.false_positive_rate:>5.1%} "
                f"{m.attack_success_rate:>5.1%} {prop:>6} {m.protocol_compliance_rate:>7.1%}"
            )

        lines.append("-" * 80)
        return "\n".join(lines)

    def to_json(self) -> dict:
        """Convert results to JSON-serializable dict."""
        overall = self.compute_metrics()
        by_protocol = self.compute_metrics_by_protocol()
        by_category = self.compute_metrics_by_category()

        return {
            "overall": asdict(overall),
            "by_protocol": {k: asdict(v) for k, v in by_protocol.items()},
            "by_category": {k: asdict(v) for k, v in by_category.items()},
            "trials": [
                {
                    "protocol": r.protocol_name,
                    "attack_id": r.attack_id,
                    "attack_category": r.attack_category,
                    "attack_objective": r.attack_objective,
                    "provider": r.provider_name,
                    "protocol_passed": r.protocol_passed,
                    "violations": r.violations,
                    "attack_succeeded": r.attack_succeeded,
                    "propagation_detected": r.propagation_detected,
                    "raw_response": r.raw_response,
                    "error": r.error,
                }
                for r in self.results
            ],
        }

    def save_json(self, path: Path) -> None:
        """Save results as JSON to a file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_json(), indent=2))
