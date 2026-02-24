"""CLI entry point for running Sigil benchmarks."""

import argparse
import asyncio
import sys
import time
from pathlib import Path

from sigil.attacks.catalog import get_all_payloads, get_payloads_by_category
from sigil.attacks.categories import AttackCategory
from sigil.evaluation.reporter import Reporter
from sigil.evaluation.runner import BenchmarkRunner, RunConfig
from sigil.protocols import ALL_PROTOCOLS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="sigil",
        description="Sigil: prompt injection detection benchmark",
    )
    p.add_argument(
        "--provider",
        choices=["claude-code", "anthropic", "openai", "zai", "mock"],
        default="claude-code",
        help="LLM provider (default: claude-code)",
    )
    p.add_argument(
        "--model",
        default="haiku",
        help="Model ID (default: haiku)",
    )
    p.add_argument(
        "--protocol",
        nargs="*",
        help="Protocols to run. Options: canary, nonce_echo, schema_strict, "
             "hmac_challenge, combined. Prefix with 'clean+' for Clean pre-filter "
             "(e.g. clean+schema_strict). Default: all base protocols.",
    )
    p.add_argument(
        "--category",
        nargs="*",
        choices=[c.value for c in AttackCategory],
        help="Run only specific attack categories (default: all)",
    )
    p.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Max concurrent API calls (default: 5)",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=Path("benchmarks/results/benchmark.json"),
        help="JSON output path (default: benchmarks/results/benchmark.json)",
    )
    p.add_argument(
        "--max-tokens",
        type=int,
        default=1024,
        help="Max tokens per response (default: 1024)",
    )
    p.add_argument(
        "--clean-only",
        action="store_true",
        help="Run only clean (no-attack) trials to measure false positive rate",
    )
    return p


def make_provider(args: argparse.Namespace):
    match args.provider:
        case "claude-code":
            from sigil.providers.claude_code import ClaudeCodeProvider
            return ClaudeCodeProvider(model=args.model, max_tokens=args.max_tokens)
        case "anthropic":
            from sigil.providers.anthropic import AnthropicProvider
            return AnthropicProvider(model=args.model, max_tokens=args.max_tokens)
        case "openai":
            from sigil.providers.openai import OpenAIProvider
            return OpenAIProvider(model=args.model, max_tokens=args.max_tokens)
        case "zai":
            from sigil.providers.zai import ZAIProvider
            return ZAIProvider(model=args.model, max_tokens=args.max_tokens)
        case "mock":
            from sigil.providers.mock import MockProvider
            return MockProvider(compliant=True)


def make_protocols(args: argparse.Namespace):
    from sigil.protocols.clean_filtered import CleanFilteredProtocol

    if not args.protocol:
        return [cls() for cls in ALL_PROTOCOLS]

    name_to_cls = {cls().name: cls for cls in ALL_PROTOCOLS}
    result = []
    for name in args.protocol:
        if name.startswith("clean+"):
            inner_name = name[len("clean+"):]
            inner = name_to_cls[inner_name]()
            result.append(CleanFilteredProtocol(inner))
        else:
            result.append(name_to_cls[name]())
    return result


def make_attacks(args: argparse.Namespace):
    if args.clean_only:
        return []
    if not args.category:
        return get_all_payloads()
    payloads = []
    for cat_name in args.category:
        cat = AttackCategory(cat_name)
        payloads.extend(get_payloads_by_category(cat))
    return payloads


def log(msg: str):
    print(msg, file=sys.stderr)


async def run_benchmark(args: argparse.Namespace):
    provider = make_provider(args)
    protocols = make_protocols(args)
    attacks = make_attacks(args)

    n_clean = len(protocols) * 5  # 5 benign messages per protocol
    n_attack = len(protocols) * len(attacks)
    total = n_clean + n_attack

    log(f"Sigil benchmark")
    log(f"  Provider:    {provider.name}")
    log(f"  Protocols:   {', '.join(p.name for p in protocols)}")
    log(f"  Attacks:     {len(attacks)}")
    log(f"  Trials:      {total} ({n_clean} clean + {n_attack} attack)")
    log(f"  Concurrency: {args.concurrency}")
    log("")

    config = RunConfig(protocols=protocols, attacks=attacks, providers=[provider])
    runner = BenchmarkRunner(config)

    sem = asyncio.Semaphore(args.concurrency)
    results = []
    completed = 0
    errors = 0
    start = time.monotonic()

    async def run_one(protocol, message, attack=None):
        nonlocal completed, errors
        async with sem:
            result = await runner.run_trial(protocol, provider, message, attack)
        results.append(result)
        completed += 1
        if result.error:
            errors += 1
        if completed % 10 == 0 or completed == total:
            elapsed = time.monotonic() - start
            rate = completed / elapsed if elapsed > 0 else 0
            log(f"  [{completed}/{total}] {rate:.1f} trials/s | {errors} errors")
        return result

    # Build all tasks
    tasks = []
    for protocol in protocols:
        for message in config.benign_messages:
            tasks.append(run_one(protocol, message))
        for attack in attacks:
            tasks.append(run_one(protocol, config.benign_messages[0], attack))

    log("Running trials...")
    await asyncio.gather(*tasks)

    elapsed = time.monotonic() - start
    log(f"\nCompleted {completed} trials in {elapsed:.1f}s")

    reporter = Reporter(results)
    log("")
    log(reporter.format_terminal())

    reporter.save_json(args.output)
    log(f"\nResults saved to {args.output}")

    # Print JSON summary to stdout for machine consumption
    metrics = reporter.compute_metrics()
    import json
    print(json.dumps({
        "detection_rate": round(metrics.detection_rate, 4),
        "false_positive_rate": round(metrics.false_positive_rate, 4),
        "attack_success_rate": round(metrics.attack_success_rate, 4),
        "propagation_rate": round(metrics.propagation_rate, 4),
        "protocol_compliance_rate": round(metrics.protocol_compliance_rate, 4),
        "total_trials": metrics.total_trials,
        "propagation_trials": metrics.total_propagation_trials,
        "errors": errors,
        "elapsed_seconds": round(elapsed, 1),
        "output_file": str(args.output),
    }, indent=2))


def main():
    parser = build_parser()
    args = parser.parse_args()
    asyncio.run(run_benchmark(args))
