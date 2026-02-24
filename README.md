# Sigil

Prompt injection detection benchmark for agent-to-agent communication protocols.

Sigil embeds challenge-response mechanisms in the communication protocol itself. When injection breaks instruction following, it manifests as a protocol violation (wrong format, missing nonce, inconsistent fingerprint), providing a detection signal independent of the LLM's judgment.

## Quick Start

```bash
uv sync

# Run with Claude Code (default provider, Haiku model)
uv run sigil --protocol none schema_strict

# Run with a specific provider and model
uv run sigil --provider zai --model glm-4.7 --protocol schema_strict

# Run specific attack categories
uv run sigil --protocol schema_strict --category direct_override propagation

# Add Clean pre-filtering
uv run sigil --protocol schema_strict clean+schema_strict
```

## Protocols

- **none** — No protection baseline
- **canary** — Random canary token that must survive round-trip
- **nonce_echo** — Nonce in structured position, must be echoed as first line
- **schema_strict** — Strict JSON schema with nonce echo and self-referential fingerprint
- **hmac_challenge** — HMAC challenge-response (tests format survival, not crypto correctness)
- **combined** — Layers nonce + schema + canary
- **clean+\<protocol\>** — Wraps any protocol with [Clean](https://github.com/sibyllinesoft/clean) input pre-filtering

## Attack Catalog

45 payloads across 9 categories:

| Category | Count | Sources |
|---|---|---|
| Direct Override | 5 | HackAPrompt, PromptInject |
| Context Manipulation | 5 | HackAPrompt, TensorTrust |
| Persona Hijack | 5 | DAN, Skeleton Key |
| Delimiter Escape | 5 | Pliny multi-delimiter |
| Payload Smuggling | 5 | BIPIA |
| Encoding/Obfuscation | 5 | Base64, ROT13, leetspeak, homoglyphs |
| Pliny Specific | 5 | Refusal-sandwich, GODMODE, L1B3RT4S |
| Indirect Injection | 5 | InjecAgent, RAG poisoning |
| Propagation | 5 | Multi-agent relay attacks |

## Providers

- **claude-code** (default) — Claude Code CLI with no tool privileges
- **anthropic** — Anthropic API direct
- **openai** — OpenAI API
- **zai** — Z.AI GLM API (coding plan endpoint)
- **mock** — Deterministic mock for unit tests

## CLI Options

```
sigil [--provider PROVIDER] [--model MODEL] [--protocol PROTOCOL ...]
      [--category CATEGORY ...] [--concurrency N] [--output PATH]
      [--max-tokens N] [--clean-only]
```

## Tests

```bash
uv run pytest tests/           # Unit tests (no API keys needed)
uv run pytest benchmarks/ -m mock  # Pipeline test with mock provider
```

## Results

Benchmark results are saved to `benchmarks/results/` as JSON. See the full analysis in [Schema Strict: A Protocol-Level Firewall for Prompt Injection](https://sibyllinesoft.github.io/articles/2026-02-22-schema-strict-prompt-injection-firewall/).
