"""Attack catalog: loads and indexes all payloads."""

from sigil.attacks.categories import AttackCategory, AttackObjective, AttackPayload
from sigil.attacks.payloads import (
    context_manipulation,
    delimiter_escape,
    direct_override,
    encoding,
    indirect,
    payload_smuggling,
    persona_hijack,
    pliny,
    propagation,
)

_PAYLOAD_MODULES = [
    direct_override,
    context_manipulation,
    persona_hijack,
    delimiter_escape,
    payload_smuggling,
    encoding,
    pliny,
    indirect,
    propagation,
]


def get_all_payloads() -> list[AttackPayload]:
    """Return all attack payloads from all modules."""
    payloads = []
    for module in _PAYLOAD_MODULES:
        payloads.extend(module.PAYLOADS)
    return payloads


def get_payloads_by_category(category: AttackCategory) -> list[AttackPayload]:
    """Return payloads filtered by category."""
    return [p for p in get_all_payloads() if p.category == category]


def get_payloads_by_objective(objective: AttackObjective) -> list[AttackPayload]:
    """Return payloads filtered by objective (execute vs propagate)."""
    return [p for p in get_all_payloads() if p.objective == objective]
