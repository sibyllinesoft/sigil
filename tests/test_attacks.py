"""Tests for attack catalog loading and validation."""

import pytest

from sigil.attacks import (
    get_all_payloads,
    get_payloads_by_category,
    get_payloads_by_objective,
    AttackCategory,
    AttackObjective,
    AttackPayload,
)


class TestAttackCatalog:
    def test_all_payloads_load(self):
        payloads = get_all_payloads()
        assert len(payloads) == 45, f"Expected 45 payloads, got {len(payloads)}"

    def test_all_categories_represented(self):
        payloads = get_all_payloads()
        categories = {p.category for p in payloads}
        for cat in AttackCategory:
            assert cat in categories, f"Category {cat} has no payloads"

    def test_five_per_category(self):
        for cat in AttackCategory:
            payloads = get_payloads_by_category(cat)
            assert len(payloads) == 5, (
                f"Category {cat.value} has {len(payloads)} payloads, expected 5"
            )

    def test_unique_ids(self):
        payloads = get_all_payloads()
        ids = [p.id for p in payloads]
        assert len(ids) == len(set(ids)), "Duplicate payload IDs found"

    def test_all_payloads_are_dataclass(self):
        for payload in get_all_payloads():
            assert isinstance(payload, AttackPayload)
            assert payload.id
            assert payload.name
            assert payload.payload
            assert payload.source
            assert payload.targets

    def test_payload_ids_match_category(self):
        """Verify payload IDs start with their category name."""
        for payload in get_all_payloads():
            assert payload.id.startswith(payload.category.value), (
                f"Payload {payload.id} doesn't match category {payload.category.value}"
            )

    def test_filter_by_category(self):
        direct = get_payloads_by_category(AttackCategory.DIRECT_OVERRIDE)
        assert all(p.category == AttackCategory.DIRECT_OVERRIDE for p in direct)
        assert len(direct) == 5

    def test_propagation_payloads_have_markers(self):
        propagation = get_payloads_by_category(AttackCategory.PROPAGATION)
        for p in propagation:
            assert p.objective == AttackObjective.PROPAGATE
            assert p.propagation_marker, f"Propagation payload {p.id} missing marker"
            assert p.propagation_marker in p.payload, (
                f"Propagation marker not found in payload text for {p.id}"
            )

    def test_filter_by_objective(self):
        execute = get_payloads_by_objective(AttackObjective.EXECUTE)
        propagate = get_payloads_by_objective(AttackObjective.PROPAGATE)
        assert len(execute) == 40
        assert len(propagate) == 5
        assert all(p.objective == AttackObjective.EXECUTE for p in execute)
        assert all(p.objective == AttackObjective.PROPAGATE for p in propagate)
