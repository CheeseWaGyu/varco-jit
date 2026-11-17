"""Unit tests for the pure JIT condition evaluator (jit.py)."""
from custom_components.varco_jit.jit import (
    audit_failure,
    evaluate_jit_params,
    validate_conditions,
)

STATES = {
    "device_tracker.phone": {"entity_id": "device_tracker.phone", "state": "home", "attributes": {}},
    "sensor.temperature": {"entity_id": "sensor.temperature", "state": "21.5", "attributes": {"unit_of_measurement": "°C"}},
    "climate.living": {"entity_id": "climate.living", "state": "heat", "attributes": {"temperature": 22, "current_temperature": 20.5}},
    "binary_sensor.door": {"entity_id": "binary_sensor.door", "state": "unavailable", "attributes": {}},
    "sensor.broken": {"entity_id": "sensor.broken", "state": "unknown", "attributes": {}},
}


def lookup(entity_id):
    return STATES.get(entity_id)


def evaluate(conditions, match="all", **extra):
    return evaluate_jit_params({"conditions": conditions, "match": match, **extra}, lookup)


def test_is_and_is_not():
    assert evaluate([{"entity_id": "device_tracker.phone", "operator": "is", "value": "home"}]).allowed
    denied = evaluate([{"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home"}])
    assert not denied.allowed
    assert denied.failures[0].reason == "condition_not_met"
    assert denied.failures[0].expected == "home"
    assert denied.failures[0].actual == "home"
    assert denied.failures[0].operator == "is_not"


def test_operator_aliases():
    assert evaluate([{"entity_id": "device_tracker.phone", "operator": "==", "value": "home"}]).allowed
    assert not evaluate([{"entity_id": "device_tracker.phone", "operator": "!=", "value": "home"}]).allowed
    assert evaluate([{"entity_id": "sensor.temperature", "operator": ">", "value": 20}]).allowed
    assert evaluate([{"entity_id": "sensor.temperature", "operator": ">=", "value": 21.5}]).allowed


def test_match_all_requires_every_condition():
    conditions = [
        {"entity_id": "device_tracker.phone", "operator": "is", "value": "home"},
        {"entity_id": "sensor.temperature", "operator": "above", "value": 30},
    ]
    decision = evaluate(conditions, match="all")
    assert not decision.allowed
    assert len(decision.failures) == 1


def test_match_any_requires_one_condition():
    conditions = [
        {"entity_id": "device_tracker.phone", "operator": "is", "value": "home"},
        {"entity_id": "sensor.temperature", "operator": "above", "value": 30},
    ]
    assert evaluate(conditions, match="any").allowed
    both_fail = [
        {"entity_id": "device_tracker.phone", "operator": "is", "value": "work"},
        {"entity_id": "sensor.temperature", "operator": "above", "value": 30},
    ]
    assert not evaluate(both_fail, match="any").allowed


def test_numeric_operators_and_non_numeric_failure():
    assert evaluate([{"entity_id": "sensor.temperature", "operator": "below", "value": 22}]).allowed
    assert evaluate([{"entity_id": "sensor.temperature", "operator": "lte", "value": 21.5}]).allowed
    assert not evaluate([{"entity_id": "sensor.temperature", "operator": "above", "value": 30}]).allowed
    non_numeric = evaluate([{"entity_id": "device_tracker.phone", "operator": "above", "value": 3}])
    assert not non_numeric.allowed
    assert non_numeric.failures[0].reason == "non_numeric"


def test_attribute_conditions():
    assert evaluate([{"entity_id": "climate.living", "attribute": "temperature", "operator": "gte", "value": 22}]).allowed
    denied = evaluate([{"entity_id": "climate.living", "attribute": "temperature", "operator": "above", "value": 25}])
    assert not denied.allowed
    assert denied.failures[0].actual == 22
    missing_attr = evaluate([{"entity_id": "climate.living", "attribute": "nope", "operator": "is", "value": "x"}])
    assert not missing_attr.allowed


def test_in_and_not_in():
    assert evaluate([{"entity_id": "device_tracker.phone", "operator": "in", "value": ["home", "work"]}]).allowed
    assert not evaluate([{"entity_id": "device_tracker.phone", "operator": "not_in", "value": ["home", "work"]}]).allowed


def test_exists_and_not_exists():
    assert evaluate([{"entity_id": "device_tracker.phone", "operator": "exists"}]).allowed
    # exists passes even when the state is unavailable: the entity exists.
    assert evaluate([{"entity_id": "binary_sensor.door", "operator": "exists"}]).allowed
    assert evaluate([{"entity_id": "sensor.missing", "operator": "not_exists"}]).allowed
    assert not evaluate([{"entity_id": "device_tracker.phone", "operator": "not_exists"}]).allowed
    missing_exists = evaluate([{"entity_id": "sensor.missing", "operator": "exists"}])
    assert not missing_exists.allowed
    assert missing_exists.failures[0].reason == "entity_unavailable"


def test_missing_entity_fails_closed():
    decision = evaluate([{"entity_id": "sensor.missing", "operator": "is", "value": "x"}])
    assert not decision.allowed
    assert decision.failures[0].reason == "entity_unavailable"
    assert decision.failures[0].actual is None


def test_unknown_and_unavailable_fail_closed():
    for entity_id in ("binary_sensor.door", "sensor.broken"):
        decision = evaluate([{"entity_id": entity_id, "operator": "is_not", "value": "on"}])
        assert not decision.allowed
        assert decision.failures[0].reason == "entity_unavailable"


def test_invalid_specs_fail_closed():
    bad_operator = evaluate([{"entity_id": "sensor.temperature", "operator": "approx", "value": 1}])
    assert not bad_operator.allowed
    assert bad_operator.failures[0].reason == "invalid_condition"

    missing_value = evaluate([{"entity_id": "sensor.temperature", "operator": "is"}])
    assert not missing_value.allowed
    assert missing_value.failures[0].reason == "invalid_condition"

    missing_entity = evaluate([{"operator": "is", "value": "x"}])
    assert not missing_entity.allowed

    empty = evaluate_jit_params({"conditions": []}, lookup)
    assert not empty.allowed

    bad_match = evaluate_jit_params(
        {"conditions": [{"entity_id": "sensor.temperature", "operator": "exists"}], "match": "some"}, lookup
    )
    assert not bad_match.allowed

    not_a_dict = evaluate_jit_params(None, lookup)
    assert not not_a_dict.allowed


def test_validate_conditions_reports_errors():
    assert validate_conditions({"conditions": [{"entity_id": "sensor.temperature", "operator": "is", "value": "21.5"}]}) == []
    assert validate_conditions({"conditions": []})
    assert validate_conditions({"conditions": [{"operator": "is", "value": 1}]})
    assert validate_conditions({"conditions": [{"entity_id": "sensor.temperature", "operator": "bogus", "value": 1}]})
    assert validate_conditions({"conditions": [{"entity_id": "sensor.temperature", "operator": "in", "value": "home"}]})
    assert validate_conditions("nope")


def test_audit_failure_drops_actual():
    decision = evaluate([{"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home"}])
    summary = audit_failure(decision.failures[0])
    assert summary == {
        "entity_id": "device_tracker.phone",
        "attribute": None,
        "operator": "is_not",
        "expected": "home",
        "reason": "condition_not_met",
    }
    assert "actual" not in summary
