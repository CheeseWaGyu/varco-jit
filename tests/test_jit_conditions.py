"""Unit tests for the pure JIT condition evaluator (jit.py)."""
from datetime import datetime, timezone

from custom_components.varco_jit.jit import (
    ConditionResult,
    actual_disclosable,
    audit_failure,
    denial_category,
    denial_rate_limit,
    diagnostic_covers,
    evaluate_jit_params,
    resolve_disclosure,
    validate_conditions,
)

NOW = datetime(2026, 11, 18, 0, 0, tzinfo=timezone.utc)

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


def test_match_any_denies_when_any_condition_is_invalid():
    """Regression (audit): under match=any, a malformed condition must deny
    the whole restriction even when another condition passes."""
    conditions = [
        {"entity_id": "device_tracker.phone", "operator": "is", "value": "home"},  # passes
        {"entity_id": "sensor.temperature", "operator": "approx", "value": 1},  # invalid operator
    ]
    decision = evaluate(conditions, match="any")
    assert not decision.allowed
    assert decision.errors
    assert any(f.reason == "invalid_condition" for f in decision.failures)

    missing_value = [
        {"entity_id": "device_tracker.phone", "operator": "is", "value": "home"},
        {"entity_id": "sensor.temperature", "operator": "is"},  # value missing
    ]
    assert not evaluate(missing_value, match="any").allowed


def test_match_any_denies_when_numeric_expected_is_not_numeric():
    """A non-numeric expected value for a numeric operator is a config error."""
    conditions = [
        {"entity_id": "device_tracker.phone", "operator": "is", "value": "home"},  # passes
        {"entity_id": "sensor.temperature", "operator": "above", "value": "warm"},  # invalid expected
    ]
    decision = evaluate(conditions, match="any")
    assert not decision.allowed
    assert decision.errors
    assert validate_conditions({"conditions": conditions[1:], "match": "any"})


def raising_lookup(entity_id):
    raise RuntimeError("state store unavailable")


def test_state_lookup_error_fails_closed_for_not_exists():
    """Regression (audit): a lookup exception is not absence; not_exists
    passes only when the lookup cleanly returns None."""
    decision = evaluate_jit_params(
        {"conditions": [{"entity_id": "sensor.ghost", "operator": "not_exists"}]},
        raising_lookup,
    )
    assert not decision.allowed
    assert decision.failures[0].reason == "state_lookup_error"


def test_state_lookup_error_fails_closed_for_positive_operators():
    for condition in (
        {"entity_id": "device_tracker.phone", "operator": "is", "value": "home"},
        {"entity_id": "device_tracker.phone", "operator": "exists"},
        {"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home"},
    ):
        decision = evaluate_jit_params({"conditions": [condition]}, raising_lookup)
        assert not decision.allowed
        assert decision.failures[0].reason == "state_lookup_error"


def test_validate_conditions_reports_errors():
    assert validate_conditions({"conditions": [{"entity_id": "sensor.temperature", "operator": "is", "value": "21.5"}]}) == []
    assert validate_conditions({"conditions": []})
    assert validate_conditions({"conditions": [{"operator": "is", "value": 1}]})
    assert validate_conditions({"conditions": [{"entity_id": "sensor.temperature", "operator": "bogus", "value": 1}]})
    assert validate_conditions({"conditions": [{"entity_id": "sensor.temperature", "operator": "in", "value": "home"}]})
    assert validate_conditions("nope")


def test_per_condition_reveal_actual_directive_is_carried_on_results():
    decision = evaluate([
        {"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home", "reveal_actual": True},
        {"entity_id": "sensor.temperature", "operator": "above", "value": 30, "reveal_actual": False},
        {"entity_id": "climate.living", "operator": "is", "value": "cool"},
    ])
    assert not decision.allowed
    directives = {failure.entity_id: failure.reveal_actual for failure in decision.failures}
    assert directives == {
        "device_tracker.phone": True,
        "sensor.temperature": False,
        "climate.living": None,
    }


def test_non_boolean_reveal_actual_is_a_validation_error():
    errors = validate_conditions({"conditions": [
        {"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home", "reveal_actual": "yes"},
    ]})
    assert any("reveal_actual" in error for error in errors)
    # ...and evaluation fails closed on it, like any malformed condition.
    decision = evaluate([
        {"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home", "reveal_actual": "yes"},
    ])
    assert not decision.allowed
    assert decision.failures[0].reason == "invalid_condition"


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


def test_resolve_disclosure_defaults_and_fail_closed_fallbacks():
    policy = resolve_disclosure({})
    assert policy.response_level == "generic"
    assert policy.audit_level == "structured"
    assert policy.response_fields["actual"] is False

    # Unknown levels fall back to the safest level for that channel.
    policy = resolve_disclosure({"disclosure": {"level": "verbose", "audit": {"level": "everything"}}})
    assert policy.response_level == "generic"
    assert policy.audit_level == "structured"

    # A present but non-boolean field toggle hides the field.
    policy = resolve_disclosure({"disclosure": {"level": "structured", "fields": {"entity_id": "yes"}}})
    assert policy.response_fields["entity_id"] is False
    assert policy.response_fields["expected"] is True

    # Actual values can never be enabled for the audit channel.
    policy = resolve_disclosure({"disclosure": {"audit": {"fields": {"actual": True}}}})
    assert policy.audit_fields["actual"] is False


def test_denial_category_mapping():
    unavailable = evaluate([{"entity_id": "sensor.missing", "operator": "is", "value": "x"}])
    assert denial_category(unavailable) == "state_unavailable"
    not_met = evaluate([{"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home"}])
    assert denial_category(not_met) == "condition_not_met"
    broken = evaluate([{"entity_id": "sensor.temperature", "operator": "bogus", "value": 1}])
    assert denial_category(broken) == "configuration_error"


def test_diagnostic_covers_requires_entity_field_and_live_expiry():
    params = {"diagnostics": [
        {"entity_id": "device_tracker.phone", "fields": ["state"], "expires_at": "2999-01-01T00:00:00Z"},
        {"entity_id": "sensor.temperature", "fields": ["unit_of_measurement"], "expires_at": "2999-01-01T00:00:00Z"},
        {"entity_id": "binary_sensor.door", "fields": ["state"], "expires_at": "2000-01-01T00:00:00Z"},
        {"entity_id": "climate.living", "fields": ["state"], "expires_at": "2999-01-01T00:00:00"},
    ]}
    assert diagnostic_covers(params, "device_tracker.phone", None, NOW) is True
    # Field not named by the grant: the state grant does not cover attributes.
    assert diagnostic_covers(params, "device_tracker.phone", "battery_level", NOW) is False
    assert diagnostic_covers(params, "sensor.temperature", "unit_of_measurement", NOW) is True
    assert diagnostic_covers(params, "sensor.temperature", None, NOW) is False
    # Expired and timezone-less expiries never cover.
    assert diagnostic_covers(params, "binary_sensor.door", None, NOW) is False
    assert diagnostic_covers(params, "climate.living", None, NOW) is False
    # No clock, no coverage.
    assert diagnostic_covers(params, "device_tracker.phone", None, None) is False


def test_actual_disclosable_is_capped_by_permission_and_only_tightened_by_reveal():
    failure = ConditionResult("device_tracker.phone", "is_not", False, reason="condition_not_met", expected="home", actual="home")
    structured = {"disclosure": {"level": "structured", "fields": {"actual": True}}}

    # Readable under the grant: disclosable.
    policy = resolve_disclosure(structured)
    assert actual_disclosable(structured, policy, ["device_tracker.phone"], failure, NOW) is True
    # reveal_actual=True cannot open an entity the grant cannot read.
    params = {**structured, "reveal_actual": True}
    assert actual_disclosable(params, policy, [], failure, NOW) is False
    # A diagnostic grant can open it, within its expiry.
    params = {**structured, "diagnostics": [
        {"entity_id": "device_tracker.phone", "fields": ["state"], "expires_at": "2999-01-01T00:00:00Z"},
    ]}
    assert actual_disclosable(params, policy, [], failure, NOW) is True
    # Tightening wins over both readability and diagnostics.
    hidden = ConditionResult("device_tracker.phone", "is_not", False, reason="condition_not_met", expected="home", actual="home", reveal_actual=False)
    assert actual_disclosable(params, policy, ["device_tracker.phone"], hidden, NOW) is False
    assert actual_disclosable({**structured, "reveal_actual": False}, policy, ["device_tracker.phone"], failure, NOW) is False
    # The field toggle and the level both gate disclosure.
    policy = resolve_disclosure({"disclosure": {"level": "structured"}})
    assert actual_disclosable(structured, policy, ["device_tracker.phone"], failure, NOW) is False
    policy = resolve_disclosure({"disclosure": {"level": "category", "fields": {"actual": True}}})
    assert actual_disclosable(structured, policy, ["device_tracker.phone"], failure, NOW) is False


def test_denial_rate_limit_parsing():
    assert denial_rate_limit({}) == (10, 60.0)
    assert denial_rate_limit({"denial_rate_limit": {"limit": 3, "window_seconds": 30}}) == (3, 30.0)
    # Malformed values fall back to the defaults; the budget stays on.
    assert denial_rate_limit({"denial_rate_limit": {"limit": 0, "window_seconds": -5}}) == (10, 60.0)
    assert denial_rate_limit({"denial_rate_limit": {"limit": True}}) == (10, 60.0)


def test_validate_conditions_reports_disclosure_errors():
    base = {"entity_id": "sensor.temperature", "operator": "is", "value": "21.5"}
    assert validate_conditions({"conditions": [base], "disclosure": {"level": "structured"}}) == []
    assert validate_conditions({"conditions": [base], "disclosure": {"level": "verbose"}})
    assert validate_conditions({"conditions": [base], "disclosure": {"fields": {"entity_id": "yes"}}})
    assert validate_conditions({"conditions": [base], "disclosure": {"fields": {"bogus": True}}})
    assert validate_conditions({"conditions": [base], "reveal_actual": "yes"})
    assert validate_conditions({"conditions": [base], "diagnostics": [{"entity_id": "sensor.temperature", "fields": ["state"]}]})
    assert validate_conditions({"conditions": [base], "diagnostics": [
        {"entity_id": "sensor.temperature", "fields": ["state"], "expires_at": "2999-01-01T00:00:00Z"},
    ]}) == []
    assert validate_conditions({"conditions": [base], "denial_rate_limit": {"limit": 0}})
