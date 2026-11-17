"""Structured just-in-time (JIT) state conditions for Varco JIT grants.

A JIT restriction is a grant restriction of type ``jit`` (alias
``state_condition``) whose ``params`` carry structured conditions over
Home Assistant entity states::

    {
      "id": "vacuum-only-when-away",
      "type": "jit",
      "enabled": true,
      "applies_to": "vacuum.start@vacuum.robot",
      "params": {
        "conditions": [
          {"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home"}
        ],
        "match": "all",
        "reveal_actual": false
      }
    }

Unlike the free-form ``template`` restriction, conditions here are data,
so a denial can report *which* condition failed, what was expected, and
(subject to the reveal rule in ``authority.py``) what the actual value
was. Evaluation itself is pure: the caller supplies a ``state_lookup``
callable with the same payload shape as ``VarcoAuthority._state_payload``
(``{"state": ..., "attributes": {...}}`` or ``None``), which keeps this
module unit-testable without Home Assistant.

Fail-closed rules:

- A missing entity fails every positive operator with reason
  ``entity_unavailable``. ``not_exists`` is the only operator that passes
  for a missing entity, and it passes *only* when the entity is truly
  absent (lookup returns ``None`` without raising).
- If ``state_lookup`` raises, the condition fails with reason
  ``state_lookup_error`` for every operator, including ``not_exists``:
  a lookup error is never treated as absence.
- States ``unknown`` and ``unavailable`` fail every positive operator
  with reason ``entity_unavailable``. ``exists`` still passes: the entity
  exists, it just has no usable value.
- Numeric operators fail with reason ``non_numeric`` when the actual
  value does not parse as a number. A non-numeric *expected* value for a
  numeric operator is a configuration error (``invalid_condition``).
- A malformed condition fails with reason ``invalid_condition``, and any
  validation error in any condition denies the whole restriction
  regardless of ``match`` — under ``match: "any"`` a broken condition
  must not be silently skipped just because another condition passes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

JIT_RESTRICTION_TYPES = {"jit", "state_condition"}

StateLookup = Callable[[str], "dict[str, Any] | None"]

# Accepted operator spellings -> canonical operator name.
OPERATOR_ALIASES: dict[str, str] = {
    "is": "is",
    "==": "is",
    "is_not": "is_not",
    "!=": "is_not",
    "in": "in",
    "not_in": "not_in",
    "above": "above",
    ">": "above",
    "below": "below",
    "<": "below",
    "gte": "gte",
    ">=": "gte",
    "lte": "lte",
    "<=": "lte",
    "exists": "exists",
    "not_exists": "not_exists",
}

_VALUELESS_OPERATORS = {"exists", "not_exists"}
_NUMERIC_OPERATORS = {"above", "below", "gte", "lte"}
_UNAVAILABLE_STATES = {"unknown", "unavailable"}


@dataclass
class ConditionResult:
    entity_id: str | None
    operator: str | None
    passed: bool
    reason: str | None = None
    attribute: str | None = None
    expected: Any = None
    actual: Any = None

    def as_dict(self, *, include_actual: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "entity_id": self.entity_id,
            "attribute": self.attribute,
            "operator": self.operator,
            "expected": self.expected,
            "reason": self.reason,
        }
        if include_actual:
            result["actual"] = self.actual
        return result


@dataclass
class JitDecision:
    allowed: bool
    match: str = "all"
    results: list[ConditionResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[ConditionResult]:
        return [result for result in self.results if not result.passed]


def validate_conditions(params: Any) -> list[str]:
    """Return human-readable errors for a JIT restriction ``params`` dict.

    An empty list means the spec is well-formed. Evaluation also fails
    closed on these errors, so callers may skip validation and rely on
    :func:`evaluate_jit_params` alone.
    """
    if not isinstance(params, dict):
        return ["params must be an object"]
    errors: list[str] = []
    match = params.get("match", "all")
    if match not in ("all", "any"):
        errors.append("match must be 'all' or 'any'")
    conditions = params.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        errors.append("conditions must be a non-empty list")
        return errors
    for index, condition in enumerate(conditions):
        errors.extend(f"conditions[{index}]: {error}" for error in _validate_condition(condition))
    return errors


def _validate_condition(condition: Any) -> list[str]:
    if not isinstance(condition, dict):
        return ["condition must be an object"]
    errors: list[str] = []
    entity_id = condition.get("entity_id")
    if not isinstance(entity_id, str) or not entity_id.strip():
        errors.append("entity_id is required")
    operator = condition.get("operator")
    if not isinstance(operator, str) or operator.strip().lower() not in OPERATOR_ALIASES:
        errors.append(f"unknown operator: {operator!r}")
        return errors
    canonical = OPERATOR_ALIASES[operator.strip().lower()]
    if canonical not in _VALUELESS_OPERATORS and "value" not in condition:
        errors.append(f"value is required for operator {canonical}")
    if canonical in {"in", "not_in"} and "value" in condition and not isinstance(condition.get("value"), list):
        errors.append(f"value must be a list for operator {canonical}")
    if canonical in _NUMERIC_OPERATORS and "value" in condition and _as_number(condition.get("value")) is None:
        errors.append(f"value must be numeric for operator {canonical}")
    attribute = condition.get("attribute")
    if attribute is not None and not isinstance(attribute, str):
        errors.append("attribute must be a string")
    return errors


def evaluate_jit_params(params: Any, state_lookup: StateLookup) -> JitDecision:
    """Evaluate JIT restriction ``params`` against current states.

    ``state_lookup(entity_id)`` returns the state payload dict or
    ``None`` when the entity does not exist. The decision is fail-closed:
    any malformed input denies.
    """
    if not isinstance(params, dict):
        return JitDecision(
            allowed=False,
            errors=["params must be an object"],
            results=[ConditionResult(None, None, False, reason="invalid_condition")],
        )
    match = params.get("match", "all")
    if match not in ("all", "any"):
        return JitDecision(
            allowed=False,
            errors=["match must be 'all' or 'any'"],
            results=[ConditionResult(None, None, False, reason="invalid_condition")],
        )
    conditions = params.get("conditions")
    if not isinstance(conditions, list) or not conditions:
        return JitDecision(
            allowed=False,
            match=match,
            errors=["conditions must be a non-empty list"],
            results=[ConditionResult(None, None, False, reason="invalid_condition")],
        )
    results = [_evaluate_condition(condition, state_lookup) for condition in conditions]
    errors = [f"conditions[{i}]: {error}" for i, condition in enumerate(conditions) for error in _validate_condition(condition)]
    if errors:
        # Fail closed on configuration errors regardless of match: under
        # "any", a malformed condition must not be skipped just because
        # another condition happened to pass.
        allowed = False
    elif match == "any":
        allowed = any(result.passed for result in results)
    else:
        allowed = all(result.passed for result in results)
    return JitDecision(allowed=allowed, match=match, results=results, errors=errors)


def _evaluate_condition(condition: Any, state_lookup: StateLookup) -> ConditionResult:
    if _validate_condition(condition):
        entity_id = condition.get("entity_id") if isinstance(condition, dict) else None
        operator = condition.get("operator") if isinstance(condition, dict) else None
        canonical = OPERATOR_ALIASES.get(str(operator).strip().lower()) if isinstance(operator, str) else None
        return ConditionResult(
            entity_id=entity_id if isinstance(entity_id, str) else None,
            attribute=condition.get("attribute") if isinstance(condition, dict) and isinstance(condition.get("attribute"), str) else None,
            operator=canonical,
            expected=condition.get("value") if isinstance(condition, dict) else None,
            actual=None,
            passed=False,
            reason="invalid_condition",
        )

    entity_id = str(condition["entity_id"])
    operator = OPERATOR_ALIASES[str(condition["operator"]).strip().lower()]
    attribute = condition.get("attribute")
    expected = condition.get("value")

    try:
        payload = state_lookup(entity_id)
    except Exception:
        # A lookup error is not absence: fail closed for every operator,
        # including not_exists, which may pass only on a clean None.
        return ConditionResult(
            entity_id, operator, False,
            reason="state_lookup_error", attribute=attribute, expected=expected, actual=None,
        )

    if operator == "not_exists":
        if payload is None:
            return ConditionResult(entity_id, operator, True, attribute=attribute, expected=expected)
        return ConditionResult(
            entity_id, operator, False,
            reason="condition_not_met", attribute=attribute, expected=expected,
            actual=_extract_value(payload, attribute),
        )
    if payload is None:
        return ConditionResult(
            entity_id, operator, False,
            reason="entity_unavailable", attribute=attribute, expected=expected, actual=None,
        )
    if operator == "exists":
        return ConditionResult(
            entity_id, operator, True,
            attribute=attribute, expected=expected, actual=_extract_value(payload, attribute),
        )

    state = payload.get("state")
    if isinstance(state, str) and state.strip().lower() in _UNAVAILABLE_STATES:
        return ConditionResult(
            entity_id, operator, False,
            reason="entity_unavailable", attribute=attribute, expected=expected, actual=state,
        )

    actual = _extract_value(payload, attribute)
    if attribute is not None and actual is None:
        return ConditionResult(
            entity_id, operator, False,
            reason="condition_not_met", attribute=attribute, expected=expected, actual=None,
        )

    if operator == "is":
        passed = _values_equal(actual, expected)
    elif operator == "is_not":
        passed = not _values_equal(actual, expected)
    elif operator == "in":
        passed = any(_values_equal(actual, item) for item in expected)
    elif operator == "not_in":
        passed = not any(_values_equal(actual, item) for item in expected)
    elif operator in _NUMERIC_OPERATORS:
        actual_number = _as_number(actual)
        expected_number = _as_number(expected)
        if actual_number is None or expected_number is None:
            return ConditionResult(
                entity_id, operator, False,
                reason="non_numeric", attribute=attribute, expected=expected, actual=actual,
            )
        if operator == "above":
            passed = actual_number > expected_number
        elif operator == "below":
            passed = actual_number < expected_number
        elif operator == "gte":
            passed = actual_number >= expected_number
        else:
            passed = actual_number <= expected_number
    else:  # pragma: no cover - validation guarantees a known operator
        return ConditionResult(
            entity_id, operator, False,
            reason="invalid_condition", attribute=attribute, expected=expected, actual=actual,
        )
    return ConditionResult(
        entity_id, operator, passed,
        reason=None if passed else "condition_not_met",
        attribute=attribute, expected=expected, actual=actual,
    )


def _extract_value(payload: dict[str, Any], attribute: str | None) -> Any:
    if attribute is None:
        return payload.get("state")
    attributes = payload.get("attributes")
    if isinstance(attributes, dict):
        return attributes.get(attribute)
    return None


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _values_equal(actual: Any, expected: Any) -> bool:
    if actual == expected:
        return True
    actual_number = _as_number(actual)
    expected_number = _as_number(expected)
    if actual_number is not None and expected_number is not None:
        return actual_number == expected_number
    if isinstance(expected, bool) or isinstance(actual, bool):
        return str(actual).strip().lower() == str(expected).strip().lower()
    return str(actual) == str(expected)


def jit_restrictions(grant: Any, operation: str, context: dict[str, Any]) -> list[dict[str, Any]]:
    """Return enabled JIT restrictions on ``grant`` matching this operation."""
    # Imported here to avoid a policy <-> jit import cycle at module load;
    # policy.py only defers JIT types and never imports this module.
    from .policy import restriction_matches

    matches: list[dict[str, Any]] = []
    for restriction in grant.restrictions:
        if not restriction.get("enabled", True):
            continue
        if str(restriction.get("type") or "").lower() not in JIT_RESTRICTION_TYPES:
            continue
        if restriction_matches(restriction, operation, context):
            matches.append(restriction)
    return matches


def audit_failure(failure: ConditionResult) -> dict[str, Any]:
    """Summarize a failure for audit / HA logs WITHOUT the actual value.

    The repository invariant is that entity states are never written to
    audit logs, so the actual state is deliberately dropped here even
    when the consumer-facing error is allowed to reveal it.
    """
    return {
        "entity_id": failure.entity_id,
        "attribute": failure.attribute,
        "operator": failure.operator,
        "expected": failure.expected,
        "reason": failure.reason,
    }
