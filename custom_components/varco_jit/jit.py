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
from datetime import datetime
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
    # Per-condition reveal directive copied from the condition spec:
    # True/False when the condition sets "reveal_actual" explicitly,
    # None when it inherits the restriction-level default. The Authority
    # applies it in _jit_denied_error; an explicit value wins in both
    # directions over the restriction default and grant readability.
    reveal_actual: bool | None = None

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
    errors.extend(_validate_disclosure(params.get("disclosure")))
    errors.extend(_validate_diagnostics(params.get("diagnostics")))
    errors.extend(_validate_denial_rate_limit(params.get("denial_rate_limit")))
    if "reveal_actual" in params and not isinstance(params.get("reveal_actual"), bool):
        errors.append("reveal_actual must be a boolean")
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
    if "reveal_actual" in condition and not isinstance(condition.get("reveal_actual"), bool):
        errors.append("reveal_actual must be a boolean")
    return errors


def condition_reveal_actual(condition: Any) -> bool | None:
    """Return a condition's explicit ``reveal_actual`` directive.

    ``True`` / ``False`` when the condition sets it to a boolean, else
    ``None`` (inherit the restriction-level default). A non-boolean
    value is a validation error, so it is treated as unset here and the
    restriction fails closed through validation instead.
    """
    if isinstance(condition, dict):
        value = condition.get("reveal_actual")
        if isinstance(value, bool):
            return value
    return None


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
    result = _evaluate_condition_inner(condition, state_lookup)
    # Stamp the per-condition reveal directive onto the result so the
    # Authority's reveal rule can apply it per failure (per entity).
    result.reveal_actual = condition_reveal_actual(condition)
    return result


def _evaluate_condition_inner(condition: Any, state_lookup: StateLookup) -> ConditionResult:
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


# ---------------------------------------------------------------------------
# Denial disclosure policy
#
# What a JIT denial tells the consumer is governed by an explicit
# disclosure policy in the restriction params, kept separate from the
# read permissions on the grant:
#
#   "disclosure": {
#     "level": "generic" | "category" | "structured",   (response channel)
#     "fields": {"entity_id": true, "expected": false, ...},
#     "audit": {"level": ..., "fields": {...}}           (HA audit channel)
#   }
#
# - generic (the default): the response carries only the denial code
#   and the request id. No restriction id, entity, expected or actual
#   values anywhere, including the human-readable message.
# - category: additionally, one broad category (see denial_category).
# - structured: per-failure detail, with each field individually
#   toggleable — entity ids and expected values can be sensitive too.
#
# The audit channel is configured independently and defaults to
# structured failure summaries; actual values are NEVER audited.
#
# Actual-value disclosure is capped by permission, never opened by a
# reveal flag: an actual value is disclosable only when the entity is
# readable under the grant, or a time-boxed diagnostic grant (below)
# covers that entity and field. reveal_actual (restriction-level and
# per-condition) is tightening-only: it can hide actuals, never open
# them beyond that cap.
# ---------------------------------------------------------------------------

DISCLOSURE_LEVELS = ("generic", "category", "structured")
DISCLOSURE_FIELDS = (
    "restriction_id",
    "entity_id",
    "attribute",
    "operator",
    "expected",
    "reason",
    "actual",
)

_RESPONSE_FIELD_DEFAULTS: dict[str, bool] = {
    "restriction_id": True,
    "entity_id": True,
    "attribute": True,
    "operator": True,
    "expected": True,
    "reason": True,
    "actual": False,
}
_AUDIT_FIELD_DEFAULTS: dict[str, bool] = dict(_RESPONSE_FIELD_DEFAULTS)

DEFAULT_DENIAL_RATE_LIMIT = 10
DEFAULT_DENIAL_RATE_WINDOW_SECONDS = 60.0


@dataclass
class DisclosurePolicy:
    response_level: str = "generic"
    response_fields: dict[str, bool] = field(default_factory=lambda: dict(_RESPONSE_FIELD_DEFAULTS))
    audit_level: str = "structured"
    audit_fields: dict[str, bool] = field(default_factory=lambda: dict(_AUDIT_FIELD_DEFAULTS))


def _resolve_level(raw: Any, default: str) -> str:
    return raw if raw in DISCLOSURE_LEVELS else default


def _resolve_fields(raw: Any, defaults: dict[str, bool]) -> dict[str, bool]:
    fields = dict(defaults)
    if isinstance(raw, dict):
        for name in DISCLOSURE_FIELDS:
            if name not in raw:
                continue
            value = raw.get(name)
            # Fail closed: a present but non-boolean toggle hides the field.
            fields[name] = value if isinstance(value, bool) else False
    return fields


def resolve_disclosure(params: Any) -> DisclosurePolicy:
    """Resolve the disclosure policy for a restriction's ``params``.

    Defensive by construction: any malformed piece falls back to the
    safest behaviour for that piece (generic response, hidden fields),
    so a configuration typo can never widen disclosure.
    """
    policy = DisclosurePolicy()
    if not isinstance(params, dict):
        return policy
    disclosure = params.get("disclosure")
    if not isinstance(disclosure, dict):
        return policy
    policy.response_level = _resolve_level(disclosure.get("level"), "generic")
    policy.response_fields = _resolve_fields(disclosure.get("fields"), _RESPONSE_FIELD_DEFAULTS)
    audit = disclosure.get("audit")
    if isinstance(audit, dict):
        policy.audit_level = _resolve_level(audit.get("level"), "structured")
        policy.audit_fields = _resolve_fields(audit.get("fields"), _AUDIT_FIELD_DEFAULTS)
    # Repository invariant: entity states are never written to audit logs.
    policy.audit_fields["actual"] = False
    return policy


def denial_category(decision: JitDecision) -> str:
    """Collapse a decision's failure reasons into one broad category."""
    reasons = {failure.reason for failure in decision.failures}
    if "invalid_condition" in reasons:
        return "configuration_error"
    if reasons & {"entity_unavailable", "state_lookup_error"}:
        return "state_unavailable"
    return "condition_not_met"


def _parse_expiry(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        # An expiry without a timezone is ambiguous; fail closed.
        return None
    return parsed


def diagnostic_covers(params: Any, entity_id: str, attribute: str | None, now: datetime | None) -> bool:
    """Whether a diagnostic grant covers this entity + field right now.

    Diagnostic grants live in ``params["diagnostics"]`` as a list of
    ``{"entity_id": ..., "fields": ["state" | <attribute>, ...],
    "expires_at": <ISO 8601 with timezone>}``. They are the ONLY way to
    disclose an actual value beyond the grant's read permissions, and
    they are deliberately narrow: one entity pattern, named fields,
    and a mandatory expiry. Malformed or expired entries never cover.
    """
    if now is None or not isinstance(params, dict):
        return False
    entries = params.get("diagnostics")
    if not isinstance(entries, list):
        return False
    field_name = "state" if attribute is None else attribute
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pattern = entry.get("entity_id")
        if not isinstance(pattern, str):
            continue
        from .policy import entity_allowed

        if not entity_allowed(entity_id, [pattern]):
            continue
        fields = entry.get("fields")
        if not isinstance(fields, list) or field_name not in fields:
            continue
        expires = _parse_expiry(entry.get("expires_at"))
        if expires is None or now >= expires:
            continue
        return True
    return False


def actual_disclosable(
    params: Any,
    policy: DisclosurePolicy,
    readable: list[str],
    failure: ConditionResult,
    now: datetime | None,
) -> bool:
    """Whether ``failure``'s actual value may be shown to the consumer.

    All of these must hold: the response is structured with the
    ``actual`` field enabled; no tightening knob hides it (restriction
    or per-condition ``reveal_actual`` set to anything but ``True``
    hides — the flags can only tighten, never loosen); and the
    permission cap allows it — the entity is readable under the grant,
    or a diagnostic grant covers this entity and field.
    """
    if policy.response_level != "structured" or not policy.response_fields.get("actual"):
        return False
    if isinstance(params, dict):
        restriction_reveal = params.get("reveal_actual")
        if restriction_reveal is not None and restriction_reveal is not True:
            return False
    if failure.reveal_actual is False:
        return False
    if failure.entity_id is None:
        return False
    from .policy import entity_allowed

    if entity_allowed(failure.entity_id, readable):
        return True
    return diagnostic_covers(params, failure.entity_id, failure.attribute, now)


def denial_rate_limit(params: Any) -> tuple[int, float]:
    """Per-restriction denial budget: (max denials, window seconds).

    Repeated denials are an oracle for the protected state, so denials
    themselves are budgeted. Malformed values fall back to the
    defaults; the budget cannot be disabled, only widened.
    """
    limit = DEFAULT_DENIAL_RATE_LIMIT
    window = DEFAULT_DENIAL_RATE_WINDOW_SECONDS
    if isinstance(params, dict):
        raw = params.get("denial_rate_limit")
        if isinstance(raw, dict):
            raw_limit = raw.get("limit")
            if isinstance(raw_limit, int) and not isinstance(raw_limit, bool) and raw_limit > 0:
                limit = raw_limit
            raw_window = raw.get("window_seconds")
            if isinstance(raw_window, (int, float)) and not isinstance(raw_window, bool) and raw_window > 0:
                window = float(raw_window)
    return limit, window


def _validate_disclosure(disclosure: Any) -> list[str]:
    if disclosure is None:
        return []
    if not isinstance(disclosure, dict):
        return ["disclosure must be an object"]
    errors: list[str] = []
    level = disclosure.get("level")
    if level is not None and level not in DISCLOSURE_LEVELS:
        errors.append(f"disclosure.level must be one of {', '.join(DISCLOSURE_LEVELS)}")
    errors.extend(_validate_disclosure_fields(disclosure.get("fields"), "disclosure.fields"))
    audit = disclosure.get("audit")
    if audit is not None:
        if not isinstance(audit, dict):
            errors.append("disclosure.audit must be an object")
        else:
            audit_level = audit.get("level")
            if audit_level is not None and audit_level not in DISCLOSURE_LEVELS:
                errors.append(f"disclosure.audit.level must be one of {', '.join(DISCLOSURE_LEVELS)}")
            errors.extend(_validate_disclosure_fields(audit.get("fields"), "disclosure.audit.fields"))
    return errors


def _validate_disclosure_fields(fields: Any, label: str) -> list[str]:
    if fields is None:
        return []
    if not isinstance(fields, dict):
        return [f"{label} must be an object"]
    errors: list[str] = []
    for name, value in fields.items():
        if name not in DISCLOSURE_FIELDS:
            errors.append(f"{label}: unknown field {name!r}")
        elif not isinstance(value, bool):
            errors.append(f"{label}.{name} must be a boolean")
    return errors


def _validate_diagnostics(diagnostics: Any) -> list[str]:
    if diagnostics is None:
        return []
    if not isinstance(diagnostics, list):
        return ["diagnostics must be a list"]
    errors: list[str] = []
    for index, entry in enumerate(diagnostics):
        if not isinstance(entry, dict):
            errors.append(f"diagnostics[{index}] must be an object")
            continue
        entity_id = entry.get("entity_id")
        if not isinstance(entity_id, str) or not entity_id.strip():
            errors.append(f"diagnostics[{index}].entity_id is required")
        fields = entry.get("fields")
        if not isinstance(fields, list) or not fields or not all(isinstance(item, str) for item in fields):
            errors.append(f"diagnostics[{index}].fields must be a non-empty list of field names")
        if _parse_expiry(entry.get("expires_at")) is None:
            errors.append(f"diagnostics[{index}].expires_at must be an ISO 8601 timestamp with a timezone")
    return errors


def _validate_denial_rate_limit(raw: Any) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, dict):
        return ["denial_rate_limit must be an object"]
    errors: list[str] = []
    limit = raw.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool) or limit <= 0):
        errors.append("denial_rate_limit.limit must be a positive integer")
    window = raw.get("window_seconds")
    if window is not None and (not isinstance(window, (int, float)) or isinstance(window, bool) or window <= 0):
        errors.append("denial_rate_limit.window_seconds must be a positive number")
    return errors
