# Varco JIT — just-in-time state conditions

Varco JIT is an experimental fork of Varco. It installs as a separate
Home Assistant integration (domain `varco_jit`, panel at `/varco-jit`)
alongside the stock `varco` integration, and it speaks the exact same
wire protocol: same bridge, same `@varco/client`, same crypto. The only
behavioural addition is a new grant restriction type: **JIT
(just-in-time) state conditions**.

## What JIT is

A JIT restriction gates an operation on the *current state of other
Home Assistant entities*, evaluated by the Authority at the moment the
operation is attempted — immediately before the service call (or read,
subscription, history query, or camera snapshot) is performed. If the
conditions do not hold, the Authority denies the operation and returns
a structured cause to the consumer.

Example: a cleaning robot may only start while the owner's phone is
not home.

```json
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
```

With this restriction on the grant, `vacuum.start@vacuum.robot` succeeds
only while `device_tracker.phone` is not `home`.

## How JIT differs from `template` restrictions

Both gate operations on Home Assistant state, but:

| | `template` | `jit` |
| --- | --- | --- |
| Condition form | Free-form Jinja2 string (`params.value_template`) | Structured data: a list of `{entity_id, attribute?, operator, value?}` conditions |
| Denial reason | One generic reason (`template_denied`, `template_error`, `template_not_configured`) | Structured per-condition failures: entity, attribute, operator, expected value, failure reason, and (when allowed) the actual value |
| Error code | `permission_denied` | `jit_denied`, with a machine-readable `jit` payload (see below) |
| Expressiveness | Arbitrary Jinja (computed values, multiple entities in one expression) | Deliberately limited to single-entity comparisons that can be explained and audited |

Use `template` for computed logic; use `jit` when the consumer (for
example an AI agent) needs to know *why* it was denied so it can react —
wait, retry later, or explain the block to the user.

## Restriction spec

The restriction uses the generic restriction shape. `type` is `jit`
(the alias `state_condition` is accepted everywhere `jit` is).
`applies_to` uses the same selectors as every other restriction type
(`grant`, `actions`, `read`, `history`, `camera`, or an action selector
such as `vacuum.start@vacuum.robot`).

`params`:

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| `conditions` | array of condition objects | — (required, non-empty) | The conditions to evaluate. |
| `match` | `"all"` \| `"any"` | `"all"` | `all`: every condition must pass. `any`: at least one must pass. |
| `reveal_actual` | boolean | `false` | Allow actual state values in the consumer-facing denial for condition entities the grant cannot already read (see “Reveal rule”). |

Condition object:

| Key | Type | Meaning |
| --- | --- | --- |
| `entity_id` | string (required) | Entity whose state (or attribute) is checked. Read fresh at evaluation time. |
| `attribute` | string (optional) | Check this entry of the entity's `attributes` instead of its state. |
| `operator` | string (required) | One of the operators below. |
| `value` | any | Expected value. Required for every operator except `exists` / `not_exists`. For `in` / `not_in` it must be a list. |

Operators (symbol aliases in parentheses):

| Operator | Passes when |
| --- | --- |
| `is` (`==`) | Actual equals `value` (numeric-aware: `"21"` equals `21`). |
| `is_not` (`!=`) | Actual does not equal `value`. |
| `in` | Actual equals any element of the `value` list. |
| `not_in` | Actual equals no element of the `value` list. |
| `above` (`>`) | Actual is numerically greater than `value`. |
| `below` (`<`) | Actual is numerically smaller than `value`. |
| `gte` (`>=`) | Actual is numerically greater than or equal to `value`. |
| `lte` (`<=`) | Actual is numerically smaller than or equal to `value`. |
| `exists` | The entity exists (any state, including `unavailable`). |
| `not_exists` | The entity is truly absent from Home Assistant. |

## Evaluation order

Restrictions are enforced in `VarcoAuthority._enforce_restrictions` in
this order:

1. Stateless restrictions (`expiry`, `schedule`, `pin`) via
   `policy.evaluate_restrictions`.
2. `template` restrictions.
3. **JIT restrictions** — states are read fresh here, via
   `VarcoAuthority._state_payload`, immediately before the operation
   proceeds. This is the just-in-time point.
4. `rate_limit` check-and-record. A JIT denial happens *before* this
   step, so a denied attempt does not consume rate-limit budget.

## The `jit_denied` error

A JIT denial returns error code `jit_denied` (not the generic
`permission_denied`), with a structured `jit` object. The `@varco/client`
transports copy `payload.jit` onto the rejected `Error` object
(`error.code === "jit_denied"`, `error.jit`), so agents receive the
cause programmatically, not just as message text.

```json
{
  "type": "error",
  "request_id": "req-42",
  "code": "jit_denied",
  "message": "JIT restriction 'vacuum-only-when-away' denied: device_tracker.phone is_not home",
  "jit": {
    "restriction_id": "vacuum-only-when-away",
    "operation": "action",
    "evaluated_at": "2026-11-17T04:30:00+00:00",
    "match": "all",
    "failures": [
      {
        "entity_id": "device_tracker.phone",
        "attribute": null,
        "operator": "is_not",
        "expected": "home",
        "reason": "condition_not_met",
        "actual": null,
        "actual_redacted": true
      }
    ]
  }
}
```

Failure `reason` values:

- `condition_not_met` — the entity has a usable value, it just does not
  satisfy the comparison (including a missing attribute).
- `entity_unavailable` — the entity is missing, or its state is
  `unknown` / `unavailable`.
- `non_numeric` — a numeric operator was used but the actual value
  does not parse as a number. (A non-numeric *expected* value is a
  configuration error: `invalid_condition`.)
- `state_lookup_error` — reading the entity's state raised an error.
  A lookup error is never treated as absence, so it fails every
  operator, including `not_exists`.
- `invalid_condition` — the condition itself is malformed (no
  `entity_id`, unknown operator, missing `value`, …). Malformed
  restrictions fail closed and the validation problems are also listed
  under `jit.errors` when available.

## Reveal rule (privacy)

The denial tells the consumer what was *expected*, but the *actual*
state of a condition entity is sensitive: a JIT condition often
references entities (presence trackers, alarm panels) that the consumer
was deliberately not given read access to. Therefore:

- `actual` is included in the consumer-facing payload and message only
  when `reveal_actual` is `true` in the restriction params, **or** the
  condition entity is already readable under the grant
  (`entity_allowed` against the manifest's `read_entities`, wildcards
  included).
- Otherwise `actual` is `null` and the failure carries
  `"actual_redacted": true`.
- The Home Assistant audit log **never** stores actual values,
  regardless of the reveal rule (see below).

## Audit and Home Assistant log behaviour

A JIT denial produces exactly one primary audit event, `jit_denied`
(the generic `restriction_denied` event is *not* also emitted for JIT):

```json
{
  "event": "jit_denied",
  "grant_id": "…",
  "details": {
    "operation": "action",
    "restriction_id": "vacuum-only-when-away",
    "domain": "vacuum",
    "service": "start",
    "entity_ids": ["vacuum.robot"],
    "failures": [
      {"entity_id": "device_tracker.phone", "attribute": null, "operator": "is_not", "expected": "home", "reason": "condition_not_met"}
    ]
  }
}
```

`domain` / `service` / `entity_ids` are included when the operation
context provides them. Per the repository invariant, audit details
never contain entity states: failures are summarized as
`{entity_id, attribute, operator, expected, reason}` with no `actual`.

The Authority also writes a `WARNING` line to the Home Assistant log
with the same non-sensitive summary (restriction id, operation, failing
entity ids / operators / reasons).

## Fail-closed rules

- Missing entity: fails every positive operator
  (`entity_unavailable`). `not_exists` passes *only* when the entity is
  truly absent; `exists` passes whenever the entity is present, even
  with state `unavailable`.
- State `unknown` or `unavailable`: fails every positive operator
  (`entity_unavailable`) — including `is_not`, so an unreadable presence
  tracker can never accidentally satisfy an “is not home” condition.
- Numeric operator on a non-numeric actual value: fails
  (`non_numeric`). A non-numeric expected value for a numeric operator
  is a configuration error (`invalid_condition`).
- Malformed restriction (no conditions, bad operator, missing value,
  bad `match`): fails (`invalid_condition`). Validation errors deny the
  whole restriction **regardless of `match`** — under `match: "any"` a
  broken condition is never skipped just because another condition
  passes.
- State lookup error: fails (`state_lookup_error`) for every operator.
  `not_exists` passes only when the lookup cleanly returns “no such
  entity”; an error while reading state is not absence.
- Disabled restrictions (`enabled: false`) are skipped, as with all
  restriction types.

## Managing JIT restrictions

From the Varco JIT panel: open a grant card → **Restrictions** → choose
**JIT state condition — allow only when entity states match**. The form
takes the conditions as a JSON array, a `match` select, and a
`reveal_actual` checkbox.

Programmatically, restrictions are replaced through the admin
WebSocket command `varco_jit/update_grant_restrictions` (the JIT
counterpart of `varco/update_grant_restrictions`), or stored on a share
/ preapproved grant at creation time. Updating restrictions clears the
grant's active subscriptions, as with any restriction change.

End-to-end vacuum example:

1. The consumer's grant includes action `vacuum.start@vacuum.robot`
   (and no read access to `device_tracker.phone`).
2. The owner adds the `vacuum-only-when-away` restriction above via the
   panel or `varco_jit/update_grant_restrictions`.
3. While the phone is `home`, the consumer's `call_service` is denied
   with the `jit_denied` payload above; the vacuum never starts, no
   rate-limit budget is consumed, and a `jit_denied` audit event is
   recorded without the phone's state value.
4. When the phone leaves (`not_home`), the same call passes the JIT
   gate and the vacuum starts.

## Limitations

- The panel form edits conditions as a raw JSON array; there is no
  per-condition visual builder yet.
- Conditions compare one entity's state/attribute per condition; there
  is no cross-entity arithmetic (use a `template` restriction for
  computed logic).
- JIT gates the moment of the operation only. It does not stop an
  already-running operation when a condition later flips, and it does
  not proactively notify consumers when conditions change (consumers
  can subscribe to the condition entities if the grant allows it).
- Evaluation reads state through the Authority's normal state payload;
  entities provided only through custom `hass` hooks follow the same
  payload shape.

## Implementation map

- `custom_components/varco_jit/jit.py` — condition spec, validation
  (`validate_conditions`), pure evaluation (`evaluate_jit_params`),
  restriction selection (`jit_restrictions`), audit summary
  (`audit_failure`).
- `custom_components/varco_jit/policy.py` — `_evaluate_restriction`
  defers `jit` / `state_condition` to the Authority, like `template`.
- `custom_components/varco_jit/authority.py` —
  `_check_jit_restrictions` / `_jit_denied_error` in
  `_enforce_restrictions`, between template and rate-limit checks.
- `packages/client/src/client.ts`, `transport.ts`,
  `transport-noble.ts` — error rejections carry `jit` (and `details`).
- `custom_components/varco_jit/frontend/src/panel.ts` — panel form,
  restriction row summary, `jit_denied` audit label.
- Tests: `tests/test_jit_conditions.py`,
  `tests/test_jit_restrictions.py`.
