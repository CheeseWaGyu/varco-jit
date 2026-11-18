"""Authority-level tests for JIT (state_condition) grant restrictions.

Modelled on tests/test_grant_restrictions.py: a paired consumer talks to
VarcoAuthority through handle_plaintext against a FakeHass.
"""
import asyncio

from custom_components.varco_jit.authority import VarcoAuthority
from custom_components.varco_jit.crypto import b64url_encode, generate_consumer_keypair, sign_access_request, sign_authenticate
from custom_components.varco_jit.storage import MemoryVarcoStore

TEST_BINDING = b64url_encode(b"\x01" * 32)

VACUUM_MANIFEST = {"name": "Demo", "version": "1", "actions": ["vacuum.start@vacuum.robot"]}

AWAY_RESTRICTION = {
    "id": "vacuum-only-when-away",
    "type": "jit",
    "enabled": True,
    "applies_to": "vacuum.start@vacuum.robot",
    "params": {
        "conditions": [{"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home"}],
        "match": "all",
    },
}


class FakeStates:
    def __init__(self):
        self.values = {
            "device_tracker.phone": {"entity_id": "device_tracker.phone", "state": "home", "attributes": {}},
            "vacuum.robot": {"entity_id": "vacuum.robot", "state": "docked", "attributes": {}},
            "sensor.temperature": {"entity_id": "sensor.temperature", "state": "21", "attributes": {}},
            "light.cucina": {"entity_id": "light.cucina", "state": "off", "attributes": {}},
        }

    def get(self, entity_id):
        return self.values.get(entity_id)

    def async_entity_ids(self):
        return list(self.values)


class FakeServices:
    def __init__(self):
        self.calls = []

    async def async_call(self, domain, service, service_data, blocking=True, target=None):
        self.calls.append((domain, service, service_data, target, blocking))


class FakeHass:
    def __init__(self):
        self.states = FakeStates()
        self.services = FakeServices()


def iter_seconds():
    current = {"value": 1000.0}

    def next_second():
        current["value"] += 1.0
        return current["value"]

    return next_second


async def paired_authority(manifest):
    store = MemoryVarcoStore()
    hass = FakeHass()
    authority = VarcoAuthority(store=store, hass=hass, monotonic_provider=iter_seconds())
    consumer = generate_consumer_keypair()
    nonce = "request-nonce"
    pending = await authority.handle_plaintext(
        "request-session",
        {
            "type": "access_request",
            "consumer_pk": consumer["public_key"],
            "manifest": manifest,
            "nonce": nonce,
            "signature": sign_access_request(consumer["private_key"], nonce, manifest),
        },
    )
    grant = await authority.approve_request(pending["access_request_id"])
    auth_nonce = "auth-nonce"
    authenticated = await authority.handle_plaintext(
        "s1",
        channel_binding=TEST_BINDING,
        message={
            "type": "authenticate",
            "consumer_pk": consumer["public_key"],
            "nonce": auth_nonce,
            "signature": sign_authenticate(consumer["private_key"], auth_nonce, TEST_BINDING),
        },
    )
    assert authenticated["type"] == "authenticated"
    return authority, store, hass, grant


async def set_restrictions(store, grant, restrictions):
    grant.restrictions = restrictions
    await store.async_upsert_grant(grant)


def set_state(hass, entity_id, state):
    hass.states.values[entity_id] = {"entity_id": entity_id, "state": state, "attributes": {}}


async def start_vacuum(authority):
    return await authority.handle_plaintext(
        "s1",
        {"type": "call_service", "domain": "vacuum", "service": "start", "target": {"entity_id": "vacuum.robot"}},
    )


def test_vacuum_denied_while_phone_home_with_structured_cause():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [AWAY_RESTRICTION])

        denied = await start_vacuum(authority)

        assert denied["type"] == "error"
        assert denied["code"] == "jit_denied"
        assert hass.services.calls == []
        assert denied["jit"]["restriction_id"] == "vacuum-only-when-away"
        assert denied["jit"]["operation"] == "action"
        assert denied["jit"]["match"] == "all"
        assert denied["jit"]["evaluated_at"]
        failure = denied["jit"]["failures"][0]
        assert failure["entity_id"] == "device_tracker.phone"
        assert failure["operator"] == "is_not"
        assert failure["expected"] == "home"
        assert failure["reason"] == "condition_not_met"
        # device_tracker.phone is not readable under this grant and
        # reveal_actual is unset: the actual value stays hidden.
        assert failure["actual"] is None
        assert failure["actual_redacted"] is True
        assert "home" in denied["message"]

        audit = await store.async_audit_events()
        jit_events = [event for event in audit if event["event"] == "jit_denied"]
        assert len(jit_events) == 1
        details = jit_events[-1]["details"]
        assert details["restriction_id"] == "vacuum-only-when-away"
        assert details["domain"] == "vacuum"
        assert details["service"] == "start"
        # Audit never stores actual state values.
        assert "actual" not in str(details["failures"])

    asyncio.run(run())


def test_vacuum_allowed_when_phone_away():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [AWAY_RESTRICTION])
        set_state(hass, "device_tracker.phone", "not_home")

        allowed = await start_vacuum(authority)

        assert allowed["type"] == "service_called"
        assert len(hass.services.calls) == 1

    asyncio.run(run())


def test_actual_revealed_when_condition_entity_is_readable():
    async def run():
        manifest = {**VACUUM_MANIFEST, "read_entities": ["device_tracker.phone"]}
        authority, store, hass, grant = await paired_authority(manifest)
        await set_restrictions(store, grant, [AWAY_RESTRICTION])

        denied = await start_vacuum(authority)

        assert denied["code"] == "jit_denied"
        failure = denied["jit"]["failures"][0]
        assert failure["actual"] == "home"
        assert "actual_redacted" not in failure
        assert "(actual: home)" in denied["message"]

    asyncio.run(run())


def test_actual_revealed_when_reveal_actual_is_true():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        restriction = {
            **AWAY_RESTRICTION,
            "params": {**AWAY_RESTRICTION["params"], "reveal_actual": True},
        }
        await set_restrictions(store, grant, [restriction])

        denied = await start_vacuum(authority)

        assert denied["code"] == "jit_denied"
        assert denied["jit"]["failures"][0]["actual"] == "home"

    asyncio.run(run())


def test_per_condition_reveal_actual_reveals_only_that_entity():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [{
            "id": "two-conditions",
            "type": "jit",
            "enabled": True,
            "applies_to": "vacuum.start@vacuum.robot",
            "params": {
                "conditions": [
                    {"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home", "reveal_actual": True},
                    {"entity_id": "sensor.temperature", "operator": "above", "value": 30},
                ],
                "match": "all",
            },
        }])

        denied = await start_vacuum(authority)

        assert denied["code"] == "jit_denied"
        failures = denied["jit"]["failures"]
        assert len(failures) == 2
        # The phone condition opted in per-condition: its actual is shown
        # even though the restriction has no reveal_actual and the grant
        # cannot read the phone.
        assert failures[0]["entity_id"] == "device_tracker.phone"
        assert failures[0]["actual"] == "home"
        assert "actual_redacted" not in failures[0]
        # The temperature condition has no directive: it inherits the
        # restriction default (hidden), so its actual stays redacted.
        assert failures[1]["entity_id"] == "sensor.temperature"
        assert failures[1]["actual"] is None
        assert failures[1]["actual_redacted"] is True

    asyncio.run(run())


def test_per_condition_reveal_actual_false_overrides_restriction_default():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        restriction = {
            **AWAY_RESTRICTION,
            "params": {
                "conditions": [
                    {"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home", "reveal_actual": False},
                ],
                "match": "all",
                "reveal_actual": True,
            },
        }
        await set_restrictions(store, grant, [restriction])

        denied = await start_vacuum(authority)

        assert denied["code"] == "jit_denied"
        failure = denied["jit"]["failures"][0]
        assert failure["actual"] is None
        assert failure["actual_redacted"] is True

    asyncio.run(run())


def test_per_condition_reveal_actual_false_overrides_grant_readability():
    async def run():
        manifest = {**VACUUM_MANIFEST, "read_entities": ["device_tracker.phone"]}
        authority, store, hass, grant = await paired_authority(manifest)
        restriction = {
            **AWAY_RESTRICTION,
            "params": {
                "conditions": [
                    {"entity_id": "device_tracker.phone", "operator": "is_not", "value": "home", "reveal_actual": False},
                ],
                "match": "all",
            },
        }
        await set_restrictions(store, grant, [restriction])

        denied = await start_vacuum(authority)

        assert denied["code"] == "jit_denied"
        failure = denied["jit"]["failures"][0]
        assert failure["actual"] is None
        assert failure["actual_redacted"] is True

    asyncio.run(run())


def test_numeric_sensor_condition():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [{
            "id": "warm-enough",
            "type": "state_condition",
            "enabled": True,
            "applies_to": "vacuum.start@vacuum.robot",
            "params": {"conditions": [{"entity_id": "sensor.temperature", "operator": "above", "value": 30}]},
        }])

        denied = await start_vacuum(authority)
        assert denied["code"] == "jit_denied"
        assert denied["jit"]["failures"][0]["reason"] == "condition_not_met"

        set_state(hass, "sensor.temperature", "35")
        allowed = await start_vacuum(authority)
        assert allowed["type"] == "service_called"

    asyncio.run(run())


def test_match_any_allows_when_one_condition_passes():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [{
            "id": "any-of",
            "type": "jit",
            "enabled": True,
            "applies_to": "actions",
            "params": {
                "match": "any",
                "conditions": [
                    {"entity_id": "device_tracker.phone", "operator": "is", "value": "work"},
                    {"entity_id": "sensor.temperature", "operator": "below", "value": 25},
                ],
            },
        }])

        allowed = await start_vacuum(authority)
        assert allowed["type"] == "service_called"

        set_state(hass, "sensor.temperature", "28")
        denied = await start_vacuum(authority)
        assert denied["code"] == "jit_denied"
        assert len(denied["jit"]["failures"]) == 2

    asyncio.run(run())


def test_missing_entity_fails_closed():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [{
            "id": "needs-missing",
            "type": "jit",
            "enabled": True,
            "applies_to": "actions",
            "params": {"conditions": [{"entity_id": "sensor.missing", "operator": "is", "value": "x"}]},
        }])

        denied = await start_vacuum(authority)
        assert denied["code"] == "jit_denied"
        assert denied["jit"]["failures"][0]["reason"] == "entity_unavailable"
        assert hass.services.calls == []

    asyncio.run(run())


def test_malformed_condition_fails_closed():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [{
            "id": "broken",
            "type": "jit",
            "enabled": True,
            "applies_to": "actions",
            "params": {"conditions": [{"entity_id": "sensor.temperature", "operator": "approx", "value": 1}]},
        }])
        denied = await start_vacuum(authority)
        assert denied["code"] == "jit_denied"
        assert denied["jit"]["failures"][0]["reason"] == "invalid_condition"

        await set_restrictions(store, grant, [{
            "id": "empty",
            "type": "jit",
            "enabled": True,
            "applies_to": "actions",
            "params": {},
        }])
        denied_empty = await start_vacuum(authority)
        assert denied_empty["code"] == "jit_denied"
        assert hass.services.calls == []

    asyncio.run(run())


def test_match_any_with_invalid_condition_denies_action():
    """Regression (audit): match=any plus one passing condition must not
    bypass a second, malformed condition."""
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [{
            "id": "any-with-typo",
            "type": "jit",
            "enabled": True,
            "applies_to": "actions",
            "params": {
                "match": "any",
                "conditions": [
                    {"entity_id": "sensor.temperature", "operator": "below", "value": 25},  # passes (21)
                    {"entity_id": "device_tracker.phone", "operator": "is_not_home", "value": "home"},  # invalid operator
                ],
            },
        }])

        denied = await start_vacuum(authority)
        assert denied["code"] == "jit_denied"
        assert hass.services.calls == []

    asyncio.run(run())


def test_jit_restriction_for_other_action_does_not_block():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [{
            "id": "lights-only",
            "type": "jit",
            "enabled": True,
            "applies_to": "light.turn_on@light.cucina",
            "params": {"conditions": [{"entity_id": "device_tracker.phone", "operator": "is", "value": "work"}]},
        }])

        allowed = await start_vacuum(authority)
        assert allowed["type"] == "service_called"

    asyncio.run(run())


def test_jit_denial_does_not_consume_rate_limit_budget():
    async def run():
        authority, store, hass, grant = await paired_authority(VACUUM_MANIFEST)
        await set_restrictions(store, grant, [
            AWAY_RESTRICTION,
            {
                "id": "once-an-hour",
                "type": "rate_limit",
                "enabled": True,
                "applies_to": "actions",
                "params": {"limit": 1, "window_seconds": 3600},
            },
        ])

        denied = await start_vacuum(authority)
        assert denied["code"] == "jit_denied"

        set_state(hass, "device_tracker.phone", "not_home")
        allowed = await start_vacuum(authority)
        assert allowed["type"] == "service_called"

        rate_denied = await start_vacuum(authority)
        assert rate_denied["code"] == "permission_denied"
        assert len(hass.services.calls) == 1

    asyncio.run(run())
