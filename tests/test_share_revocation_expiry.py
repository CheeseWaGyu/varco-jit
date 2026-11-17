"""Share revocation cascades to claimed grants; expiry values fail closed.

Two audit findings are covered here:

1. Revoking or deleting a share must also revoke the grants that were
   already claimed from it. Previously only the share record was flagged,
   so claimed consumers kept access until their grant expired on its own.
   Revocation is effective for live sessions because ``_authenticate``
   and ``_require_grant`` re-check ``grant.revoked`` on every message.

2. An ``expires_at`` that cannot be parsed as ISO 8601 must never mean
   "never expires". Creation/approval validates the value up front
   (``ManifestError``), the runtime expiry check fails closed, and the
   storage purges treat unparseable expiries as expired.
"""
import asyncio
import hashlib

import pytest

from custom_components.varco_jit.authority import VarcoAuthority
from custom_components.varco_jit.crypto import generate_consumer_keypair, sign_access_request, sign_authenticate
from custom_components.varco_jit.manifest import ManifestError
from custom_components.varco_jit.models import Grant, Share
from custom_components.varco_jit.storage import MemoryVarcoStore
from tests.test_authority_dataplane import TEST_BINDING, FakeHass

MANIFEST = {"name": "One seat", "version": "1", "read_entities": ["sensor.temp"]}


def make_authority():
    store = MemoryVarcoStore()
    return VarcoAuthority(store=store, hass=FakeHass()), store


async def claim_share(authority, session_id, share, secret, consumer):
    return await authority.handle_plaintext(session_id, {
        "type": "claim_share",
        "share_id": share.share_id,
        "secret": secret,
        "consumer_pk": consumer["public_key"],
    })


def authenticate_message(consumer):
    auth_nonce = "auth-nonce"
    return {
        "type": "authenticate",
        "consumer_pk": consumer["public_key"],
        "nonce": auth_nonce,
        "signature": sign_authenticate(consumer["private_key"], auth_nonce, TEST_BINDING),
    }


def test_revoke_share_revokes_claimed_grants_only():
    async def run():
        authority, store = make_authority()
        share, secret = await authority.create_share("One seat", MANIFEST, max_claims=1)
        other_share, other_secret = await authority.create_share("Other seat", MANIFEST, max_claims=1)
        consumer = generate_consumer_keypair()
        other_consumer = generate_consumer_keypair()

        claimed = await claim_share(authority, "claim", share, secret, consumer)
        assert claimed["type"] == "share_claimed"
        other_claimed = await claim_share(authority, "claim-other", other_share, other_secret, other_consumer)
        assert other_claimed["type"] == "share_claimed"

        # The claimed grant works on the data plane before revocation.
        ok = await authority.handle_plaintext("claim", {"type": "get_states", "request_id": "r1", "entity_ids": ["sensor.temp"]})
        assert ok["type"] == "states"

        await authority.revoke_share(share.share_id)

        grant = await store.async_get_grant_by_consumer(consumer["public_key"])
        assert grant.revoked is True
        assert grant.share_id == share.share_id

        # Data plane is denied on the very next message (per-message check).
        denied = await authority.handle_plaintext("claim", {"type": "get_states", "request_id": "r2", "entity_ids": ["sensor.temp"]})
        assert denied["type"] == "error"
        assert denied["code"] == "grant_revoked"

        # A fresh authenticate is denied too.
        auth = await authority.handle_plaintext("auth2", authenticate_message(consumer), channel_binding=TEST_BINDING)
        assert auth["type"] == "error"
        assert auth["code"] == "not_authorized"

        # The cascaded revocation is audit-logged with its source.
        events = await store.async_audit_events()
        cascaded = [e for e in events if e["event"] == "grant_revoked" and e["grant_id"] == grant.grant_id]
        assert len(cascaded) == 1
        assert cascaded[0]["details"] == {"source": "share_revoked", "share_id": share.share_id}

        # A grant claimed from a different share is untouched.
        other_grant = await store.async_get_grant_by_consumer(other_consumer["public_key"])
        assert other_grant.revoked is False
        other_auth = await authority.handle_plaintext("auth3", authenticate_message(other_consumer), channel_binding=TEST_BINDING)
        assert other_auth["type"] == "authenticated"

    asyncio.run(run())


def test_delete_share_revokes_claimed_grants():
    async def run():
        authority, store = make_authority()
        share, secret = await authority.create_share("One seat", MANIFEST, max_claims=1)
        consumer = generate_consumer_keypair()

        claimed = await claim_share(authority, "claim", share, secret, consumer)
        assert claimed["type"] == "share_claimed"

        await authority.delete_share(share.share_id)

        assert await store.async_get_share(share.share_id) is None
        grant = await store.async_get_grant_by_consumer(consumer["public_key"])
        assert grant.revoked is True

        auth = await authority.handle_plaintext("auth2", authenticate_message(consumer), channel_binding=TEST_BINDING)
        assert auth["type"] == "error"
        assert auth["code"] == "not_authorized"

        events = await store.async_audit_events()
        cascaded = [e for e in events if e["event"] == "grant_revoked" and e["grant_id"] == grant.grant_id]
        assert len(cascaded) == 1
        assert cascaded[0]["details"] == {"source": "share_deleted", "share_id": share.share_id}

    asyncio.run(run())


def test_create_share_rejects_unparseable_expires_at():
    async def run():
        authority, _store = make_authority()
        with pytest.raises(ManifestError, match="ISO 8601"):
            await authority.create_share("Bad expiry", MANIFEST, expires_at="not-a-date")
        with pytest.raises(ManifestError, match="ISO 8601"):
            await authority.create_share("Bad expiry", MANIFEST, expires_at=12345)

        # Valid ISO values (including date-only) and None still work.
        dated, _ = await authority.create_share("Dated", MANIFEST, expires_at="2999-01-01T00:00:00+00:00")
        assert dated.expires_at == "2999-01-01T00:00:00+00:00"
        date_only, _ = await authority.create_share("Date only", MANIFEST, expires_at="2999-01-01")
        assert date_only.expires_at == "2999-01-01"
        forever, _ = await authority.create_share("No expiry", MANIFEST)
        assert forever.expires_at is None

    asyncio.run(run())


def test_create_preapproved_grant_rejects_unparseable_expires_at():
    async def run():
        authority, _store = make_authority()
        with pytest.raises(ManifestError, match="ISO 8601"):
            await authority.create_preapproved_grant(MANIFEST, expires_at="not-a-date")

        grant, _identity = await authority.create_preapproved_grant(MANIFEST, expires_at="2999-01-01T00:00:00+00:00")
        assert grant.expires_at == "2999-01-01T00:00:00+00:00"

    asyncio.run(run())


def test_approve_request_rejects_unparseable_expires_at():
    async def run():
        authority, store = make_authority()
        consumer = generate_consumer_keypair()
        nonce = "nonce"
        pending = await authority.handle_plaintext("s1", {
            "type": "access_request",
            "consumer_pk": consumer["public_key"],
            "manifest": MANIFEST,
            "nonce": nonce,
            "signature": sign_access_request(consumer["private_key"], nonce, MANIFEST),
        })

        with pytest.raises(ManifestError, match="ISO 8601"):
            await authority.approve_request(pending["access_request_id"], expires_at="not-a-date")
        assert await store.async_get_grant_by_consumer(consumer["public_key"]) is None

        grant = await authority.approve_request(pending["access_request_id"], expires_at="2999-01-01T00:00:00+00:00")
        assert grant.expires_at == "2999-01-01T00:00:00+00:00"

    asyncio.run(run())


def test_share_with_garbage_stored_expiry_cannot_be_claimed():
    async def run():
        authority, store = make_authority()
        secret = "claim-secret"
        share = Share(
            share_id="garbage-expiry-share",
            name="Legacy share",
            manifest=MANIFEST,
            secret_hash=hashlib.sha256(secret.encode()).hexdigest(),
            max_claims=1,
            expires_at="not-a-date",
        )
        # Inserted directly through the store, bypassing creation validation,
        # to simulate legacy/corrupt persisted data.
        await store.async_upsert_share(share)

        denied = await claim_share(authority, "claim", share, secret, generate_consumer_keypair())
        assert denied["type"] == "error"
        assert denied["code"] == "share_unavailable"
        assert await store.async_list_grants() == []

    asyncio.run(run())


def test_purge_removes_records_with_garbage_expiry():
    async def run():
        store = MemoryVarcoStore()
        garbage_share = Share(
            share_id="garbage-share",
            name="Garbage",
            manifest=MANIFEST,
            secret_hash="unused",
            expires_at="not-a-date",
        )
        live_share = Share(
            share_id="live-share",
            name="Live",
            manifest=MANIFEST,
            secret_hash="unused",
            expires_at="2999-01-01T00:00:00+00:00",
        )
        await store.async_upsert_share(garbage_share)
        await store.async_upsert_share(live_share)

        garbage_grant = Grant(grant_id="garbage-grant", consumer_pk="garbage-pk", manifest=MANIFEST, expires_at="not-a-date")
        live_grant = Grant(grant_id="live-grant", consumer_pk="live-pk", manifest=MANIFEST, expires_at="2999-01-01T00:00:00+00:00")
        forever_grant = Grant(grant_id="forever-grant", consumer_pk="forever-pk", manifest=MANIFEST)
        await store.async_upsert_grant(garbage_grant)
        await store.async_upsert_grant(live_grant)
        await store.async_upsert_grant(forever_grant)

        assert await store.async_purge_expired_shares() == ["garbage-share"]
        assert await store.async_get_share("garbage-share") is None
        assert await store.async_get_share("live-share") is not None

        assert await store.async_purge_expired_grants() == ["garbage-grant"]
        assert await store.async_get_grant("garbage-grant") is None
        assert await store.async_get_grant("live-grant") is not None
        assert await store.async_get_grant("forever-grant") is not None

    asyncio.run(run())
