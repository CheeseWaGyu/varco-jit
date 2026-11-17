"""Share manifests must not contain wildcard action scopes.

Share links and preapproved grants are minted from a manifest without a
per-claim owner approval step, so a wildcard such as
``lock.*@lock.front_door`` would silently grant every service of a domain
on the entity. The Authority rejects wildcard action scopes on both
share-creation paths; explicit ``domain.service@entity_id`` scopes and
read-only shares stay allowed. The normal access-request approval flow is
not affected.
"""
import asyncio

import pytest

from custom_components.varco_jit.authority import VarcoAuthority
from custom_components.varco_jit.manifest import ManifestError, reject_wildcard_share_actions
from custom_components.varco_jit.storage import MemoryVarcoStore
from tests.test_authority_dataplane import FakeHass


def make_authority():
    return VarcoAuthority(store=MemoryVarcoStore(), hass=FakeHass())


@pytest.mark.parametrize(
    "action",
    [
        "lock.*@lock.front_door",
        "*@lock.front_door",
        "lock.*",
        "lock.lock@*",
        "*",
    ],
)
def test_create_share_rejects_wildcard_action_scopes(action):
    async def run():
        authority = make_authority()
        manifest = {"name": "Front door", "version": "1", "read_entities": ["lock.front_door"], "actions": [action]}
        with pytest.raises(ManifestError, match="wildcard"):
            await authority.create_share("Front door", manifest)

    asyncio.run(run())


def test_create_preapproved_grant_rejects_wildcard_action_scopes():
    async def run():
        authority = make_authority()
        manifest = {"name": "Front door", "version": "1", "read_entities": ["lock.front_door"], "actions": ["*@lock.front_door"]}
        with pytest.raises(ManifestError, match="wildcard"):
            await authority.create_preapproved_grant(manifest)

    asyncio.run(run())


def test_create_share_allows_explicit_action_scopes():
    async def run():
        authority = make_authority()
        manifest = {"name": "Front door", "version": "1", "read_entities": ["lock.front_door"], "actions": ["lock.lock@lock.front_door"]}
        share, secret = await authority.create_share("Front door", manifest)
        assert share.manifest["actions"] == ["lock.lock@lock.front_door"]
        assert secret

    asyncio.run(run())


def test_create_share_allows_read_only_manifest():
    async def run():
        authority = make_authority()
        manifest = {"name": "Temperature", "version": "1", "read_entities": ["sensor.temp"], "subscriptions": ["sensor.temp"]}
        share, _secret = await authority.create_share("Temperature", manifest)
        assert "actions" not in share.manifest

    asyncio.run(run())


def test_create_preapproved_grant_allows_explicit_action_scopes():
    async def run():
        authority = make_authority()
        manifest = {"name": "Gate", "version": "1", "read_entities": ["sensor.temp"], "actions": ["cover.open_cover@cover.gate"]}
        grant, identity = await authority.create_preapproved_grant(manifest)
        assert grant.manifest["actions"] == ["cover.open_cover@cover.gate"]
        assert identity["public_key"]

    asyncio.run(run())


def test_reject_wildcard_share_actions_helper():
    reject_wildcard_share_actions({"name": "x", "actions": ["light.turn_on@light.kitchen"]})
    reject_wildcard_share_actions({"name": "x"})
    reject_wildcard_share_actions({"name": "x", "actions": []})
    with pytest.raises(ManifestError):
        reject_wildcard_share_actions({"name": "x", "actions": ["light.*@light.kitchen"]})
