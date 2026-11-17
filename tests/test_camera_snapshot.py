import asyncio
import base64
import io
import sys
import types

import pytest

from custom_components.varco_jit.authority import VarcoAuthority
from custom_components.varco_jit.camera import (
    MAX_ENCODED_LENGTH,
    _as_jpeg_under_limit,
    async_get_snapshot_base64,
    async_register_camera_snapshot,
    async_unregister_camera_snapshot,
)
from custom_components.varco_jit.crypto import (
    b64url_encode,
    generate_consumer_keypair,
    sign_access_request,
    sign_authenticate,
)
from custom_components.varco_jit.storage import MemoryVarcoStore

TEST_BINDING = b64url_encode(b"\x01" * 32)


class FakeStates:
    def get(self, entity_id):
        return {"entity_id": entity_id, "state": "idle", "attributes": {}}


class FakeHass:
    def __init__(self):
        self.states = FakeStates()


async def paired_authority(hass):
    store = MemoryVarcoStore()
    authority = VarcoAuthority(store=store, hass=hass)
    consumer = generate_consumer_keypair()
    nonce = "nonce"
    manifest = {"name": "Demo", "version": "1", "camera_snapshots": ["camera.porta"]}
    pending = await authority.handle_plaintext("s1", {
        "type": "access_request",
        "consumer_pk": consumer["public_key"],
        "manifest": manifest,
        "nonce": nonce,
        "signature": sign_access_request(consumer["private_key"], nonce, manifest),
    })
    await authority.approve_request(pending["access_request_id"])
    auth_nonce = "auth-nonce"
    auth = await authority.handle_plaintext(
        "s1",
        channel_binding=TEST_BINDING,
        message={
            "type": "authenticate",
            "consumer_pk": consumer["public_key"],
            "nonce": auth_nonce,
            "signature": sign_authenticate(consumer["private_key"], auth_nonce, TEST_BINDING),
        },
    )
    assert auth["type"] == "authenticated"
    return authority


def test_camera_snapshot_returns_registered_hook_payload():
    async def run():
        hass = FakeHass()

        async def fake_snapshot(entity_id):
            assert entity_id == "camera.porta"
            return "aGVsbG8td29ybGQ="

        hass.varco_jit_camera_snapshot = fake_snapshot
        authority = await paired_authority(hass)
        response = await authority.handle_plaintext(
            "s1", {"type": "camera_snapshot", "entity_id": "camera.porta"}
        )
        assert response["type"] == "camera_snapshot"
        assert response["content_type"] == "image/jpeg"
        assert response["body"] == "aGVsbG8td29ybGQ="

    asyncio.run(run())


def test_camera_snapshot_hook_error_returns_generic_error_with_request_id():
    async def run():
        hass = FakeHass()

        async def failing_snapshot(entity_id):
            raise RuntimeError("Unable to get image from http://192.168.1.10/internal")

        hass.varco_jit_camera_snapshot = failing_snapshot
        authority = await paired_authority(hass)
        response = await authority.handle_plaintext(
            "s1",
            {"type": "camera_snapshot", "entity_id": "camera.porta", "request_id": "req-1"},
        )
        assert response["type"] == "error"
        assert response["request_id"] == "req-1"
        assert response["code"] == "camera_snapshot_failed"
        assert response["message"] == "Camera snapshot failed"
        assert "Unable to get image" not in response["message"]
        assert "192.168.1.10" not in response["message"]

    asyncio.run(run())


def test_camera_snapshot_without_hook_keeps_placeholder():
    async def run():
        authority = await paired_authority(FakeHass())
        response = await authority.handle_plaintext(
            "s1", {"type": "camera_snapshot", "entity_id": "camera.porta"}
        )
        assert response["type"] == "camera_snapshot"
        assert response["body"] == "snapshot:camera.porta"

    asyncio.run(run())


def test_register_and_unregister_hook():
    hass = types.SimpleNamespace()
    async_register_camera_snapshot(hass)
    hook = hass.varco_jit_camera_snapshot
    assert callable(hook)
    async_register_camera_snapshot(hass)
    assert hass.varco_jit_camera_snapshot is hook
    async_unregister_camera_snapshot(hass)
    assert not hasattr(hass, "varco_jit_camera_snapshot")


def test_as_jpeg_under_limit_transcodes_and_shrinks():
    Image = pytest.importorskip("PIL.Image")
    import random

    rng = random.Random(42)
    img = Image.new("RGB", (2400, 1800))
    img.putdata(
        [
            (rng.randrange(256), rng.randrange(256), rng.randrange(256))
            for _ in range(2400 * 1800)
        ]
    )
    buffer = io.BytesIO()
    img.save(buffer, "PNG")

    jpeg = _as_jpeg_under_limit(buffer.getvalue())

    assert jpeg[:2] == b"\xff\xd8"
    assert len(base64.b64encode(jpeg)) <= MAX_ENCODED_LENGTH


def test_get_snapshot_base64_passes_small_jpeg_through(monkeypatch):
    jpeg_bytes = b"\xff\xd8" + b"\x00" * 64
    camera_module = types.ModuleType("homeassistant.components.camera")

    async def fake_get_image(hass, entity_id):
        assert entity_id == "camera.porta"
        return types.SimpleNamespace(content_type="image/jpeg", content=jpeg_bytes)

    camera_module.async_get_image = fake_get_image
    components_module = types.ModuleType("homeassistant.components")
    components_module.camera = camera_module
    ha_module = types.ModuleType("homeassistant")
    ha_module.components = components_module
    monkeypatch.setitem(sys.modules, "homeassistant", ha_module)
    monkeypatch.setitem(sys.modules, "homeassistant.components", components_module)
    monkeypatch.setitem(sys.modules, "homeassistant.components.camera", camera_module)

    async def run():
        result = await async_get_snapshot_base64(types.SimpleNamespace(), "camera.porta")
        assert base64.b64decode(result) == jpeg_bytes

    asyncio.run(run())
