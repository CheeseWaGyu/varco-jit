"""Real camera snapshots for Varco.

The Authority answers ``camera_snapshot`` requests through the
``hass.varco_jit_camera_snapshot`` hook (see ``authority.py``). Nothing
registered that hook, so snapshots always fell back to the placeholder
string ``snapshot:<entity_id>``. This module is the real implementation:
it fetches the camera's current image from Home Assistant and registers
the hook during integration setup.

The hook contract is a base64-encoded JPEG string, matching the
``image/jpeg`` content type the Authority reports for the payload.
Cameras whose integrations only expose a stream still answer through
Home Assistant's camera image API when they can produce a still; when
they cannot, the Home Assistant error propagates and the consumer gets
an error instead of a placeholder.
"""
from __future__ import annotations

import base64
import io
import logging

_LOGGER = logging.getLogger(__name__)

# The stock bridge drops WebSocket messages over 2 MiB (bridge
# MAX_MESSAGE_SIZE). The snapshot travels as base64 inside an encrypted
# JSON envelope, so keep the encoded image well below that limit.
MAX_ENCODED_LENGTH = 1_400_000
MAX_DIMENSION = 1280
_MIN_DIMENSION = 320
_JPEG_QUALITY = 85

_HOOK_ATTR = "varco_jit_camera_snapshot"


def async_register_camera_snapshot(hass) -> None:
    """Register the snapshot hook the Authority looks for on hass.

    Idempotent: an existing hook (ours or another provider's) is kept.
    """
    if getattr(hass, _HOOK_ATTR, None) is not None:
        return

    async def _varco_jit_camera_snapshot(entity_id: str) -> str:
        return await async_get_snapshot_base64(hass, entity_id)

    setattr(hass, _HOOK_ATTR, _varco_jit_camera_snapshot)


def async_unregister_camera_snapshot(hass) -> None:
    """Remove the hook registered by async_register_camera_snapshot."""
    hook = getattr(hass, _HOOK_ATTR, None)
    if hook is not None and getattr(hook, "__name__", None) == "_varco_jit_camera_snapshot":
        delattr(hass, _HOOK_ATTR)


async def async_get_snapshot_base64(hass, entity_id: str) -> str:
    """Return the camera's current image as a base64-encoded JPEG string."""
    from homeassistant.components.camera import async_get_image

    image = await async_get_image(hass, entity_id)
    content = bytes(image.content)
    encoded = base64.b64encode(content).decode("ascii")
    if image.content_type == "image/jpeg" and len(encoded) <= MAX_ENCODED_LENGTH:
        return encoded
    jpeg = await hass.async_add_executor_job(_as_jpeg_under_limit, content)
    return base64.b64encode(jpeg).decode("ascii")


def _as_jpeg_under_limit(content: bytes) -> bytes:
    """Transcode image bytes to JPEG, shrinking until the base64 fits.

    Runs in an executor: Pillow is blocking and ships with Home
    Assistant, so no new dependency is introduced.
    """
    from PIL import Image

    with Image.open(io.BytesIO(content)) as img:
        img.load()
        if img.mode != "RGB":
            img = img.convert("RGB")
        if max(img.size) > MAX_DIMENSION:
            img.thumbnail((MAX_DIMENSION, MAX_DIMENSION))
        while True:
            buffer = io.BytesIO()
            img.save(buffer, "JPEG", quality=_JPEG_QUALITY)
            data = buffer.getvalue()
            if len(base64.b64encode(data)) <= MAX_ENCODED_LENGTH:
                return data
            if max(img.size) <= _MIN_DIMENSION:
                _LOGGER.warning(
                    "Varco JIT camera snapshot still exceeds %d encoded bytes at %s; sending anyway",
                    MAX_ENCODED_LENGTH,
                    img.size,
                )
                return data
            img.thumbnail((int(img.size[0] * 0.75), int(img.size[1] * 0.75)))
