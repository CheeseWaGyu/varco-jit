"""Manifest validation and normalization.

Canonical manifest keys are snake_case. camelCase aliases (``readEntities``,
``cameraSnapshots``) are accepted on the wire for compatibility with already
deployed consumers, but the Authority stores only the canonical form.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

import voluptuous as vol

# canonical snake_case key -> accepted camelCase alias
_SCOPE_ALIASES = {
    "read_entities": "readEntities",
    "subscriptions": None,
    "history": None,
    "camera_snapshots": "cameraSnapshots",
    "actions": None,
}

_SCOPE_LIST = vol.All([vol.All(str, vol.Length(min=1))], list)

_MANIFEST_SCHEMA = vol.Schema(
    {
        vol.Required("name"): vol.All(str, vol.Length(min=1)),
        vol.Optional("version"): str,
        vol.Optional("icon"): str,
        vol.Optional("read_entities"): _SCOPE_LIST,
        vol.Optional("readEntities"): _SCOPE_LIST,
        vol.Optional("subscriptions"): _SCOPE_LIST,
        vol.Optional("history"): _SCOPE_LIST,
        vol.Optional("camera_snapshots"): _SCOPE_LIST,
        vol.Optional("cameraSnapshots"): _SCOPE_LIST,
        vol.Optional("actions"): _SCOPE_LIST,
        vol.Optional("dashboard"): dict,
    },
    extra=vol.ALLOW_EXTRA,
)


class ManifestError(ValueError):
    """Raised when an inbound manifest fails strict validation."""


def validate_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Strictly validate an inbound manifest and return the canonical form.

    Rejects conflicting snake_case/camelCase aliases instead of silently
    dropping one. Unknown extra keys are tolerated on the wire but not stored.
    """
    try:
        validated = _MANIFEST_SCHEMA(manifest)
    except vol.Invalid as err:
        raise ManifestError(str(err)) from err
    for canonical, alias in _SCOPE_ALIASES.items():
        if alias and canonical in validated and alias in validated:
            raise ManifestError(f"conflicting manifest keys: {canonical} and {alias}")
    return _canonicalize(validated)


def reject_wildcard_share_actions(manifest: dict[str, Any]) -> None:
    """Reject wildcard action scopes in a share manifest.

    Share links and preapproved grants are minted from a manifest without a
    per-claim owner approval step, so their action scopes must name explicit
    ``domain.service@entity_id`` pairs. A wildcard such as
    ``lock.*@lock.front_door`` would silently grant every service of a
    domain on the entity (including e.g. ``lock.unlock``). Raises
    :class:`ManifestError` on the first wildcard action scope found.
    """
    for action in manifest.get("actions") or []:
        if "*" in str(action):
            raise ManifestError(
                "Share manifests cannot contain wildcard action scopes; "
                "list explicit domain.service@entity_id actions"
            )


def validate_expires_at(expires_at: Any) -> None:
    """Reject an ``expires_at`` that is not a parseable ISO 8601 datetime.

    ``None`` means "no expiry" and is allowed. Any other value must be a
    string :func:`datetime.fromisoformat` can parse (a date-only string
    such as ``"2026-01-01"`` is valid ISO 8601 and accepted). Anything
    else raises :class:`ManifestError`, so a malformed expiry can never
    be stored and silently treated as "never expires" by the expiry
    checks, which fail closed on unparseable values.
    """
    if expires_at is None:
        return
    if not isinstance(expires_at, str):
        raise ManifestError("expires_at must be an ISO 8601 datetime string")
    try:
        datetime.fromisoformat(expires_at)
    except ValueError as err:
        raise ManifestError("expires_at must be an ISO 8601 datetime string") from err


def coerce_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    """Leniently normalize a stored manifest to canonical snake_case.

    Used when loading persisted requests/grants that may predate strict
    validation. Never raises; snake_case wins if both spellings are present.
    """
    return _canonicalize(manifest)


def _canonicalize(manifest: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in ("name", "version", "icon", "dashboard"):
        if key in manifest:
            result[key] = manifest[key]
    for canonical, alias in _SCOPE_ALIASES.items():
        value = manifest.get(canonical)
        if not isinstance(value, list) and alias:
            value = manifest.get(alias)
        if isinstance(value, list):
            result[canonical] = [str(item) for item in value]
    return result
