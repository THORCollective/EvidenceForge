# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""macOS code-signing identity data for eslogger (Endpoint Security) rendering.

Loads known-binary code-signing identity mappings from macos_signing.yaml and
provides get_signing_identity() for the eslogger emitter's process audit-token
fields (signing_id, team_id, cdhash, is_platform_binary, codesigning_flags).
"""

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list
from evidenceforge.utils.rng import _stable_seed

_MACOS_SIGNING_PATH = get_activity_directory() / "macos_signing.yaml"
_CACHED_SIGNING: dict[str, Any] | None = None

_CDHASH_ALPHABET = "0123456789abcdef"
_CDHASH_LENGTH = 40  # Real macOS CDHashes are a 40-character SHA-1 hex digest.


def _merge_macos_signing(default: dict, overlay: dict) -> dict:
    """Merge macOS signing overlay with package defaults (keyed by binary_path)."""
    result = dict(default)
    if "binaries" in overlay:
        result["binaries"] = merge_keyed_list(
            default.get("binaries", []),
            overlay["binaries"],
            key_field="binary_path",
        )
    return result


def load_macos_signing() -> dict[str, Any]:
    """Load macOS code-signing identity data from YAML, merged with overlay if present.

    Cached after first call.
    """
    global _CACHED_SIGNING
    if _CACHED_SIGNING is not None:
        return _CACHED_SIGNING

    _CACHED_SIGNING = load_with_overlay(
        _MACOS_SIGNING_PATH,
        "activity/macos_signing.yaml",
        _merge_macos_signing,
    )
    return _CACHED_SIGNING


def _derive_cdhash(binary_path: str, team_id: str | None) -> str:
    """Derive a deterministic, realistic-shaped CDHash for a binary identity.

    Real macOS CDHashes are the SHA-1 digest of a binary's code directory
    (40 lowercase hex characters). There is no real code directory to hash
    here, so this derives a stable 40-hex-character string scoped by
    binary path + team ID via `_stable_seed` — never `hash()`, never a
    globally-seeded `random.Random(42)` — so the same binary+team identity
    always yields the same CDHash, in this process and across separate runs
    with the same scenario/seed (AGENTS.md "deterministic but scoped" rule).
    """
    scope_key = f"macos-cdhash:{binary_path}:{team_id or ''}"
    rng = random.Random(_stable_seed(scope_key))
    return "".join(rng.choice(_CDHASH_ALPHABET) for _ in range(_CDHASH_LENGTH))


def _identity_from_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Build a fresh identity dict from a YAML entry (or the default fallback)."""
    return {
        "signing_id": entry.get("signing_id", ""),
        "team_id": entry.get("team_id"),
        "is_platform_binary": bool(entry.get("is_platform_binary", False)),
        "codesigning_flags": list(entry.get("codesigning_flags", [])),
    }


def get_signing_identity(binary_path: str) -> dict[str, Any]:
    """Return the code-signing identity for a macOS binary path.

    Looks up `binary_path` in the known-binaries table (system binaries,
    third-party apps, storyline malware). Unknown binaries — including any
    attacker-chosen malware path not explicitly listed — fall back to the
    table's unsigned/ad-hoc `default` entry.

    Returns a dict with keys: signing_id, team_id, is_platform_binary,
    codesigning_flags, cdhash. CDHash is derived here (compute-once,
    use-everywhere) so the eslogger emitter never re-derives it independently.
    """
    data = load_macos_signing()

    entry = next(
        (b for b in data.get("binaries", []) if b.get("binary_path") == binary_path),
        None,
    )
    identity = _identity_from_entry(entry if entry is not None else data.get("default", {}))
    identity["cdhash"] = _derive_cdhash(binary_path, identity["team_id"])
    return identity
