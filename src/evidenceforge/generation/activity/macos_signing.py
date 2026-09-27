# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""macOS code-signing identity data for eslogger (Endpoint Security) rendering.

Loads known-binary code-signing identity mappings from macos_signing.yaml and
provides get_signing_identity() for the eslogger emitter's process audit-token
fields (signing_id, team_id, cdhash, is_platform_binary, codesigning_flags).

AMOS/Atomic Stealer signing convention: `/usr/bin/osascript` is a real Apple
platform binary and always resolves to a signed, `is_platform_binary=True`
identity — real AMOS samples invoke the genuine osascript (malicious intent
lives in its argv, not its binary identity), exactly like countless benign
AppleScript automations. The unsigned/ad-hoc identity belongs to AMOS's
trojanized dropper process (see the "malware" section and its AMOS convention
comment in macos_signing.yaml), which spawns osascript as a child rather than
being osascript itself. See that YAML comment before wiring up the Task 12
three-hunt demo scenario.
"""

import random
from typing import Any

from evidenceforge.config import get_activity_directory
from evidenceforge.config.overlay import load_with_overlay, merge_keyed_list
from evidenceforge.utils.rng import _stable_seed

_MACOS_SIGNING_PATH = get_activity_directory() / "macos_signing.yaml"
_CACHED_SIGNING: dict[str, Any] | None = None

# Code-signing status bits from XNU's <kern/cs_blobs.h>. ES reports
# es_process_t.codesigning_flags as this uint32 bitmask; the YAML stores the
# readable flag names.
CS_FLAG_BITS: dict[str, int] = {
    "CS_VALID": 0x00000001,
    "CS_ADHOC": 0x00000002,
    "CS_GET_TASK_ALLOW": 0x00000004,
    "CS_INSTALLER": 0x00000008,
    "CS_FORCED_LV": 0x00000010,
    "CS_INVALID_ALLOWED": 0x00000020,
    "CS_HARD": 0x00000100,
    "CS_KILL": 0x00000200,
    "CS_CHECK_EXPIRATION": 0x00000400,
    "CS_RESTRICT": 0x00000800,
    "CS_ENFORCEMENT": 0x00001000,
    "CS_REQUIRE_LV": 0x00002000,
    "CS_ENTITLEMENTS_VALIDATED": 0x00004000,
    "CS_NVRAM_UNRESTRICTED": 0x00008000,
    "CS_RUNTIME": 0x00010000,
    "CS_LINKER_SIGNED": 0x00020000,
    "CS_EXEC_SET_HARD": 0x00100000,
    "CS_EXEC_SET_KILL": 0x00200000,
    "CS_EXEC_SET_ENFORCEMENT": 0x00400000,
    "CS_EXEC_INHERIT_SIP": 0x00800000,
    "CS_KILLED": 0x01000000,
    "CS_NO_UNTRUSTED_HELPERS": 0x02000000,
    "CS_PLATFORM_BINARY": 0x04000000,
    "CS_PLATFORM_PATH": 0x08000000,
    "CS_DEBUGGED": 0x10000000,
    "CS_SIGNED": 0x20000000,
    "CS_DEV_CODE": 0x40000000,
    "CS_DATAVAULT_CONTROLLER": 0x80000000,
}

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


def codesigning_flags_value(flag_names: list[str]) -> int:
    """Fold cs_blobs.h flag names into the uint32 bitmask ES reports.

    Raises:
        ValueError: If a flag name is not a known cs_blobs.h flag.
    """
    value = 0
    for name in flag_names:
        if name not in CS_FLAG_BITS:
            raise ValueError(
                f"Unknown code-signing flag {name!r} in macos_signing.yaml; "
                f"use a cs_blobs.h name such as {sorted(CS_FLAG_BITS)[:3]}"
            )
        value |= CS_FLAG_BITS[name]
    return value


def _identity_from_entry(entry: dict[str, Any], binary_path: str) -> dict[str, Any]:
    """Build a fresh identity dict from a YAML entry or a templated fallback."""
    basename = binary_path.rsplit("/", 1)[-1]
    return {
        "signing_id": str(entry.get("signing_id", "")).replace("{basename}", basename),
        "team_id": entry.get("team_id"),
        "is_platform_binary": bool(entry.get("is_platform_binary", False)),
        "codesigning_flags": codesigning_flags_value(list(entry.get("codesigning_flags", []))),
    }


def get_signing_identity(binary_path: str) -> dict[str, Any]:
    """Return the code-signing identity for a macOS binary path.

    Resolution order: an exact ``binaries`` entry; then ``platform_default``
    for any path on the sealed system volume (``platform_path_prefixes``),
    which can only hold Apple platform binaries; then the ad-hoc ``default``
    for everything else, including attacker-chosen malware paths.

    Returns a dict with keys: signing_id, team_id, is_platform_binary,
    codesigning_flags (uint32 bitmask), cdhash. CDHash is derived here
    (compute-once, use-everywhere) so the eslogger emitter never re-derives
    it independently.
    """
    data = load_macos_signing()

    entry = next(
        (b for b in data.get("binaries", []) if b.get("binary_path") == binary_path),
        None,
    )
    if entry is None and any(
        binary_path.startswith(prefix) for prefix in data.get("platform_path_prefixes", [])
    ):
        entry = data.get("platform_default")
    identity = _identity_from_entry(
        entry if entry is not None else data.get("default", {}), binary_path
    )
    identity["cdhash"] = _derive_cdhash(binary_path, identity["team_id"])
    return identity
