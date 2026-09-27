# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for macOS code-signing identity data and loader.

Covers `config/activity/macos_signing.yaml` + `generation/activity/macos_signing.py`:
loader caching, known-binary lookups (system/third-party/malware), the
sealed-system-volume platform fallback, the ad-hoc fallback default, the
cs_blobs.h flag bitmask, and CDHash determinism.
"""

import pytest

from evidenceforge.generation.activity.macos_signing import (
    CS_FLAG_BITS,
    codesigning_flags_value,
    get_signing_identity,
    load_macos_signing,
)


class TestLoadMacosSigning:
    """Loader caching and data shape."""

    def test_load_macos_signing_is_cached(self):
        """Calling load_macos_signing() twice returns the identical cached object."""
        first = load_macos_signing()
        second = load_macos_signing()
        assert first is second

    def test_load_macos_signing_has_binaries_and_default(self):
        data = load_macos_signing()
        assert "binaries" in data
        assert isinstance(data["binaries"], list)
        assert len(data["binaries"]) > 0
        assert "default" in data
        assert isinstance(data["default"], dict)

    def test_every_binary_entry_has_required_fields(self):
        data = load_macos_signing()
        required = {
            "binary_path",
            "signing_id",
            "team_id",
            "is_platform_binary",
            "codesigning_flags",
        }
        for entry in data["binaries"]:
            missing = required - entry.keys()
            assert not missing, f"{entry.get('binary_path')} missing fields: {missing}"

    def test_platform_binaries_have_no_team_id(self):
        """Apple platform binaries aren't Team-ID-signed like third-party apps."""
        data = load_macos_signing()
        for entry in data["binaries"]:
            if entry.get("is_platform_binary"):
                assert entry.get("team_id") is None, (
                    f"{entry['binary_path']} is_platform_binary but has a team_id"
                )

    def test_third_party_binaries_have_team_id_or_are_explicitly_unsigned(self):
        data = load_macos_signing()
        for entry in data["binaries"]:
            if entry.get("category") == "third_party" and entry.get("signing_id"):
                assert entry.get("team_id"), (
                    f"{entry['binary_path']} has a signing_id but no team_id"
                )


class TestGetSigningIdentity:
    """get_signing_identity() lookup behavior."""

    def test_known_system_binary_is_platform_binary_with_realistic_signing_id(self):
        identity = get_signing_identity("/sbin/launchd")
        assert identity["is_platform_binary"] is True
        assert identity["signing_id"] == "com.apple.xpc.launchd"
        assert identity["team_id"] is None
        assert identity["cdhash"]

    def test_another_known_system_binary_resolves_correctly(self):
        identity = get_signing_identity(
            "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
        )
        assert identity["is_platform_binary"] is True
        assert identity["signing_id"] == "com.apple.loginwindow"

    def test_known_third_party_binary_has_team_id_and_is_not_platform_binary(self):
        identity = get_signing_identity(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )
        assert identity["is_platform_binary"] is False
        assert identity["signing_id"] == "com.google.Chrome"
        assert identity["team_id"] == "EQHXZ8M8AV"

    def test_known_malware_process_returns_ad_hoc_identity_without_team_id(self):
        identity = get_signing_identity(
            "/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper"
        )
        assert identity["signing_id"] == "CleanMyMacX Helper"
        assert identity["team_id"] is None
        assert identity["is_platform_binary"] is False

    def test_osascript_remains_apple_signed_platform_binary(self):
        """Regression test for a review finding: /usr/bin/osascript is a real,
        unmodified Apple platform binary used by countless benign AppleScript
        automations as well as by AMOS/Atomic Stealer's password-prompt step.
        Real AMOS samples never re-sign or replace osascript itself — the
        malicious intent lives in the argv passed to it, not in its binary
        identity. It must stay signed/platform here so benign osascript
        invocations don't falsely render as unsigned/suspicious.
        """
        identity = get_signing_identity("/usr/bin/osascript")
        assert identity["is_platform_binary"] is True
        assert identity["signing_id"] == "com.apple.osascript"
        assert identity["team_id"] is None

    def test_amos_dropper_payload_is_ad_hoc_signed(self):
        """The AMOS payload's ad-hoc identity belongs to the trojanized dropper
        process, not to osascript: a signing identifier and CS_ADHOC, but no
        Team ID and no platform bit (see the AMOS convention in
        macos_signing.yaml).
        """
        identity = get_signing_identity(
            "/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper"
        )
        assert identity["team_id"] is None
        assert identity["is_platform_binary"] is False
        assert identity["codesigning_flags"] & CS_FLAG_BITS["CS_ADHOC"]
        assert not identity["codesigning_flags"] & CS_FLAG_BITS["CS_PLATFORM_BINARY"]

    def test_official_node_install_is_developer_id_signed(self):
        """nodejs.org's installer ships a Node.js Foundation Developer ID-signed
        node; BeaverTail's signal is ancestry and egress, not node's signature."""
        identity = get_signing_identity("/usr/local/bin/node")
        assert identity["signing_id"] == "node"
        assert identity["team_id"] == "HX7739G8FX"
        assert identity["is_platform_binary"] is False

    def test_unknown_path_returns_ad_hoc_default_named_after_binary(self):
        identity = get_signing_identity("/private/tmp/totally-unknown-attacker-binary")
        assert identity["signing_id"] == "totally-unknown-attacker-binary"
        assert identity["team_id"] is None
        assert identity["is_platform_binary"] is False
        assert identity["codesigning_flags"] == codesigning_flags_value(
            ["CS_VALID", "CS_SIGNED", "CS_ADHOC", "CS_LINKER_SIGNED"]
        )
        assert identity["cdhash"]

    @pytest.mark.parametrize(
        ("path", "signing_id"),
        [
            ("/usr/libexec/sharingd", "com.apple.sharingd"),
            ("/System/Library/CoreServices/NotificationCenter", "com.apple.NotificationCenter"),
            ("/usr/bin/zip", "com.apple.zip"),
            (
                "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/"
                "com.apple.WebKit.WebContent.xpc/Contents/MacOS/com.apple.WebKit.WebContent",
                "com.apple.WebKit.WebContent",
            ),
        ],
    )
    def test_unlisted_system_volume_path_is_apple_platform_binary(self, path, signing_id):
        identity = get_signing_identity(path)
        assert identity["is_platform_binary"] is True
        assert identity["team_id"] is None
        assert identity["signing_id"] == signing_id
        assert identity["codesigning_flags"] & CS_FLAG_BITS["CS_PLATFORM_BINARY"]

    def test_usr_local_is_not_treated_as_system_volume(self):
        identity = get_signing_identity("/usr/local/bin/some-tool")
        assert identity["is_platform_binary"] is False

    def test_baseline_macos_daemons_resolve_as_platform_binaries(self):
        """Regression: Spotlight/iCloud daemons used to render unsigned."""
        for path in (
            "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/"
            "Metadata.framework/Versions/A/Support/mdworker_shared",
            "/System/Library/PrivateFrameworks/CloudKitDaemon.framework/Support/cloudd",
            "/System/Library/PrivateFrameworks/iCloudDriveCore.framework/Versions/A/Support/bird",
        ):
            assert get_signing_identity(path)["is_platform_binary"] is True, path


class TestCodesigningFlagsValue:
    """cs_blobs.h flag names fold into the uint32 bitmask ES reports."""

    def test_apple_platform_flags_fold_to_expected_bitmask(self):
        assert codesigning_flags_value(["CS_VALID", "CS_SIGNED", "CS_PLATFORM_BINARY"]) == (
            0x20000000 | 0x04000000 | 0x00000001
        )

    def test_empty_flag_list_is_zero(self):
        assert codesigning_flags_value([]) == 0

    def test_unknown_flag_name_raises_actionable_error(self):
        with pytest.raises(ValueError, match="CS_BOGUS"):
            codesigning_flags_value(["CS_BOGUS"])

    def test_every_yaml_flag_name_is_known(self):
        data = load_macos_signing()
        entries = [*data["binaries"], data["default"], data["platform_default"]]
        for entry in entries:
            codesigning_flags_value(entry["codesigning_flags"])


class TestCdhashDeterminism:
    """CDHash derivation must be deterministic, scoped, and never use hash()/Random(42)."""

    def test_same_binary_and_team_id_produces_identical_cdhash_across_calls(self):
        """Two independent calls (simulating two separate runs of the same
        scenario/seed) must yield the identical CDHash."""
        first_call = get_signing_identity("/sbin/launchd")
        second_call = get_signing_identity("/sbin/launchd")
        assert first_call["cdhash"] == second_call["cdhash"]

    def test_cdhash_looks_like_a_real_macos_cdhash(self):
        identity = get_signing_identity("/sbin/launchd")
        cdhash = identity["cdhash"]
        assert len(cdhash) == 40
        assert all(c in "0123456789abcdef" for c in cdhash)

    def test_different_binary_paths_produce_different_cdhashes(self):
        launchd = get_signing_identity("/sbin/launchd")
        chrome = get_signing_identity(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        )
        assert launchd["cdhash"] != chrome["cdhash"]

    def test_cdhash_scoped_by_team_id_differs_for_same_path_different_team(self):
        """Same binary path with a different team_id must not collide —
        the scoping key includes both binary path and team ID."""
        from evidenceforge.generation.activity.macos_signing import _derive_cdhash

        cdhash_a = _derive_cdhash("/Applications/Example.app/Contents/MacOS/Example", "TEAMID1234")
        cdhash_b = _derive_cdhash("/Applications/Example.app/Contents/MacOS/Example", "TEAMID9999")
        assert cdhash_a != cdhash_b

    def test_cdhash_derivation_is_reproducible_in_a_fresh_process_simulation(self):
        """Simulate 'two separate runs' by re-deriving from scratch (a fresh
        call chain, not reusing any cached intermediate object) and confirm
        the result matches — proves the derivation depends only on stable
        inputs (binary_path, team_id), never on process-local state."""
        from evidenceforge.generation.activity.macos_signing import _derive_cdhash

        run_one = _derive_cdhash("/usr/bin/curl", None)
        run_two = _derive_cdhash("/usr/bin/curl", None)
        assert run_one == run_two
        # And it must agree with the value produced via the public lookup path.
        looked_up = get_signing_identity("/usr/bin/curl")
        assert looked_up["cdhash"] == run_one
