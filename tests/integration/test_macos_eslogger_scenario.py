# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# SPDX-License-Identifier: MIT

"""End-to-end integration test for the three-hunt macOS eslogger demo scenario.

Generates ``scenarios/macos-eslogger-demo/scenario.yaml`` through the real
``eforge generate`` CLI path and asserts the ESF (eslogger) + Zeek evidence for
all three OBTS hunts:

1. AMOS/Atomic Stealer  — unsigned dropper ``exec`` + keychain ``open`` +
   TLS exfil (Zeek), with signed ``osascript`` as a child.
2. DPRK BeaverTail       — ``npm`` -> ``node`` ``exec`` chain + node egress
   correlated in Zeek conn/dns.
3. CloudMensis-style      — LaunchAgent plist ``create`` that drives the BTM
   causal rule (``btm_launch_item_add``), which is NOT declared in the scenario.

Also covers determinism (byte-identical eslogger output across two runs) and the
Task 11c "orphan openssh_logout" watch item (every logout has a preceding login
for the same session).
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SUCCESS, app

runner = CliRunner()

SCENARIO = (
    Path(__file__).resolve().parents[2] / "scenarios" / "macos-eslogger-demo" / "scenario.yaml"
)

MACOS_HOSTS = {
    "MAC-DESIGN-01": "MAC-DESIGN-01.clearwater-studio.test",
    "MAC-DEV-01": "MAC-DEV-01.clearwater-studio.test",
    "MAC-IT-01": "MAC-IT-01.clearwater-studio.test",
}

AMOS_DROPPER = "/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper"
KEYCHAIN_PATH = "/Users/dana.reyes/Library/Keychains/login.keychain-db"
LAUNCHAGENT_PLIST = "/Users/riley.chen/Library/LaunchAgents/com.apple.cloudsyncd.plist"


def _generate(tmp_path: Path, name: str = "output") -> Path:
    out = tmp_path / name
    result = runner.invoke(app, ["generate", str(SCENARIO), "--output", str(out), "--force"])
    assert result.exit_code == EXIT_SUCCESS, result.stdout
    return out


def _eslogger_records(output_dir: Path, host_fqdn: str) -> list[dict]:
    path = output_dir / "data" / host_fqdn / "eslogger.ndjson"
    assert path.exists(), f"missing eslogger output for {host_fqdn}: {path}"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _event_name(record: dict) -> str:
    return next(iter(record["event"]))


def _zeek_records(output_dir: Path, log: str) -> list[dict]:
    # Zeek is host-multiplexed under the sensor hostname directory.
    matches = list(output_dir.rglob(f"{log}.json"))
    assert matches, f"no Zeek {log}.json found under {output_dir}"
    records: list[dict] = []
    for path in matches:
        records.extend(
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line
        )
    return records


def test_eslogger_output_exists_for_every_macos_host(tmp_path: Path) -> None:
    output = _generate(tmp_path)
    for host_fqdn in MACOS_HOSTS.values():
        records = _eslogger_records(output, host_fqdn)
        # Modest baseline + a hunt beat per host: each host should carry a
        # plausible, nonzero number of ES records.
        assert len(records) >= 5, f"{host_fqdn} eslogger output too small: {len(records)}"
        # Every record is a single-keyed ES event object with the acting process.
        for r in records:
            assert len(r["event"]) == 1
            assert "process" in r
        # No network events: ESF has no TCP-connect event (design decision).
        names = {_event_name(r) for r in records}
        assert not (names & {"connection", "flow", "network"})


def _exec_target(record: dict) -> dict:
    """Return the new program image of an ES exec record (es_event_exec_t.target)."""
    return record["event"]["exec"]["target"]


def test_hunt1_amos_unsigned_dropper_exec_and_keychain_open(tmp_path: Path) -> None:
    output = _generate(tmp_path)
    records = _eslogger_records(output, MACOS_HOSTS["MAC-DESIGN-01"])

    # The AMOS dropper exec must carry the exact ad-hoc binary_path: a
    # signing identifier but no Team ID and no platform bit.
    dropper_execs = [
        r
        for r in records
        if _event_name(r) == "exec" and _exec_target(r)["executable"]["path"] == AMOS_DROPPER
    ]
    assert dropper_execs, "no exec for the AMOS dropper binary_path"
    dropper = _exec_target(dropper_execs[0])
    assert dropper["is_platform_binary"] is False
    assert dropper["team_id"] is None
    assert dropper["codesigning_flags"] & 0x2  # CS_ADHOC

    # The keychain `open` must be attributed to the unsigned dropper (Task 8
    # convention: the dropper owns the keychain read, NOT osascript).
    keychain_opens = [
        r
        for r in records
        if _event_name(r) == "open" and r["event"]["open"]["file"]["path"] == KEYCHAIN_PATH
    ]
    assert keychain_opens, "no eslogger `open` event for the login keychain"
    actor = keychain_opens[0]["process"]
    assert actor["executable"]["path"] == AMOS_DROPPER
    assert actor["is_platform_binary"] is False

    # osascript is a signed Apple platform binary child (not the malicious top).
    osascript_execs = [
        r
        for r in records
        if _event_name(r) == "exec"
        and _exec_target(r)["executable"]["path"] == "/usr/bin/osascript"
    ]
    assert osascript_execs, "no osascript exec"
    assert _exec_target(osascript_execs[0])["is_platform_binary"] is True
    assert _exec_target(osascript_execs[0])["signing_id"] == "com.apple.osascript"


def test_hunt2_beavertail_npm_node_exec_chain(tmp_path: Path) -> None:
    output = _generate(tmp_path)
    records = _eslogger_records(output, MACOS_HOSTS["MAC-DEV-01"])
    execs = [r for r in records if _event_name(r) == "exec"]

    # npm is a node script: ES sees node exec'd with the npm script in argv.
    npm = next(
        r
        for r in execs
        if r["event"]["exec"]["args"][:3] == ["node", "/usr/local/bin/npm", "install"]
    )
    assert _exec_target(npm)["executable"]["path"] == "/usr/local/bin/node"
    assert npm["event"]["exec"]["cwd"]["path"] == "/Users/sam.okafor/dev/webapp"

    # npm -> sh -c (lifecycle script) -> node postinstall, from the package dir.
    npm_pid = _exec_target(npm)["audit_token"]["pid"]
    lifecycle = next(
        r
        for r in execs
        if r["process"]["ppid"] == npm_pid and r["event"]["exec"]["args"][0] == "sh"
    )
    loader = next(
        r for r in execs if r["process"]["ppid"] == _exec_target(lifecycle)["audit_token"]["pid"]
    )
    assert loader["event"]["exec"]["args"] == ["node", "scripts/postinstall.js"]
    assert loader["event"]["exec"]["cwd"]["path"].endswith(
        "/node_modules/@clearwater-ui/react-icons-pro"
    )


def test_hunt1_amos_runs_in_real_order_and_dropper_owns_exfil(tmp_path: Path) -> None:
    output = _generate(tmp_path)
    records = _eslogger_records(output, MACOS_HOSTS["MAC-DESIGN-01"])

    dropper = next(
        r
        for r in records
        if _event_name(r) == "exec" and _exec_target(r)["executable"]["path"] == AMOS_DROPPER
    )
    dropper_pid = _exec_target(dropper)["audit_token"]["pid"]
    # LaunchServices launched the app: its parent is launchd, not a shell or sshd.
    assert dropper["process"]["ppid"] == 1
    prompt = next(
        r
        for r in records
        if _event_name(r) == "exec"
        and _exec_target(r)["executable"]["path"] == "/usr/bin/osascript"
        and r["process"]["ppid"] == dropper_pid
    )
    keychain = next(
        r
        for r in records
        if _event_name(r) == "open" and r["event"]["open"]["file"]["path"] == KEYCHAIN_PATH
    )
    # Real AMOS phishes the password first, then reads the keychain.
    assert dropper["time"] < prompt["time"] < keychain["time"]
    assert keychain["process"]["audit_token"]["pid"] == dropper_pid

    # The dropper uploads natively; no curl is fabricated to own the exfil.
    assert not any(
        _event_name(r) == "exec" and "macos-analytics" in " ".join(r["event"]["exec"]["args"])
        for r in records
    )


def test_hunt3_cloudmensis_plist_create_drives_btm(tmp_path: Path) -> None:
    output = _generate(tmp_path)
    records = _eslogger_records(output, MACOS_HOSTS["MAC-IT-01"])

    # The plist create (file-event new vocabulary) must render.
    plist_creates = [
        r
        for r in records
        if _event_name(r) == "create"
        and r["event"]["create"]["destination"]["existing_file"]["path"] == LAUNCHAGENT_PLIST
    ]
    assert plist_creates, "no eslogger `create` for the LaunchAgent plist"

    # The BTM event must be produced by the causal rule (it is NOT declared in
    # the scenario storyline) and reference the same plist path.
    btm = [r for r in records if _event_name(r) == "btm_launch_item_add"]
    assert btm, "BTM launch-item-add was not produced by the causal rule"
    btm_paths = {r["event"]["btm_launch_item_add"]["item"]["item_url"] for r in btm}
    assert "file://" + LAUNCHAGENT_PLIST in btm_paths, f"BTM path mismatch: {btm_paths}"


def test_file_events_render_with_new_vocabulary(tmp_path: Path) -> None:
    """Task 9 reviewer risk: the `open`/`create` (Task 6 vocabulary) file events
    must actually appear in eslogger output, not be silently dropped."""
    output = _generate(tmp_path)
    all_names: set[str] = set()
    for host_fqdn in MACOS_HOSTS.values():
        all_names.update(_event_name(r) for r in _eslogger_records(output, host_fqdn))
    assert "open" in all_names, "keychain `open` file event did not render"
    assert "create" in all_names, "plist `create` file event did not render"


def test_zeek_correlates_with_macos_egress(tmp_path: Path) -> None:
    output = _generate(tmp_path)
    conn = _zeek_records(output, "conn")
    dns = _zeek_records(output, "dns")

    # AMOS exfil (MAC-DESIGN-01 -> stealer panel) and BeaverTail beacon
    # (MAC-DEV-01 -> attacker infra) must be observable in Zeek conn.
    conn_pairs = {(r.get("id.orig_h"), r.get("id.resp_h")) for r in conn}
    assert ("10.20.10.31", "193.42.33.14") in conn_pairs, "AMOS exfil missing from Zeek conn"
    assert ("10.20.10.32", "45.128.199.72") in conn_pairs, (
        "BeaverTail egress missing from Zeek conn"
    )

    # The C2 hostnames must be resolved in Zeek dns (DNS causal expansion).
    queries = {r.get("query") for r in dns}
    assert "gateway.macos-analytics.top" in queries, "AMOS C2 DNS lookup missing"
    assert "api.ipcheck-beaver.cc" in queries, "BeaverTail C2 DNS lookup missing"


def test_eslogger_output_is_byte_deterministic(tmp_path: Path) -> None:
    """facts.md item 20: identical scenario input -> byte-identical ES output."""
    first = _generate(tmp_path, "first")
    second = _generate(tmp_path, "second")
    for host_fqdn in MACOS_HOSTS.values():
        a = (first / "data" / host_fqdn / "eslogger.ndjson").read_bytes()
        b = (second / "data" / host_fqdn / "eslogger.ndjson").read_bytes()
        assert a == b, f"eslogger output not byte-identical for {host_fqdn}"


def test_no_orphan_openssh_logout(tmp_path: Path) -> None:
    """Task 11c watch item: every openssh_logout must have a preceding
    openssh_login for the same session on the same host (no orphan logouts)."""
    output = _generate(tmp_path)
    found_a_pair = False
    for host_fqdn in MACOS_HOSTS.values():
        records = _eslogger_records(output, host_fqdn)
        open_sessions: set[int] = set()
        for r in records:
            name = _event_name(r)
            sid = r["process"]["session_id"]
            if name == "openssh_login":
                open_sessions.add(sid)
            elif name == "openssh_logout":
                assert sid in open_sessions, (
                    f"orphan openssh_logout (session {sid}) with no preceding "
                    f"openssh_login on {host_fqdn}"
                )
                found_a_pair = True
    # The scenario deliberately includes one complete SSH login/logout pair, so
    # the assertion above is exercised, not vacuous.
    assert found_a_pair, "expected at least one paired openssh_login/openssh_logout"


def test_scenario_validates_without_errors(tmp_path: Path) -> None:
    result = runner.invoke(app, ["validate", str(SCENARIO)])
    assert result.exit_code == EXIT_SUCCESS, result.stdout
