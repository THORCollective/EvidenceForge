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

"""Realism invariants for macOS Endpoint Security output.

Generates the OBTS demo scenario once and checks properties any real
``eslogger`` capture has, found while hunting the demo in a SIEM: ES client
sequence numbering, process ancestry, controlling terminals, exit bookkeeping,
the launchd-spawned per-connection ``sshd``, and macOS (not Windows) DNS
behavior in the correlated Zeek output.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SUCCESS, app

SCENARIO = (
    Path(__file__).resolve().parents[2] / "scenarios" / "macos-eslogger-demo" / "scenario.yaml"
)
_SHELLS = {"zsh", "bash", "sh"}


@pytest.fixture(scope="module")
def output(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("macos-realism") / "output"
    result = CliRunner().invoke(
        app, ["generate", str(SCENARIO), "--output", str(out), "--overwrite"]
    )
    assert result.exit_code == EXIT_SUCCESS, result.stdout
    return out


@pytest.fixture(scope="module")
def es_files(output: Path) -> dict[str, list[dict]]:
    files: dict[str, list[dict]] = {}
    for path in sorted((output / "data").glob("*/eslogger.ndjson")):
        files[path.parent.name] = [
            json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line
        ]
    assert files, "no eslogger output generated"
    return files


def _name(record: dict) -> str:
    return next(iter(record["event"]))


def _base(path: str | None) -> str:
    return (path or "").rsplit("/", 1)[-1]


def _process_objects(record: dict) -> list[dict]:
    """Every es_process_t carried by a record (subject plus event payload)."""
    objs = [record["process"]]
    payload = record["event"][_name(record)]
    for key in ("target", "child", "instigator"):
        value = payload.get(key) if isinstance(payload, dict) else None
        if isinstance(value, dict) and "audit_token" in value:
            objs.append(value)
    return objs


def _execs(records: list[dict]) -> list[dict]:
    return [r for r in records if _name(r) == "exec"]


def test_records_are_time_ordered_with_contiguous_client_sequence_numbers(
    es_files: dict[str, list[dict]],
) -> None:
    # Each Mac runs its own ES client: global_seq_num is contiguous per client in
    # delivery (time) order, and seq_num counts per event type.
    for host, records in es_files.items():
        times = [r["time"] for r in records]
        assert times == sorted(times), f"{host}: records not in time order"
        gseq = [r["global_seq_num"] for r in records]
        assert all(b - a == 1 for a, b in zip(gseq, gseq[1:], strict=False)), (
            f"{host}: global_seq_num not contiguous: {gseq[:20]}"
        )
        by_type: dict[int, list[int]] = defaultdict(list)
        for r in records:
            by_type[r["event_type"]].append(r["seq_num"])
        for event_type, seqs in by_type.items():
            assert all(b - a == 1 for a, b in zip(seqs, seqs[1:], strict=False)), (
                f"{host}: seq_num for event_type {event_type} not contiguous: {seqs[:20]}"
            )


def test_exec_is_delivered_after_its_fork(es_files: dict[str, list[dict]]) -> None:
    for host, records in es_files.items():
        fork_time = {
            r["event"]["fork"]["child"]["audit_token"]["pid"]: r["time"]
            for r in records
            if _name(r) == "fork"
        }
        for r in _execs(records):
            pid = r["process"]["audit_token"]["pid"]
            if pid in fork_time:
                assert fork_time[pid] < r["time"], (
                    f"{host}: exec of pid {pid} at {r['time']} not after fork {fork_time[pid]}"
                )


def test_ssh_client_is_launched_from_an_interactive_shell(
    es_files: dict[str, list[dict]],
) -> None:
    clients = [
        r
        for records in es_files.values()
        for r in _execs(records)
        if _base(r["event"]["exec"]["target"]["executable"]["path"]) in {"ssh", "scp"}
    ]
    assert clients, "demo should contain an outbound ssh client exec"
    for r in clients:
        # On exec, the subject is the pre-exec image: the parent program.
        assert _base(r["process"]["executable"]["path"]) in _SHELLS, r["process"]["executable"]


def test_macos_sshd_is_launched_per_connection_by_launchd(
    es_files: dict[str, list[dict]],
) -> None:
    sshd_execs = [
        r
        for records in es_files.values()
        for r in _execs(records)
        if r["event"]["exec"]["target"]["executable"]["path"] == "/usr/sbin/sshd"
    ]
    assert sshd_execs, "demo should contain an inbound sshd exec"
    for r in sshd_execs:
        assert r["event"]["exec"]["args"] == ["/usr/sbin/sshd", "-i"]
        assert r["process"]["executable"]["path"] == "/sbin/launchd"
        assert r["event"]["exec"]["target"]["ppid"] == 1


def test_openssh_login_is_reported_by_that_connections_sshd(
    es_files: dict[str, list[dict]],
) -> None:
    for host, records in es_files.items():
        sshd_pids = {
            r["event"]["exec"]["target"]["audit_token"]["pid"]
            for r in _execs(records)
            if r["event"]["exec"]["target"]["executable"]["path"] == "/usr/sbin/sshd"
        }
        for r in records:
            if _name(r) in {"openssh_login", "openssh_logout"}:
                assert r["process"]["audit_token"]["pid"] in sshd_pids, (
                    f"{host}: {_name(r)} reported by a persistent sshd, not the session's"
                )


def test_launchd_children_have_no_controlling_terminal(
    es_files: dict[str, list[dict]],
) -> None:
    for host, records in es_files.items():
        for r in records:
            for obj in _process_objects(r):
                if obj["ppid"] in {0, 1}:
                    assert obj["tty"] is None, (
                        f"{host}: {obj['executable']['path']} (ppid {obj['ppid']}) has tty "
                        f"{obj['tty']}"
                    )


def test_exit_reports_the_process_parent(es_files: dict[str, list[dict]]) -> None:
    for host, records in es_files.items():
        exec_ppid = {
            r["event"]["exec"]["target"]["audit_token"]["pid"]: r["event"]["exec"]["target"]["ppid"]
            for r in _execs(records)
        }
        for r in records:
            if _name(r) != "exit":
                continue
            proc = r["process"]
            pid = proc["audit_token"]["pid"]
            assert proc["ppid"] != 0, f"{host}: exit of pid {pid} reports ppid 0"
            if pid in exec_ppid:
                assert proc["original_ppid"] == exec_ppid[pid]
                # A child that outlives its parent is reparented to launchd.
                assert proc["ppid"] in {exec_ppid[pid], 1}


def test_process_exits_are_not_microsecond_cascades(es_files: dict[str, list[dict]]) -> None:
    for host, records in es_files.items():
        exits = sorted(r["time"] for r in records if _name(r) == "exit")
        for a, b in zip(exits, exits[1:], strict=False):
            # Same second: compare the sub-second nanosecond digits.
            if a[:19] == b[:19]:
                gap_ns = int(b[20:29]) - int(a[20:29])
                assert gap_ns >= 100_000, f"{host}: exits {a} and {b} only {gap_ns} ns apart"


def test_envelope_times_are_not_whole_seconds(es_files: dict[str, list[dict]]) -> None:
    for host, records in es_files.items():
        whole = [r["time"] for r in records if r["time"][20:26] == "000000"]
        assert not whole, f"{host}: whole-second envelope times {whole}"


def test_npm_waits_for_its_lifecycle_script(es_files: dict[str, list[dict]]) -> None:
    records = next(v for k, v in es_files.items() if k.startswith("MAC-DEV-01"))
    npm = next(
        r
        for r in _execs(records)
        if r["event"]["exec"]["args"][:3] == ["node", "/usr/local/bin/npm", "install"]
    )
    postinstall = next(
        r
        for r in _execs(records)
        if r["event"]["exec"]["args"] == ["node", "scripts/postinstall.js"]
    )
    exit_time = {
        r["process"]["audit_token"]["pid"]: r["time"] for r in records if _name(r) == "exit"
    }
    npm_pid = npm["event"]["exec"]["target"]["audit_token"]["pid"]
    child_pid = postinstall["event"]["exec"]["target"]["audit_token"]["pid"]
    assert npm_pid in exit_time and child_pid in exit_time
    assert exit_time[npm_pid] > exit_time[child_pid], "npm exited before its postinstall script"


def test_sh_c_wrapper_does_not_write_files_while_waiting(
    es_files: dict[str, list[dict]],
) -> None:
    for host, records in es_files.items():
        wrappers = {
            r["event"]["exec"]["target"]["audit_token"]["pid"]
            for r in _execs(records)
            if r["event"]["exec"]["args"][:2] == ["sh", "-c"]
        }
        for r in records:
            if _name(r) in {"create", "write"}:
                assert r["process"]["audit_token"]["pid"] not in wrappers, (
                    f"{host}: `sh -c` wrapper {r['process']['audit_token']['pid']} wrote a file"
                )


def _mac_ips() -> set[str]:
    scenario = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
    return {
        s["ip"]
        for s in scenario["environment"]["systems"]
        if str(s.get("os", "")).lower().startswith("macos")
    }


def test_macs_do_not_emit_windows_only_dns(output: Path) -> None:
    mac_ips = _mac_ips()
    domain = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))["environment"].get("domain", "")
    queries = [
        json.loads(line)
        for path in output.rglob("dns.json")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]
    offenders = []
    for q in queries:
        if q.get("id.orig_h") not in mac_ips:
            continue
        name = str(q.get("query", ""))
        label = name.split(".", 1)[0]
        if label == "isatap" or name.endswith(".local"):
            offenders.append(name)
        # Windows DNS devolution: an already-qualified name with the primary
        # suffix appended (e.g. login.microsoftonline.com.<domain>).
        if domain and name.endswith(f".{domain}") and name.count(".") > domain.count(".") + 2:
            offenders.append(name)
    assert not offenders, f"Windows-only DNS behavior from Macs: {sorted(set(offenders))}"


def _zeek(output: Path, log: str) -> list[dict]:
    return [
        json.loads(line)
        for path in output.rglob(f"{log}.json")
        for line in path.read_text(encoding="utf-8").splitlines()
        if line
    ]


def _resolver_ips() -> set[str]:
    scenario = yaml.safe_load(SCENARIO.read_text(encoding="utf-8"))
    return {
        s["ip"]
        for s in scenario["environment"]["systems"]
        if "dns_server" in (s.get("roles") or [])
    }


def test_each_mac_user_has_one_console_session(es_files: dict[str, list[dict]]) -> None:
    # Every app and Terminal window runs in the user's loginwindow audit
    # session; baseline activity must not open a session per burst.
    for host, records in es_files.items():
        user_asids = {
            r["event"]["exec"]["target"]["audit_token"]["asid"]
            for r in _execs(records)
            if r["event"]["exec"]["target"]["audit_token"]["euid"] >= 500
            and r["event"]["exec"]["target"]["executable"]["path"] != "/usr/sbin/sshd"
            and r["event"]["exec"]["target"]["tty"] is None
        }
        # One loginwindow session, or two if the baseline logged the user out and
        # back in -- never a session per activity burst.
        assert len(user_asids) <= 2, f"{host}: GUI processes span sessions {sorted(user_asids)}"


def test_running_app_bundles_are_not_relaunched(es_files: dict[str, list[dict]]) -> None:
    for host, records in es_files.items():
        launched: dict[tuple[str, int], int] = defaultdict(int)
        for r in _execs(records):
            target = r["event"]["exec"]["target"]
            path = target["executable"]["path"]
            if ".app/Contents/MacOS/" in path and target["ppid"] == 1:
                launched[(path, target["audit_token"]["asid"])] += 1
        relaunched = {k: v for k, v in launched.items() if v > 1}
        assert not relaunched, f"{host}: app bundles launched repeatedly {relaunched}"


def test_macs_resolve_through_the_internal_resolver(output: Path) -> None:
    resolvers = _resolver_ips()
    assert resolvers, "demo scenario should declare an internal dns_server"
    mac_queries = [q for q in _zeek(output, "dns") if q.get("id.orig_h") in _mac_ips()]
    assert mac_queries
    assert {q["id.resp_h"] for q in mac_queries} <= resolvers


def test_macs_do_not_contact_windows_or_linux_update_hosts(output: Path) -> None:
    foreign = ("windowsupdate.com", "settings-win.data.microsoft.com", "packages.microsoft.com")
    foreign += ("ubuntu.com", "snapcraft.io")
    names = {
        str(r.get("server_name") or r.get("query") or "")
        for log in ("ssl", "dns")
        for r in _zeek(output, log)
        if r.get("id.orig_h") in _mac_ips()
    }
    assert not {n for n in names if n.endswith(foreign)}


def test_btm_executable_path_is_the_launch_item_program(
    es_files: dict[str, list[dict]],
) -> None:
    btm = [
        r["event"]["btm_launch_item_add"]
        for records in es_files.values()
        for r in records
        if _name(r) == "btm_launch_item_add"
    ]
    by_url = {e["item"]["item_url"]: e["executable_path"] for e in btm}
    brew_url = "file:///Users/jordan.lee/Library/LaunchAgents/homebrew.mxcl.postgresql@16.plist"
    assert by_url[brew_url] == "/opt/homebrew/opt/postgresql@16/bin/postgres"


def test_launch_agent_program_is_started_by_launchd(es_files: dict[str, list[dict]]) -> None:
    starts = [
        r
        for records in es_files.values()
        for r in _execs(records)
        if r["event"]["exec"]["target"]["executable"]["path"]
        == "/opt/homebrew/opt/postgresql@16/bin/postgres"
    ]
    assert starts and all(r["process"]["executable"]["path"] == "/sbin/launchd" for r in starts)


def test_authored_egress_resolves_after_its_process_starts(
    output: Path, es_files: dict[str, list[dict]]
) -> None:
    # (host, process argv prefix, DNS name the process resolves)
    owners = [
        (
            "MAC-DESIGN-01",
            ["/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper"],
            "gateway.macos-analytics.top",
        ),
        ("MAC-DEV-01", ["node", "scripts/postinstall.js"], "api.ipcheck-beaver.cc"),
        (
            "MAC-DEV-02",
            ["node", "/usr/local/lib/node_modules/npm/node_modules/node-gyp/bin/node-gyp.js"],
            "nodejs.org",
        ),
    ]
    dns = _zeek(output, "dns")
    for host, argv_prefix, name in owners:
        records = next(v for k, v in es_files.items() if k.startswith(host))
        exec_time = min(
            r["time"]
            for r in _execs(records)
            if r["event"]["exec"]["args"][: len(argv_prefix)] == argv_prefix
        )
        lookups = sorted(q["ts"] for q in dns if q.get("query") == name)
        assert lookups, f"no DNS lookup for {name}"
        first = datetime.fromtimestamp(lookups[0], tz=UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")
        assert first > exec_time[:26], f"{name} resolved at {first} before {host} exec {exec_time}"
