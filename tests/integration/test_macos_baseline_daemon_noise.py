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

"""Integration test for macOS baseline system-daemon noise generation (Task 13b).

Generates a small, storyline-free macOS scenario over several days of baseline
activity and asserts that each of facts.md's six named daemons (Spotlight,
Time Machine, softwareupdated, cfprefsd, cloudd/bird, trustd) produces at
least one verifiable event in the resulting ``eslogger.ndjson``, with
non-uniform timing (AGENTS.md realism rule #5 — no fixed-interval ticks).
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from evidenceforge.cli.commands import EXIT_SUCCESS, app

runner = CliRunner()

_SCENARIO_YAML = """\
version: "1.0"
name: macos-baseline-daemon-noise-test
description: "Minimal macOS scenario to verify baseline system-daemon noise generation."

environment:
  description: "Two macOS workstations, no attack storyline -- pure baseline noise."
  domain: "noisetest.test"

  users:
    - username: avery.kim
      full_name: "Avery Kim"
      email: "avery.kim@noisetest.test"
      persona: developer
      primary_system: MAC-01
      enabled: true
    - username: jordan.lee
      full_name: "Jordan Lee"
      email: "jordan.lee@noisetest.test"
      persona: marketing
      primary_system: MAC-02
      enabled: true

  systems:
    - hostname: MAC-01
      ip: "10.50.10.11"
      os: "macOS 14.5"
      type: workstation
      assigned_user: avery.kim
    - hostname: MAC-02
      ip: "10.50.10.12"
      os: "macOS 14.5"
      type: workstation
      assigned_user: jordan.lee

time_window:
  start: "2024-06-11T00:00:00Z"
  duration: "96h"

baseline_activity:
  description: "Low baseline activity; no storyline."
  intensity: low
  variation: low

output:
  logs:
    - format: eslogger
  destination: "./output"
  compression: false
"""

MACOS_HOSTS = {
    "MAC-01": "MAC-01.noisetest.test",
    "MAC-02": "MAC-02.noisetest.test",
}

# Full daemon executable paths as spawned by _generate_macos_daemon_noise /
# _seed_macos_process_tree -- matched as substrings against each eslogger
# record's process.executable.path.
_DAEMON_IMAGE_MARKERS = {
    "mds/mdworker_shared (Spotlight)": "mdworker_shared",
    "backupd (Time Machine)": "Backup.framework/Resources/backupd",
    "softwareupdated": "SoftwareUpdate.framework/Resources/softwareupdated",
    "cfprefsd": "/usr/sbin/cfprefsd",
    "cloudd (iCloud)": "/usr/libexec/cloudd",
    "bird (iCloud)": "/usr/libexec/bird",
    "trustd": "/usr/libexec/trustd",
}


def _generate(tmp_path: Path) -> Path:
    scenario_path = tmp_path / "scenario.yaml"
    scenario_path.write_text(_SCENARIO_YAML, encoding="utf-8")
    out = tmp_path / "output"
    result = runner.invoke(app, ["generate", str(scenario_path), "--output", str(out), "--force"])
    assert result.exit_code == EXIT_SUCCESS, result.stdout
    return out


def _eslogger_records(output_dir: Path, host_fqdn: str) -> list[dict]:
    path = output_dir / "data" / host_fqdn / "eslogger.ndjson"
    assert path.exists(), f"missing eslogger output for {host_fqdn}: {path}"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _event_name(record: dict) -> str:
    return next(iter(record["event"]))


def test_all_named_daemons_produce_eslogger_activity(tmp_path: Path):
    """Each of facts.md's 6 named macOS daemons shows verifiable low-volume activity."""
    output_dir = _generate(tmp_path)

    all_records: list[dict] = []
    for host_fqdn in MACOS_HOSTS.values():
        all_records.extend(_eslogger_records(output_dir, host_fqdn))

    process_paths = {
        record["process"]["executable"]["path"]
        for record in all_records
        if "process" in record and record["process"].get("executable")
    }

    missing = [
        label
        for label, marker in _DAEMON_IMAGE_MARKERS.items()
        if not any(marker in path for path in process_paths)
    ]
    assert not missing, (
        f"Daemons with no observed eslogger process activity: {missing}. "
        f"Observed executable paths: {sorted(process_paths)}"
    )


def test_spotlight_and_backupd_have_process_lifecycle_pairs(tmp_path: Path):
    """Spawned mdworker_shared/backupd instances have both a create and a terminate."""
    output_dir = _generate(tmp_path)

    for host_fqdn in MACOS_HOSTS.values():
        records = _eslogger_records(output_dir, host_fqdn)
        for marker in ("mdworker_shared", "backupd"):
            exec_pids = {
                record["process"]["pid"]
                for record in records
                if _event_name(record) == "exec"
                and marker in record["process"]["executable"]["path"]
            }
            exit_pids = {
                record["process"]["pid"]
                for record in records
                if _event_name(record) == "exit"
                and marker in record["process"]["executable"]["path"]
            }
            assert exec_pids, f"{host_fqdn}: no {marker} exec events found"
            assert exec_pids <= exit_pids, (
                f"{host_fqdn}: {marker} process(es) {exec_pids - exit_pids} never terminated"
            )


def test_time_machine_backup_timing_is_not_fixed_interval(tmp_path: Path):
    """backupd firings across the run must not land on the hour or at identical gaps."""
    output_dir = _generate(tmp_path)

    for host_fqdn in MACOS_HOSTS.values():
        records = _eslogger_records(output_dir, host_fqdn)
        backupd_starts = sorted(
            record["time"]
            for record in records
            if _event_name(record) == "exec"
            and "backupd" in record["process"]["executable"]["path"]
        )
        assert len(backupd_starts) >= 3, (
            f"{host_fqdn}: expected multiple backupd runs over 96h, got {backupd_starts}"
        )

        # Not on the exact hour (minute/second/microsecond == 0) every time.
        on_the_hour = [ts for ts in backupd_starts if ts[-13:] == ":00:00.000000"]
        assert len(on_the_hour) != len(backupd_starts), (
            f"{host_fqdn}: every backupd run landed exactly on the hour: {backupd_starts}"
        )

        # Gaps between consecutive runs must not all be identical (no fixed-interval ticks).
        from datetime import datetime as _dt

        parsed = [_dt.fromisoformat(ts.replace("Z", "+00:00")) for ts in backupd_starts]
        gaps = [(b - a).total_seconds() for a, b in zip(parsed, parsed[1:], strict=False)]
        assert len(set(round(g) for g in gaps)) > 1, (
            f"{host_fqdn}: backupd gaps are all identical (looks fixed-interval): {gaps}"
        )


def test_cfprefsd_churn_reuses_existing_seeded_process(tmp_path: Path):
    """cfprefsd churn should attach to the already-seeded persistent daemon, not spawn a new one."""
    output_dir = _generate(tmp_path)

    for host_fqdn in MACOS_HOSTS.values():
        records = _eslogger_records(output_dir, host_fqdn)
        cfprefsd_file_events = [
            record
            for record in records
            if _event_name(record) in ("open", "write")
            and "/usr/sbin/cfprefsd" in record["process"]["executable"]["path"]
        ]
        assert cfprefsd_file_events, f"{host_fqdn}: no cfprefsd file open/write activity found"

        # No extra process create/terminate events for cfprefsd beyond the single
        # boot-seeded process (Task 3) -- churn must be file activity only.
        cfprefsd_execs = {
            record["process"]["pid"]
            for record in records
            if _event_name(record) == "exec"
            and "/usr/sbin/cfprefsd" in record["process"]["executable"]["path"]
        }
        assert len(cfprefsd_execs) <= 1, (
            f"{host_fqdn}: expected cfprefsd to stay a single boot-seeded process, "
            f"found execs for PIDs {cfprefsd_execs}"
        )
