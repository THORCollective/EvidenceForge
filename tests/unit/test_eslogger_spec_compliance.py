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

"""Spec-compliance + determinism tests for the eslogger emitter.

Validates every emitted record against the config/formats/eslogger.yaml field
schema (dotted field names walked into the nested record), and confirms that
rendering the same SecurityEvents twice produces byte-identical NDJSON.
"""

import json
from datetime import UTC, datetime

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    AuthContext,
    FileContext,
    HostContext,
    ProcessContext,
)
from evidenceforge.formats.format_def import FieldType
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.eslogger import ESLoggerEmitter
from evidenceforge.generation.state_manager import StateManager

BOOT = datetime(2024, 3, 14, 8, 0, 0, tzinfo=UTC)
TS = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)

_SENTINEL = object()


def _mac_host():
    return HostContext(
        hostname="MAC-01",
        ip="10.0.0.50",
        os="macOS 14.4",
        os_category="macos",
        system_type="workstation",
        fqdn="MAC-01.corp.local",
    )


def _win_host():
    return HostContext(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
    )


def _sample_events():
    """One event per supported type, covering the ES record shapes."""
    mac = _mac_host()
    win = _win_host()
    proc = ProcessContext(
        pid=1500,
        parent_pid=1,
        image="/usr/bin/osascript",
        command_line='osascript -e "do shell script"',
        username="alice",
        start_time=TS,
    )
    return [
        OccurrenceBuilder(timestamp=TS, event_type="process_create", src_host=mac, process=proc),
        OccurrenceBuilder(timestamp=TS, event_type="process_terminate", src_host=mac, process=proc),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="file_open",
            src_host=mac,
            process=proc,
            file=FileContext("/Users/alice/Library/Keychains/login.keychain-db", "open", 1500),
            auth=AuthContext(username="alice"),
        ),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="file_create",
            src_host=mac,
            process=proc,
            file=FileContext("/Users/alice/Library/LaunchAgents/x.plist", "create", 1500),
            auth=AuthContext(username="alice"),
        ),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="ssh_session",
            src_host=win,
            dst_host=mac,
            auth=AuthContext(username="alice", source_ip="10.0.0.10", session_id=132500),
        ),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="logoff",
            src_host=win,
            dst_host=mac,
            auth=AuthContext(username="alice", source_ip="10.0.0.10", session_id=132500),
        ),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="btm_launch_item_add",
            src_host=mac,
            process=proc,
            file=FileContext("/Users/alice/Library/LaunchAgents/x.plist", "create", 1500),
            auth=AuthContext(username="alice"),
        ),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="workstation_locked",
            dst_host=mac,
            auth=AuthContext(username="alice", session_id=132501),
        ),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="workstation_unlocked",
            dst_host=mac,
            auth=AuthContext(username="alice", session_id=132501),
        ),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="privilege_elevation",
            src_host=mac,
            process=ProcessContext(
                pid=1600,
                parent_pid=1500,
                image="/usr/bin/sudo",
                command_line="sudo /usr/bin/whoami",
                username="alice",
                start_time=TS,
            ),
            auth=AuthContext(username="root", subject_username="alice", elevated=True),
        ),
        OccurrenceBuilder(
            timestamp=TS,
            event_type="privilege_elevation",
            src_host=mac,
            process=ProcessContext(
                pid=1601,
                parent_pid=1500,
                image="/usr/bin/su",
                command_line="su -",
                username="alice",
                start_time=TS,
            ),
            auth=AuthContext(username="root", subject_username="alice", elevated=True),
        ),
    ]


def _render_all(events):
    fd = load_format("eslogger")
    sm = StateManager()
    sm.register_boot_time("MAC-01", BOOT)
    emitter = ESLoggerEmitter(fd, _tmp(), threaded=False)
    emitter._state_manager = sm
    lines = []
    captured = []
    emitter.emit_event = lambda ed: captured.append(ed)
    for event in events:
        if emitter.can_handle(event):
            emitter.emit(event)
    for ed in captured:
        lines.append(emitter._render_event(ed))
    return lines


def _tmp():
    import tempfile
    from pathlib import Path

    return Path(tempfile.mkdtemp())


def _walk(record, dotted):
    node = record
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return _SENTINEL
        node = node[part]
    return node


def _type_ok(value, field_type):
    if value is None:
        # null is acceptable for optional-valued fields (team_id, tty)
        return True
    if field_type in (FieldType.INTEGER,):
        return isinstance(value, int) and not isinstance(value, bool)
    if field_type == FieldType.BOOLEAN:
        return isinstance(value, bool)
    if field_type == FieldType.LIST:
        return isinstance(value, list)
    if field_type in (FieldType.STRING, FieldType.TIMESTAMP):
        return isinstance(value, str)
    return True


class TestSpecCompliance:
    def test_every_record_matches_yaml_schema(self):
        fd = load_format("eslogger")
        records = [json.loads(line) for line in _render_all(_sample_events())]
        assert records, "expected at least one emitted record"
        for record in records:
            for field in fd.fields:
                value = _walk(record, field.name)
                if field.required:
                    assert value is not _SENTINEL, (
                        f"required field {field.name!r} missing from "
                        f"{record.get('event_type')} record"
                    )
                if value is not _SENTINEL:
                    assert _type_ok(value, field.type), (
                        f"field {field.name!r} has wrong type in "
                        f"{record.get('event_type')} record: {value!r}"
                    )

    def test_no_network_records_emitted(self):
        # The emitter must never produce connection/flow records.
        assert "connection" not in ESLoggerEmitter._supported_types
        records = [json.loads(line) for line in _render_all(_sample_events())]
        for record in records:
            assert "flow" not in record["event"]
            assert "connection" not in record["event"]

    def test_event_object_single_named_key(self):
        records = [json.loads(line) for line in _render_all(_sample_events())]
        for record in records:
            assert len(record["event"]) == 1

    def test_format_output_config(self):
        fd = load_format("eslogger")
        assert fd.category == "host"
        assert fd.output.file_extension == ".ndjson"
        assert fd.output.template == "{}"


class TestDeterminism:
    def test_same_events_rendered_twice_byte_identical(self):
        first = _render_all(_sample_events())
        second = _render_all(_sample_events())
        assert first == second
        assert "\n".join(first) == "\n".join(second)

    def test_cdhash_stable_across_runs(self):
        first = [json.loads(line) for line in _render_all(_sample_events())]
        second = [json.loads(line) for line in _render_all(_sample_events())]
        assert first[0]["process"]["cdhash"] == second[0]["process"]["cdhash"]
