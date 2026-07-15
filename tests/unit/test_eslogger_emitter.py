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

"""Per-event-type field-rendering tests for ESLoggerEmitter.

Constructs SecurityEvents for each supported event type directly (no full
generation pipeline) and asserts the rendered NDJSON line carries the correct
field values, types, and envelope fields.
"""

import json
from datetime import UTC, datetime

import pytest

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import (
    AuthContext,
    EdrContext,
    FileContext,
    HostContext,
    ProcessContext,
)
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.emitters.eslogger import ESLoggerEmitter
from evidenceforge.generation.state_manager import StateManager

BOOT = datetime(2024, 3, 14, 8, 0, 0, tzinfo=UTC)


@pytest.fixture
def ts():
    return datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)


@pytest.fixture
def mac_host():
    return HostContext(
        hostname="MAC-01",
        ip="10.0.0.50",
        os="macOS 14.4",
        os_category="macos",
        system_type="workstation",
        fqdn="MAC-01.corp.local",
    )


@pytest.fixture
def win_host():
    return HostContext(
        hostname="WS-01",
        ip="10.0.0.10",
        os="Windows 11",
        os_category="windows",
        system_type="workstation",
    )


@pytest.fixture
def emitter(tmp_path):
    fd = load_format("eslogger")
    sm = StateManager()
    sm.register_boot_time("MAC-01", BOOT)
    e = ESLoggerEmitter(fd, tmp_path, threaded=False)
    e._state_manager = sm
    return e


def _rows(emitter, event):
    """Capture the event_data dicts an emit() produces, then render each line."""
    captured = []
    original = emitter.emit_event
    emitter.emit_event = lambda ed: captured.append(ed)
    try:
        emitter.emit(event)
    finally:
        emitter.emit_event = original
    return [json.loads(emitter._render_event(ed)) for ed in captured]


class TestCanHandle:
    def test_macos_process_create_handled(self, emitter, mac_host, ts):
        event = SecurityEvent(
            timestamp=ts,
            event_type="process_create",
            src_host=mac_host,
            process=ProcessContext(1234, 1, "/usr/bin/osascript", "osascript", "alice"),
        )
        assert emitter.can_handle(event) is True

    def test_windows_process_create_rejected(self, emitter, win_host, ts):
        event = SecurityEvent(
            timestamp=ts,
            event_type="process_create",
            src_host=win_host,
            process=ProcessContext(1234, 4, r"C:\Windows\cmd.exe", "cmd.exe", "alice"),
        )
        assert emitter.can_handle(event) is False

    def test_connection_never_supported(self, emitter):
        assert "connection" not in emitter._supported_types

    def test_ssh_session_gated_on_dst_host(self, emitter, mac_host, win_host, ts):
        # macOS destination -> handled (session events log on dst_host)
        event = SecurityEvent(
            timestamp=ts,
            event_type="ssh_session",
            src_host=win_host,
            dst_host=mac_host,
            auth=AuthContext(username="alice", source_ip="10.0.0.10", session_id=132500),
        )
        assert emitter.can_handle(event) is True


class TestProcessLifecycle:
    def test_process_create_emits_fork_then_exec(self, emitter, mac_host, ts):
        proc = ProcessContext(
            pid=1500,
            parent_pid=1,
            image="/usr/bin/osascript",
            command_line='osascript -e "do shell script"',
            username="alice",
            start_time=ts,
        )
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        rows = _rows(emitter, event)
        assert [r["event_type"] for r in rows] == [11, 9]
        assert list(rows[0]["event"].keys()) == ["fork"]
        assert list(rows[1]["event"].keys()) == ["exec"]
        # fork subject is the parent (pid 1 = launchd), child in the event
        assert rows[0]["process"]["pid"] == 1
        assert rows[0]["event"]["fork"]["child"]["pid"] == 1500
        # exec subject is the new image with full argv + cwd
        assert rows[1]["process"]["pid"] == 1500
        assert rows[1]["event"]["exec"]["args"] == ["osascript", "-e", "do shell script"]
        assert rows[1]["event"]["exec"]["cwd"]["path"] == "/Users/alice"

    def test_process_terminate_emits_exit(self, emitter, mac_host, ts):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_terminate", src_host=mac_host, process=proc
        )
        rows = _rows(emitter, event)
        assert len(rows) == 1
        assert rows[0]["event_type"] == 15
        assert "exit" in rows[0]["event"]
        assert rows[0]["process"]["pid"] == 1500

    def test_audit_token_pidversion_from_state_manager(self, emitter, mac_host, ts):
        # create_process bumps pidversion; the emitter must read it, not derive.
        sm = emitter._state_manager
        sm.set_current_time(ts)
        from evidenceforge.models.state import RunningProcess

        sm.state.running_processes[("MAC-01", 1)] = RunningProcess(
            pid=1,
            parent_pid=0,
            image="/sbin/launchd",
            command_line="/sbin/launchd",
            username="root",
            system="MAC-01",
            start_time=ts,
            integrity_level="System",
        )
        pid = sm.create_process(
            "MAC-01", 1, "/usr/bin/osascript", "osascript", "alice", "Medium", os_category="macos"
        )
        expected = sm.get_pidversion("MAC-01", pid)
        proc = ProcessContext(pid, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        rows = _rows(emitter, event)
        assert rows[1]["process"]["audit_token"]["pidversion"] == expected


class TestCodeSigning:
    def test_platform_binary_signed(self, emitter, mac_host, ts):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        exec_row = _rows(emitter, event)[1]
        p = exec_row["process"]
        assert p["is_platform_binary"] is True
        assert p["signing_id"] == "com.apple.osascript"
        assert p["team_id"] is None
        assert len(p["cdhash"]) == 40
        assert "CS_PLATFORM_BINARY" in p["codesigning_flags"]

    def test_malware_dropper_unsigned(self, emitter, mac_host, ts):
        # AMOS trojanized-cleaner dropper resolves to unsigned/ad-hoc (Task 8).
        image = "/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper"
        proc = ProcessContext(1600, 1, image, "CleanMyMacX Helper", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        exec_row = _rows(emitter, event)[1]
        p = exec_row["process"]
        assert p["is_platform_binary"] is False
        assert "CS_PLATFORM_BINARY" not in p["codesigning_flags"]


class TestFileEvents:
    @pytest.mark.parametrize(
        "event_type,es_name,code",
        [
            ("file_create", "create", 13),
            ("file_open", "open", 10),
            ("file_write", "write", 24),
            ("file_rename", "rename", 26),
            ("file_unlink", "unlink", 27),
        ],
    )
    def test_file_event_names(self, emitter, mac_host, ts, event_type, es_name, code):
        proc = ProcessContext(1700, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        path = "/Users/alice/Library/Keychains/login.keychain-db"
        event = SecurityEvent(
            timestamp=ts,
            event_type=event_type,
            src_host=mac_host,
            process=proc,
            file=FileContext(path=path, action=es_name, pid=1700),
            auth=AuthContext(username="alice"),
        )
        rows = _rows(emitter, event)
        assert len(rows) == 1
        assert rows[0]["event_type"] == code
        assert es_name in rows[0]["event"]
        # the path shows up in the event payload regardless of ES sub-key
        assert path in json.dumps(rows[0]["event"][es_name])
        assert rows[0]["process"]["pid"] == 1700


class TestSshSessions:
    def test_openssh_login(self, emitter, mac_host, win_host, ts):
        event = SecurityEvent(
            timestamp=ts,
            event_type="ssh_session",
            src_host=win_host,
            dst_host=mac_host,
            auth=AuthContext(
                username="alice", source_ip="10.0.0.10", source_port=54321, session_id=132500
            ),
            edr=EdrContext(object_id="sess-1"),
        )
        rows = _rows(emitter, event)
        assert len(rows) == 1
        row = rows[0]
        assert row["event_type"] == 106
        login = row["event"]["openssh_login"]
        assert login["success"] is True
        assert login["username"] == "alice"
        assert login["source_address"] == "10.0.0.10"
        assert login["source_address_type"] == "ipv4"
        # session id from the ES audit-token identity (SSH bundle, Task 5)
        assert row["process"]["session_id"] == 132500

    def test_openssh_logout(self, emitter, mac_host, win_host, ts):
        event = SecurityEvent(
            timestamp=ts,
            event_type="logoff",
            src_host=win_host,
            dst_host=mac_host,
            auth=AuthContext(username="alice", source_ip="10.0.0.10", session_id=132500),
        )
        rows = _rows(emitter, event)
        assert rows[0]["event_type"] == 107
        assert "openssh_logout" in rows[0]["event"]
        assert rows[0]["event"]["openssh_logout"]["username"] == "alice"


class TestBtm:
    def test_btm_launch_item_add_agent(self, emitter, mac_host, ts):
        plist = "/Users/alice/Library/LaunchAgents/com.evil.persist.plist"
        proc = ProcessContext(1800, 1, "/bin/cp", "cp", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts,
            event_type="btm_launch_item_add",
            src_host=mac_host,
            process=proc,
            file=FileContext(path=plist, action="create", pid=1800),
            auth=AuthContext(username="alice"),
        )
        rows = _rows(emitter, event)
        assert len(rows) == 1
        row = rows[0]
        assert row["event_type"] == 105
        item = row["event"]["btm_launch_item_add"]["item"]
        assert item["item_type"] == "agent"
        assert item["url"]["path"] == plist

    def test_btm_launch_item_add_daemon(self, emitter, mac_host, ts):
        plist = "/Library/LaunchDaemons/com.evil.persist.plist"
        event = SecurityEvent(
            timestamp=ts,
            event_type="btm_launch_item_add",
            src_host=mac_host,
            file=FileContext(path=plist, action="create", pid=0),
            auth=AuthContext(username="root"),
        )
        rows = _rows(emitter, event)
        item = rows[0]["event"]["btm_launch_item_add"]["item"]
        assert item["item_type"] == "daemon"


class TestEnvelope:
    def test_envelope_fields_present(self, emitter, mac_host, ts):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        row = _rows(emitter, event)[0]
        for key in (
            "schema_version",
            "time",
            "mach_time",
            "seq_num",
            "global_seq_num",
            "event_type",
            "event",
            "process",
        ):
            assert key in row
        assert row["schema_version"] == 1
        assert row["time"].endswith("Z")
        assert isinstance(row["mach_time"], int) and row["mach_time"] > 0

    def test_seq_numbers_increment(self, emitter, mac_host, ts):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        rows = _rows(emitter, event)
        assert [r["seq_num"] for r in rows] == [1, 2]
        assert [r["global_seq_num"] for r in rows] == [1, 2]

    def test_mach_time_reflects_boot(self, emitter, mac_host, ts):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        row = _rows(emitter, event)[0]
        # 26 hours between BOOT and ts = 93600 s -> ns
        assert row["mach_time"] == 93600 * 1_000_000_000
