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
from evidenceforge.generation.activity.macos_signing import CS_FLAG_BITS
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
        assert rows[0]["process"]["audit_token"]["pid"] == 1
        assert rows[0]["event"]["fork"]["child"]["audit_token"]["pid"] == 1500
        # exec: subject is the same PID, target is the new image with argv + cwd
        exec_event = rows[1]["event"]["exec"]
        assert rows[1]["process"]["audit_token"]["pid"] == 1500
        assert exec_event["target"]["audit_token"]["pid"] == 1500
        assert exec_event["target"]["executable"]["path"] == "/usr/bin/osascript"
        assert exec_event["args"] == ["osascript", "-e", "do shell script"]
        assert exec_event["cwd"] == {"path": "/Users/alice", "path_truncated": False}

    def test_exec_subject_is_pre_exec_image_of_the_parent_binary(self, emitter, mac_host, ts):
        """es_event_exec_t: message process = image before exec, target = image after."""
        proc = ProcessContext(
            1500,
            1,
            "/usr/bin/osascript",
            "osascript",
            "alice",
            start_time=ts,
            parent_image="/bin/zsh",
        )
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        fork_row, exec_row = _rows(emitter, event)
        assert fork_row["event"]["fork"]["child"]["executable"]["path"] == "/bin/zsh"
        assert exec_row["process"]["executable"]["path"] == "/bin/zsh"
        assert exec_row["process"]["signing_id"] == "com.apple.zsh"
        assert exec_row["event"]["exec"]["target"]["signing_id"] == "com.apple.osascript"

    def test_process_object_has_no_top_level_pid(self, emitter, mac_host, ts):
        """es_process_t carries the PID only inside its audit token."""
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        for row in _rows(emitter, event):
            assert "pid" not in row["process"]
            for key in (
                "group_id",
                "is_es_client",
                "responsible_audit_token",
                "parent_audit_token",
            ):
                assert key in row["process"]
            assert row["process"]["executable"]["path_truncated"] is False

    def test_process_terminate_emits_exit(self, emitter, mac_host, ts):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_terminate", src_host=mac_host, process=proc
        )
        rows = _rows(emitter, event)
        assert len(rows) == 1
        assert rows[0]["event_type"] == 15
        assert rows[0]["event"]["exit"] == {"stat": 0}
        assert rows[0]["process"]["audit_token"]["pid"] == 1500

    def test_audit_token_pidversion_from_state_manager(self, emitter, mac_host, ts):
        # create_process assigns pidversion; the emitter must read it, not derive.
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
        fork_row, exec_row = _rows(emitter, event)
        # exec bumps pidversion: the new image is post-exec, the fork child pre-exec.
        assert exec_row["event"]["exec"]["target"]["audit_token"]["pidversion"] == expected
        assert exec_row["process"]["audit_token"]["pidversion"] == expected - 1
        assert fork_row["event"]["fork"]["child"]["audit_token"]["pidversion"] == expected - 1


class TestCodeSigning:
    def test_platform_binary_signed(self, emitter, mac_host, ts):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        target = _rows(emitter, event)[1]["event"]["exec"]["target"]
        assert target["is_platform_binary"] is True
        assert target["signing_id"] == "com.apple.osascript"
        assert target["team_id"] is None
        assert len(target["cdhash"]) == 40
        assert isinstance(target["codesigning_flags"], int)
        assert target["codesigning_flags"] & CS_FLAG_BITS["CS_PLATFORM_BINARY"]

    def test_malware_dropper_is_ad_hoc_without_team_id(self, emitter, mac_host, ts):
        # AMOS trojanized-cleaner dropper resolves to an ad-hoc identity.
        image = "/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper"
        proc = ProcessContext(1600, 1, image, "CleanMyMacX Helper", "alice", start_time=ts)
        event = SecurityEvent(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        exec_event = _rows(emitter, event)[1]["event"]["exec"]
        target = exec_event["target"]
        assert target["is_platform_binary"] is False
        assert target["team_id"] is None
        assert target["codesigning_flags"] & CS_FLAG_BITS["CS_ADHOC"]
        assert not target["codesigning_flags"] & CS_FLAG_BITS["CS_PLATFORM_BINARY"]
        assert exec_event["image_cpusubtype"] == 0


class TestFileEvents:
    @pytest.mark.parametrize(
        "event_type,es_name,code",
        [
            ("file_create", "create", 13),
            ("file_open", "open", 10),
            ("file_write", "write", 33),
            ("file_rename", "rename", 25),
            ("file_unlink", "unlink", 32),
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
        assert rows[0]["process"]["audit_token"]["pid"] == 1700

    def test_create_reports_existing_file_destination(self, emitter, mac_host, ts):
        path = "/Users/alice/Library/LaunchAgents/com.example.plist"
        event = SecurityEvent(
            timestamp=ts,
            event_type="file_create",
            src_host=mac_host,
            file=FileContext(path=path, action="create"),
            auth=AuthContext(username="alice"),
        )
        payload = _rows(emitter, event)[0]["event"]["create"]
        assert payload["destination_type"] == 0
        assert payload["destination"]["existing_file"]["path"] == path

    def test_open_reports_fflag_and_unlink_reports_parent_dir(self, emitter, mac_host, ts):
        path = "/Users/alice/Library/Keychains/login.keychain-db"
        opened = _rows(
            emitter,
            SecurityEvent(
                timestamp=ts,
                event_type="file_open",
                src_host=mac_host,
                file=FileContext(path=path, action="open"),
                auth=AuthContext(username="alice"),
            ),
        )[0]["event"]["open"]
        unlinked = _rows(
            emitter,
            SecurityEvent(
                timestamp=ts,
                event_type="file_unlink",
                src_host=mac_host,
                file=FileContext(path=path, action="unlink"),
                auth=AuthContext(username="alice"),
            ),
        )[0]["event"]["unlink"]
        assert opened["fflag"] == 1
        assert unlinked["parent_dir"]["path"] == "/Users/alice/Library/Keychains"


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
        assert row["event_type"] == 120
        login = row["event"]["openssh_login"]
        assert login["success"] is True
        assert login["result_type"] == 2  # ES_OPENSSH_AUTH_SUCCESS
        assert login["username"] == "alice"
        assert login["source_address"] == "10.0.0.10"
        assert login["source_address_type"] == 1  # ES_ADDRESS_TYPE_IPV4
        assert login["has_uid"] is True
        assert isinstance(login["uid"]["uid"], int)
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
        emitter._openssh_login_sessions.add(("MAC-01", 132500))
        rows = _rows(emitter, event)
        assert rows[0]["event_type"] == 121
        logout = rows[0]["event"]["openssh_logout"]
        assert logout["username"] == "alice"
        assert isinstance(logout["uid"], int)


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
        assert row["event_type"] == 124
        # backgroundtaskmanagementd reports; the plist's dropper is the instigator
        assert row["process"]["executable"]["path"].endswith("/backgroundtaskmanagementd")
        btm = row["event"]["btm_launch_item_add"]
        assert btm["instigator"]["executable"]["path"] == "/bin/cp"
        item = btm["item"]
        assert item["item_type"] == 3  # ES_BTM_ITEM_TYPE_AGENT
        assert item["legacy"] is True
        assert item["item_url"] == "file://" + plist

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
        btm = rows[0]["event"]["btm_launch_item_add"]
        assert btm["item"]["item_type"] == 4  # ES_BTM_ITEM_TYPE_DAEMON
        assert btm["item"]["uid"] == 0
        assert btm["instigator"] is None

    def test_btm_item_url_percent_encodes_spaces(self, emitter, mac_host, ts):
        plist = "/Users/alice/Library/LaunchAgents/com.example agent.plist"
        event = SecurityEvent(
            timestamp=ts,
            event_type="btm_launch_item_add",
            src_host=mac_host,
            file=FileContext(path=plist, action="create"),
            auth=AuthContext(username="alice"),
        )
        item = _rows(emitter, event)[0]["event"]["btm_launch_item_add"]["item"]
        assert item["item_url"].endswith("/com.example%20agent.plist")


class TestEventTypeCodes:
    def test_codes_match_apple_estypes_header(self):
        """Values from <EndpointSecurity/ESTypes.h>; collectors switch on them."""
        from evidenceforge.generation.emitters.eslogger import _ES_EVENT_TYPE_CODES

        assert _ES_EVENT_TYPE_CODES == {
            "exec": 9,
            "open": 10,
            "fork": 11,
            "close": 12,
            "create": 13,
            "exit": 15,
            "rename": 25,
            "unlink": 32,
            "write": 33,
            "lw_session_lock": 116,
            "lw_session_unlock": 117,
            "openssh_login": 120,
            "openssh_logout": 121,
            "btm_launch_item_add": 124,
            "su": 128,
            "sudo": 131,
        }


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
            "version",
            "thread",
            "action_type",
            "action",
        ):
            assert key in row
        assert row["schema_version"] == 1
        assert row["version"] == 7  # macOS 14 message version
        assert row["action_type"] == 1  # ES_ACTION_TYPE_NOTIFY
        assert isinstance(row["thread"]["thread_id"], int)
        # timespec rendered with nanosecond precision
        assert row["time"].endswith("Z")
        assert len(row["time"].split(".")[1]) == 10
        assert isinstance(row["mach_time"], int) and row["mach_time"] > 0

    @pytest.mark.parametrize(
        ("os_name", "version"), [("macOS 13.6", 6), ("macOS 14.5", 7), ("macOS 15.1", 8)]
    )
    def test_message_version_tracks_macos_release(self, os_name, version):
        host = HostContext(
            hostname="MAC-02",
            ip="10.0.0.51",
            os=os_name,
            os_category="macos",
            system_type="workstation",
        )
        assert ESLoggerEmitter._message_version(host) == version

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
        # 26 hours between BOOT and ts = 93600 s, in 24 MHz Apple Silicon ticks
        assert row["mach_time"] == 93600 * 24_000_000
