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
import random
from datetime import UTC, datetime, timedelta

import pytest

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import (
    AuthContext,
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


def _event_name(row: dict) -> str:
    return next(iter(row["event"]))


class TestCanHandle:
    def test_macos_process_create_handled(self, emitter, mac_host, ts):
        event = OccurrenceBuilder(
            timestamp=ts,
            event_type="process_create",
            src_host=mac_host,
            process=ProcessContext(1234, 1, "/usr/bin/osascript", "osascript", "alice"),
        )
        assert emitter.can_handle(event) is True

    def test_windows_process_create_rejected(self, emitter, win_host, ts):
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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
        assert exec_event["cwd"]["path"] == "/Users/alice"
        assert exec_event["cwd"]["path_truncated"] is False
        assert exec_event["cwd"]["stat"]["st_mode"] & 0o170000 == 0o040000  # a directory

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
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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
        sm.register_process(
            system="MAC-01",
            pid=1,
            parent_pid=0,
            image="/sbin/launchd",
            command_line="/sbin/launchd",
            username="root",
            integrity_level="System",
            os_category="macos",
            start_time=ts,
        )
        pid = sm.create_process(
            "MAC-01", 1, "/usr/bin/osascript", "osascript", "alice", "Medium", os_category="macos"
        )
        expected = sm.get_pidversion("MAC-01", pid)
        assert expected > 0
        proc = ProcessContext(pid, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
            timestamp=ts,
            event_type=event_type,
            src_host=mac_host,
            process=proc,
            file=FileContext(path=path, action=es_name, pid=1700),
            auth=AuthContext(username="alice"),
        )
        rows = _rows(emitter, event)
        # The canonical beat is always rendered exactly once, by the same process;
        # open/write/create also carry their derived fd open/close records.
        beat = [r for r in rows if r["event_type"] == code and es_name in r["event"]]
        assert len(beat) == 1
        # the path shows up in the event payload regardless of ES sub-key
        assert path in json.dumps(beat[0]["event"][es_name])
        assert all(r["process"]["audit_token"]["pid"] == 1700 for r in rows)
        expected = {
            "create": ["create", "close"],
            "open": ["open", "close"],
            "write": ["open", "write", "close"],
            "rename": ["rename"],
            "unlink": ["unlink"],
        }[es_name]
        assert [_event_name(r) for r in sorted(rows, key=lambda r: r["time"])] == expected


class TestFileDescriptorLifecycle:
    def _file_rows(self, emitter, mac_host, ts, event_type, action):
        proc = ProcessContext(1700, 1, "/usr/sbin/cfprefsd", "cfprefsd", "alice", start_time=ts)
        event = OccurrenceBuilder(
            timestamp=ts,
            event_type=event_type,
            src_host=mac_host,
            process=proc,
            file=FileContext(
                path="/Users/alice/Library/Preferences/com.apple.dock.plist",
                action=action,
                pid=1700,
            ),
            auth=AuthContext(username="alice"),
        )
        return sorted(_rows(emitter, event), key=lambda r: r["time"])

    def test_write_is_bracketed_by_read_write_open_and_modified_close(self, emitter, mac_host, ts):
        opened, written, closed = self._file_rows(emitter, mac_host, ts, "file_write", "write")
        assert opened["event"]["open"]["fflag"] == 0x3  # FREAD | FWRITE
        assert opened["time"] < written["time"] < closed["time"]
        assert closed["event_type"] == 12
        assert closed["event"]["close"]["modified"] is True
        assert closed["event"]["close"]["was_mapped_writable"] is False

    def test_read_open_is_followed_by_unmodified_close(self, emitter, mac_host, ts):
        opened, closed = self._file_rows(emitter, mac_host, ts, "file_open", "open")
        assert opened["event"]["open"]["fflag"] == 0x1
        assert closed["event"]["close"]["modified"] is False
        assert closed["event"]["close"]["target"] == opened["event"]["open"]["file"]


class TestFileStat:
    """Every es_file_t carries a stat shaped like a real eslogger capture."""

    _STAT_KEYS = {
        "st_dev",
        "st_mode",
        "st_nlink",
        "st_ino",
        "st_uid",
        "st_gid",
        "st_rdev",
        "st_atimespec",
        "st_mtimespec",
        "st_ctimespec",
        "st_birthtimespec",
        "st_size",
        "st_blocks",
        "st_blksize",
        "st_flags",
        "st_gen",
    }

    def _write_rows(self, emitter, mac_host, ts, path, image="/usr/sbin/cfprefsd"):
        proc = ProcessContext(1700, 1, image, image.rsplit("/", 1)[-1], "alice", start_time=ts)
        event = OccurrenceBuilder(
            timestamp=ts,
            event_type="file_write",
            src_host=mac_host,
            process=proc,
            file=FileContext(path=path, action="write", pid=1700),
            auth=AuthContext(username="alice"),
        )
        return sorted(_rows(emitter, event), key=lambda r: r["time"])

    def test_every_es_file_has_a_full_stat(self, emitter, mac_host, ts):
        rows = self._write_rows(emitter, mac_host, ts, "/Users/alice/Library/Preferences/x.plist")
        for row in rows:
            assert set(row["process"]["executable"]["stat"]) == self._STAT_KEYS
            payload = next(iter(row["event"].values()))
            es_file = payload.get("file") or payload.get("target")
            assert set(es_file["stat"]) == self._STAT_KEYS

    def test_write_grows_the_file_and_moves_mtime(self, emitter, mac_host, ts):
        from evidenceforge.generation.emitters.eslogger import _es_client_sequence_numbering

        rows = self._write_rows(emitter, mac_host, ts, "/Users/alice/Library/Preferences/x.plist")
        number = _es_client_sequence_numbering()
        opened, written, closed = [
            json.loads(number(json.dumps(r, separators=(",", ":")))) for r in rows
        ]
        before = opened["event"]["open"]["file"]["stat"]
        after = written["event"]["write"]["target"]["stat"]
        assert after["st_ino"] == before["st_ino"]
        assert after["st_size"] > before["st_size"]
        assert after["st_mtimespec"] > before["st_mtimespec"]
        assert after["st_mtimespec"] < written["time"]
        assert after["st_blocks"] == -(-after["st_size"] // 4096) * 8
        assert closed["event"]["close"]["target"]["stat"] == after

    def test_out_of_order_emission_still_reads_in_time_order(self):
        from evidenceforge.generation.emitters.eslogger_stat import FileWriteTimeline

        def rec(event_type, key, time, size, mtime):
            stat = {
                "st_size": size,
                "st_mtimespec": mtime,
                "st_ctimespec": mtime,
                "st_birthtimespec": mtime,
                "st_blocks": 0,
                "st_flags": 0,
                "st_mode": 0o100644,
            }
            sub = (
                {"file": {"path": "/p", "stat": stat}}
                if key == "open"
                else {"target": {"path": "/p", "stat": stat}}
            )
            return {"time": time, "event_type": event_type, "event": {key: sub}}

        base = "2024-06-01T00:00:00.000000000Z"
        timeline = FileWriteTimeline()
        records = [
            rec(10, "open", "2024-06-11T10:00:00.000000100Z", 1000, base),
            rec(33, "write", "2024-06-11T10:00:00.000200100Z", 1000, base),
            rec(12, "close", "2024-06-11T10:00:00.000400100Z", 1000, base),
            rec(33, "write", "2024-06-11T10:00:00.000600100Z", 1000, base),
            rec(12, "close", "2024-06-11T10:00:00.000800100Z", 1000, base),
        ]
        for r in records:
            timeline.apply(r)
        sizes = [
            next(iter(next(iter(r["event"].values())).values()))["stat"]["st_size"] for r in records
        ]
        assert sizes[0] == 1000
        assert sizes[1] > 1000 and sizes[2] == sizes[1]
        assert sizes[3] > sizes[2] and sizes[4] == sizes[3]

    def test_user_preference_file_shape(self, emitter, mac_host, ts):
        emitter.configure_local_accounts({"MAC-01": "alice"}, ["alice"])
        st = self._write_rows(emitter, mac_host, ts, "/Users/alice/Library/Preferences/y.plist")[1][
            "event"
        ]["write"]["target"]["stat"]
        assert (st["st_mode"], st["st_uid"], st["st_gid"], st["st_flags"]) == (
            0o100600,
            501,
            20,
            0,
        )
        assert st["st_blocks"] == -(-st["st_size"] // 4096) * 8
        assert not st["st_mtimespec"].endswith(".000000000Z")

    def test_system_binary_shape(self, emitter, mac_host, ts):
        exe = self._write_rows(emitter, mac_host, ts, "/tmp/z")[0]["process"]["executable"]
        st = exe["stat"]
        assert exe["path"] == "/usr/sbin/cfprefsd"
        assert (st["st_mode"], st["st_uid"], st["st_gid"], st["st_nlink"]) == (
            0o100755,
            0,
            0,
            1,
        )
        assert st["st_flags"] == 0x80020  # SF_RESTRICTED | UF_COMPRESSED
        assert st["st_blocks"] * 512 < st["st_size"]  # compressed on disk
        times = {
            st[k] for k in ("st_atimespec", "st_mtimespec", "st_ctimespec", "st_birthtimespec")
        }
        assert len(times) == 1 and times.pop().endswith(".000000000Z")

    def test_created_file_is_owned_by_its_creator_and_starts_empty(self, emitter, mac_host, ts):
        proc = ProcessContext(1800, 1, "/Users/Shared/.x/helper", "helper", "alice", start_time=ts)
        event = OccurrenceBuilder(
            timestamp=ts,
            event_type="file_create",
            src_host=mac_host,
            process=proc,
            file=FileContext(path="/Users/Shared/.x/dropped.plist", action="create", pid=1800),
            auth=AuthContext(username="alice"),
        )
        created = next(r for r in _rows(emitter, event) if r["event_type"] == 13)
        st = created["event"]["create"]["destination"]["existing_file"]["stat"]
        assert st["st_size"] == 0 and st["st_blocks"] == 0
        assert st["st_uid"] == created["process"]["audit_token"]["euid"]
        assert st["st_birthtimespec"] == st["st_mtimespec"]


class TestLocalAccountUids:
    def test_assigned_user_is_501_and_other_users_follow(self, emitter):
        emitter.configure_local_accounts(
            {"MAC-01": "alice", "MAC-02": "bob"}, ["carol", "bob", "alice"]
        )
        assert emitter._macos_ids("alice", "MAC-01") == {"uid": 501, "gid": 20}
        assert emitter._macos_ids("bob", "MAC-02") == {"uid": 501, "gid": 20}
        # Non-primary accounts on MAC-01, in sorted username order: bob, carol.
        assert emitter._macos_ids("bob", "MAC-01")["uid"] == 502
        assert emitter._macos_ids("carol", "MAC-01")["uid"] == 503
        assert emitter._macos_ids("root", "MAC-01") == {"uid": 0, "gid": 0}

    def test_without_account_layout_uids_stay_in_user_band(self, emitter):
        uid = emitter._macos_ids("alice", "MAC-01")["uid"]
        assert 501 <= uid <= 600

    def test_create_reports_existing_file_destination(self, emitter, mac_host, ts):
        path = "/Users/alice/Library/LaunchAgents/com.example.plist"
        event = OccurrenceBuilder(
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
            OccurrenceBuilder(
                timestamp=ts,
                event_type="file_open",
                src_host=mac_host,
                file=FileContext(path=path, action="open"),
                auth=AuthContext(username="alice"),
            ),
        )[0]["event"]["open"]
        unlinked = _rows(
            emitter,
            OccurrenceBuilder(
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
        event = OccurrenceBuilder(
            timestamp=ts,
            event_type="ssh_session",
            src_host=win_host,
            dst_host=mac_host,
            auth=AuthContext(
                username="alice", source_ip="10.0.0.10", source_port=54321, session_id=132500
            ),
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
        event = OccurrenceBuilder(
            timestamp=ts,
            event_type="logoff",
            src_host=win_host,
            dst_host=mac_host,
            auth=AuthContext(username="alice", source_ip="10.0.0.10", session_id=132500),
        )
        emitter._openssh_login_sessions[("MAC-01", 132500)] = {}
        rows = _rows(emitter, event)
        assert rows[0]["event_type"] == 121
        logout = rows[0]["event"]["openssh_logout"]
        assert logout["username"] == "alice"
        assert isinstance(logout["uid"], int)


class TestBtm:
    def test_btm_launch_item_add_agent(self, emitter, mac_host, ts):
        plist = "/Users/alice/Library/LaunchAgents/com.evil.persist.plist"
        proc = ProcessContext(1800, 1, "/bin/cp", "cp", "alice", start_time=ts)
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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
        event = OccurrenceBuilder(
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

    def test_seq_numbers_are_assigned_per_client_in_time_order(
        self, emitter, mac_host, ts, tmp_path
    ):
        # Dispatched out of time order; the published file is time-ordered with a
        # contiguous global_seq_num and a per-event-type seq_num.
        later = ProcessContext(
            1600,
            1,
            "/usr/bin/osascript",
            "osascript",
            "alice",
            start_time=ts + timedelta(seconds=5),
        )
        earlier = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        for proc in (later, earlier):
            emitter.emit(
                OccurrenceBuilder(
                    timestamp=proc.start_time,
                    event_type="process_create",
                    src_host=mac_host,
                    process=proc,
                )
            )
        emitter.close()
        path = tmp_path / "MAC-01.corp.local" / "eslogger.ndjson"
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

        assert [r["time"] for r in rows] == sorted(r["time"] for r in rows)
        assert [_event_name(r) for r in rows] == ["fork", "exec", "fork", "exec"]
        assert [r["global_seq_num"] for r in rows] == [1, 2, 3, 4]
        assert [r["seq_num"] for r in rows] == [1, 1, 2, 2]

    def test_mach_time_reflects_boot(self, emitter, mac_host, ts):
        proc = ProcessContext(1500, 1, "/usr/bin/osascript", "osascript", "alice", start_time=ts)
        event = OccurrenceBuilder(
            timestamp=ts, event_type="process_create", src_host=mac_host, process=proc
        )
        row = _rows(emitter, event)[0]
        # 26 hours between BOOT and ts = 93600 s, in 24 MHz Apple Silicon ticks
        assert row["mach_time"] == 93600 * 24_000_000


class TestEsloggerSerialization:
    """Published lines are written the way `eslogger --format json` writes them."""

    def _publish(self, records):
        from evidenceforge.generation.emitters.eslogger import _es_client_sequence_numbering

        number = _es_client_sequence_numbering()
        return [number(json.dumps(r, separators=(",", ":"))) for r in records]

    def _record(self, i):
        return {
            "time": f"2024-06-11T10:00:{i:02d}.000000000Z",
            "seq_num": 0,
            "global_seq_num": 0,
            "event_type": 9,
            "process": {"executable": {"path": "/usr/bin/osascript", "path_truncated": False}},
            "event": {"exec": {"args": ["osascript", "-e", "display dialog"]}},
        }

    def test_slashes_are_escaped_and_json_round_trips(self):
        (line,) = self._publish([self._record(0)])
        assert "/usr/bin" not in line
        assert "\\/usr\\/bin\\/osascript" in line
        parsed = json.loads(line)
        assert parsed["process"]["executable"]["path"] == "/usr/bin/osascript"
        assert parsed["event"]["exec"]["args"] == ["osascript", "-e", "display dialog"]

    def test_key_order_varies_but_is_reproducible(self):
        records = [self._record(i) for i in range(12)]
        first = self._publish(records)
        assert first == self._publish(records)
        orders = {tuple(json.loads(line)) for line in first}
        assert len(orders) > 1


def test_application_install_stamp_is_whole_seconds_at_another_time_of_day():
    """An /Applications file was unpacked from an archive: birth == mtime in whole
    seconds, at a clock time unrelated to the event that first touches it."""
    from datetime import UTC, datetime

    from evidenceforge.generation.emitters.eslogger_stat import MacFileStatModel

    model = MacFileStatModel(lambda user, host: 501)
    at = datetime(2024, 6, 11, 14, 21, 53, 921201, tzinfo=UTC)
    paths = [
        "/Applications/CleanMyMacX Helper.app/Contents/MacOS/CleanMyMacX Helper",
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/Applications/Slack.app/Contents/MacOS/Slack",
    ]
    for path in paths:
        stat = model.stat("MAC-01.example.test", path, at, kind="exec")
        assert stat["st_birthtimespec"] == stat["st_mtimespec"]
        assert stat["st_birthtimespec"].endswith(".000000000Z")
        assert stat["st_birthtimespec"][11:19] != "14:21:53"
        assert not stat["st_ctimespec"].endswith(".000000000Z")


class TestAuditSessionIds:
    """asid/auid consistency between a login session and its processes."""

    def test_build_process_object_session_logon_uses_allocated_asid(self, emitter, mac_host, ts):
        # Arrange: an SSH bundle records the allocated asid on the session.
        sm = emitter._state_manager
        sm.set_current_time(ts)
        logon_id = sm.create_session(
            username="alice",
            system="MAC-01",
            logon_type=10,
            source_ip="10.0.0.10",
            start_time=ts,
            session_kind="ssh",
            session_id=100031,
        )

        # Act: the session's shell is rendered without an explicit session id.
        shell = emitter._build_process_object(
            mac_host, pid=4321, ppid=4320, image="/bin/zsh", username="alice", logon_id=logon_id
        )

        # Assert
        assert shell["audit_token"]["asid"] == 100031

    def test_build_process_object_ended_session_keeps_allocated_asid(self, emitter, mac_host, ts):
        # Arrange
        sm = emitter._state_manager
        sm.set_current_time(ts)
        logon_id = sm.create_session(
            username="alice",
            system="MAC-01",
            logon_type=10,
            source_ip="10.0.0.10",
            start_time=ts,
            session_kind="ssh",
            session_id=100031,
        )
        sm.end_session(logon_id, ts + timedelta(minutes=5))

        # Act: a process exit rendered after logoff.
        shell = emitter._build_process_object(
            mac_host, pid=4321, ppid=4320, image="/bin/zsh", username="alice", logon_id=logon_id
        )

        # Assert
        assert shell["audit_token"]["asid"] == 100031

    @pytest.mark.parametrize("logon_id", ["0x3e7", "0x3e4", "0x3e5", "-", "0x0"])
    def test_build_process_object_service_logon_id_is_system_session(
        self, emitter, mac_host, logon_id
    ):
        # Act
        daemon = emitter._build_process_object(
            mac_host, pid=812, ppid=1, image="/usr/sbin/sshd", username="root", logon_id=logon_id
        )

        # Assert
        assert daemon["audit_token"]["asid"] == 100000
        assert daemon["audit_token"]["auid"] == 4294967295

    def test_resolve_asid_derived_band_disjoint_from_allocator(self):
        # Arrange
        sm = StateManager()
        rng = random.Random(7)
        allocated = {sm.next_macos_audit_session_id("MAC-01", rng) for _ in range(500)}

        # Act
        derived = {
            ESLoggerEmitter._resolve_asid("MAC-01", f"user{n}", f"0x{n:x}", 0, True)
            for n in range(1000)
        }

        # Assert
        assert max(allocated) < min(derived)

    def _console_session(self, emitter, ts, *, session_id):
        sm = emitter._state_manager
        sm.set_current_time(ts)
        return sm.create_session(
            username="alice",
            system="MAC-01",
            logon_type=2,
            source_ip="-",
            start_time=ts,
            session_kind="interactive",
            session_id=session_id,
        )

    def test_build_process_object_user_agent_joins_console_session(self, emitter, mac_host, ts):
        # Arrange: a console login, then a user launchd agent with no logon of its own.
        console_logon = self._console_session(emitter, ts, session_id=1)
        console_shell = emitter._build_process_object(
            mac_host, pid=700, ppid=1, image="/bin/zsh", username="alice", logon_id=console_logon
        )

        # Act
        agent = emitter._build_process_object(
            mac_host,
            pid=701,
            ppid=1,
            image="/System/Library/PrivateFrameworks/CloudKitDaemon.framework/Support/cloudd",
            username="alice",
            logon_id="0x3e7",
            start_time=ts + timedelta(minutes=10),
        )

        # Assert
        assert agent["audit_token"]["asid"] == console_shell["audit_token"]["asid"]
        assert agent["audit_token"]["auid"] == agent["audit_token"]["euid"]

    def test_render_lw_session_windows_style_session_id_matches_console_processes(
        self, emitter, mac_host, ts
    ):
        # Arrange: the console session carries a Windows-style terminal number.
        console_logon = self._console_session(emitter, ts, session_id=2)
        shell = emitter._build_process_object(
            mac_host, pid=700, ppid=1, image="/bin/zsh", username="alice", logon_id=console_logon
        )
        lock_event = OccurrenceBuilder(
            timestamp=ts + timedelta(minutes=5),
            event_type="workstation_locked",
            src_host=mac_host,
            dst_host=mac_host,
            auth=AuthContext(username="alice", logon_id=console_logon, session_id=2),
        )

        # Act
        row = _rows(emitter, lock_event)[0]

        # Assert
        assert (
            row["event"]["lw_session_lock"]["graphical_session_id"]
            == (shell["audit_token"]["asid"])
        )
        assert row["process"]["audit_token"]["asid"] == shell["audit_token"]["asid"]

    def _ssh_session(self, emitter, ts, *, transport_pid=None):
        sm = emitter._state_manager
        sm.set_current_time(ts)
        return sm.create_session(
            username="alice",
            system="MAC-01",
            logon_type=10,
            source_ip="10.0.0.10",
            start_time=ts,
            session_kind="ssh",
            session_id=100031,
            transport_pid=transport_pid,
        )

    def test_build_process_object_connection_sshd_after_logoff_keeps_session_asid(
        self, emitter, mac_host, ts
    ):
        # Arrange: the per-connection sshd started seconds before its session,
        # and the session has ended (binding cleared) before sshd's exit renders.
        logon_id = self._ssh_session(emitter, ts)
        emitter._state_manager.end_session(logon_id, ts + timedelta(minutes=9))

        # Act
        sshd = emitter._build_process_object(
            mac_host,
            pid=36316,
            ppid=1,
            image="/usr/sbin/sshd",
            username="root",
            logon_id="0x3e7",
            start_time=ts - timedelta(seconds=5),
        )

        # Assert
        assert sshd["audit_token"]["asid"] == 100031

    def test_build_process_object_post_auth_sshd_joins_session(self, emitter, mac_host, ts):
        # Arrange: the session is bound to the connection sshd; the post-auth
        # sshd starts just after the session does.
        self._ssh_session(emitter, ts, transport_pid=36316)

        # Act
        sshd = emitter._build_process_object(
            mac_host,
            pid=36322,
            ppid=1,
            image="/usr/sbin/sshd",
            username="root",
            logon_id="0x3e7",
            start_time=ts + timedelta(milliseconds=700),
        )

        # Assert
        assert sshd["audit_token"]["asid"] == 100031

    def test_build_process_object_unrelated_sshd_stays_in_system_session(
        self, emitter, mac_host, ts
    ):
        # Arrange: an sshd started long after the only SSH session began.
        self._ssh_session(emitter, ts)

        # Act
        sshd = emitter._build_process_object(
            mac_host,
            pid=40000,
            ppid=1,
            image="/usr/sbin/sshd",
            username="root",
            logon_id="0x3e7",
            start_time=ts + timedelta(hours=1),
        )

        # Assert
        assert sshd["audit_token"]["asid"] == 100000
        assert sshd["audit_token"]["auid"] == 4294967295
