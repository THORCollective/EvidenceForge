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

"""Producer + renderer tests for the macOS ES signals closed by Task 9b.

Each test drives the canonical producer (SSH bundle close, workstation
lock/unlock bundles, or the sudo/su privilege-elevation producer/hook) through a
real ``ActivityGenerator`` with a capturing dispatcher, then feeds the resulting
canonical ``SecurityEvent``s through a real ``ESLoggerEmitter`` and asserts the
rendered ES event names/codes — proving the events actually render, not merely
that a SecurityEvent was constructed.
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import ProcessContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.formats.loader import load_format
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.emitters.eslogger import ESLoggerEmitter
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User

BOOT = datetime(2024, 3, 14, 8, 0, 0, tzinfo=UTC)
TS = datetime(2024, 3, 15, 10, 0, 0, tzinfo=UTC)

MAC = System(hostname="MAC-01", ip="10.0.0.50", os="macOS 14.4", type="workstation")
WIN = System(hostname="WS-01", ip="10.0.0.10", os="Windows 11", type="workstation")
ALICE = User(username="alice", full_name="Alice", email="alice@corp.local", enabled=True)


def _make_gen() -> tuple[ActivityGenerator, list[SecurityEvent], StateManager]:
    """Build an ActivityGenerator whose dispatcher captures every dispatched event."""
    sm = StateManager()
    sm.set_current_time(TS)
    emitters: dict[str, MagicMock] = {}
    for name in ("zeek_conn", "zeek_dns", "ecar", "syslog", "web_access", "snort_alert"):
        m = MagicMock()
        m.can_handle.return_value = False
        emitters[name] = m
    dispatcher = EventDispatcher(sm, emitters)
    captured: list[SecurityEvent] = []
    original = dispatcher.dispatch

    def capturing(event: SecurityEvent) -> None:
        captured.append(event)
        original(event)

    dispatcher.dispatch = capturing
    gen = ActivityGenerator(sm, emitters, dispatcher=dispatcher)
    return gen, captured, sm


def _eslogger(tmp_path, sm: StateManager) -> ESLoggerEmitter:
    fd = load_format("eslogger")
    e = ESLoggerEmitter(fd, tmp_path, threaded=False)
    e._state_manager = sm
    return e


def _render(emitter: ESLoggerEmitter, event: SecurityEvent) -> list[dict]:
    """Render a single event through the emitter, returning the NDJSON records."""
    captured: list[dict] = []
    original = emitter.emit_event
    emitter.emit_event = lambda ed: captured.append(ed)
    try:
        emitter.emit(event)
    finally:
        emitter.emit_event = original
    return [json.loads(emitter._render_event(ed)) for ed in captured]


def _proc(image: str, cmd: str, *, pid: int = 1500, ppid: int = 1) -> ProcessContext:
    return ProcessContext(
        pid=pid,
        parent_pid=ppid,
        image=image,
        command_line=cmd,
        username="alice",
        start_time=TS,
    )


# ---------------------------------------------------------------------------
# Sub-item 1: SSH session close -> openssh_logout
# ---------------------------------------------------------------------------


def test_macos_ssh_session_close_renders_login_then_logout(tmp_path):
    """emit_session_close on a macOS SSH target yields openssh_login then openssh_logout."""
    gen, events, sm = _make_gen()
    sm.register_boot_time("MAC-01", BOOT)

    gen.generate_ssh_session(
        user=ALICE,
        target_system=MAC,
        time=TS,
        source_ip="10.0.0.10",
        source_port=54321,
        emit_session_close=True,
    )

    session_events = [e for e in events if e.event_type in ("ssh_session", "logoff")]
    assert [e.event_type for e in session_events] == ["ssh_session", "logoff"]
    login_ev, logout_ev = session_events
    assert login_ev.dst_host is not None and login_ev.dst_host.os_category == "macos"
    assert logout_ev.dst_host is not None and logout_ev.dst_host.os_category == "macos"
    assert logout_ev.timestamp > login_ev.timestamp
    # macOS close carries no Linux-style sshd/systemd-logind syslog companion.
    assert logout_ev.syslog is None
    # The logoff carries the ES audit-token session identity used by the login.
    assert logout_ev.auth is not None and logout_ev.auth.session_id == login_ev.auth.session_id

    emitter = _eslogger(tmp_path, sm)
    login_rows = _render(emitter, login_ev)
    logout_rows = _render(emitter, logout_ev)
    assert login_rows[0]["event_type"] == 106
    assert "openssh_login" in login_rows[0]["event"]
    assert logout_rows[0]["event_type"] == 107
    assert "openssh_logout" in logout_rows[0]["event"]
    assert logout_rows[0]["event"]["openssh_logout"]["username"] == "alice"


# ---------------------------------------------------------------------------
# Sub-item 2: screen lock/unlock -> lw_session
# ---------------------------------------------------------------------------


def test_macos_interactive_lock_unlock_renders_lw_session(tmp_path):
    """A macOS interactive session locks/unlocks as ES lw_session events."""
    gen, events, sm = _make_gen()
    sm.register_boot_time("MAC-01", BOOT)
    logon_id = sm.create_session(
        username="alice",
        system="MAC-01",
        logon_type=2,
        source_ip="10.0.0.50",
        session_kind="interactive",
        start_time=TS,
    )

    lock_time = TS + timedelta(minutes=5)
    unlock_time = TS + timedelta(minutes=35)
    gen.generate_workstation_lock(user=ALICE, system=MAC, time=lock_time, logon_id=logon_id)
    gen.generate_workstation_unlock(user=ALICE, system=MAC, time=unlock_time, logon_id=logon_id)

    lock_ev = next(e for e in events if e.event_type == "workstation_locked")
    unlock_ev = next(e for e in events if e.event_type == "workstation_unlocked")
    assert lock_ev.dst_host is not None and lock_ev.dst_host.os_category == "macos"
    # macOS screen unlock produces no Windows-style Type 7 re-auth logon.
    assert not any(
        e.event_type == "logon" and e.auth is not None and e.auth.logon_type == 7 for e in events
    )

    emitter = _eslogger(tmp_path, sm)
    lock_rows = _render(emitter, lock_ev)
    unlock_rows = _render(emitter, unlock_ev)
    assert lock_rows[0]["event_type"] == 108
    assert "lw_session_lock" in lock_rows[0]["event"]
    assert lock_rows[0]["event"]["lw_session_lock"]["username"] == "alice"
    assert unlock_rows[0]["event_type"] == 109
    assert "lw_session_unlock" in unlock_rows[0]["event"]
    # loginwindow is the reporting process for lw_session events.
    assert lock_rows[0]["process"]["executable"]["path"].endswith("loginwindow")


def test_windows_lock_still_gated_windows_only():
    """The macOS widening must not accept Linux interactive sessions."""
    from evidenceforge.generation.activity.generator import _is_lockable_workstation_session

    linux_session = MagicMock(logon_type=2, session_kind="interactive")
    assert _is_lockable_workstation_session(linux_session, "linux") is False
    assert _is_lockable_workstation_session(linux_session, "macos") is True
    assert _is_lockable_workstation_session(linux_session, "windows") is True
    ssh_session = MagicMock(logon_type=10, session_kind="ssh")
    assert _is_lockable_workstation_session(ssh_session, "macos") is False


# ---------------------------------------------------------------------------
# Sub-item 3: sudo/su privilege elevation -> ES sudo/su
# ---------------------------------------------------------------------------


def test_privilege_elevation_renders_as_sudo(tmp_path):
    """generate_privilege_elevation for /usr/bin/sudo renders as an ES sudo event."""
    gen, events, sm = _make_gen()
    sm.register_boot_time("MAC-01", BOOT)
    proc = _proc("/usr/bin/sudo", "sudo /usr/bin/whoami")

    gen.generate_privilege_elevation(system=MAC, time=TS, process=proc, from_username="alice")

    ev = next(e for e in events if e.event_type == "privilege_elevation")
    assert ev.src_host is not None and ev.src_host.os_category == "macos"

    emitter = _eslogger(tmp_path, sm)
    rows = _render(emitter, ev)
    assert rows[0]["event_type"] == 131
    sudo = rows[0]["event"]["sudo"]
    assert sudo["success"] is True
    assert sudo["from_username"] == "alice"
    assert sudo["to_username"] == "root"
    assert sudo["to_uid"] == 0
    assert sudo["command"] == "sudo /usr/bin/whoami"
    assert rows[0]["process"]["executable"]["path"] == "/usr/bin/sudo"


def test_privilege_elevation_renders_as_su(tmp_path):
    """A /usr/bin/su elevation renders as an ES su event."""
    gen, events, sm = _make_gen()
    sm.register_boot_time("MAC-01", BOOT)
    proc = _proc("/usr/bin/su", "su -")

    gen.generate_privilege_elevation(system=MAC, time=TS, process=proc, from_username="alice")

    ev = next(e for e in events if e.event_type == "privilege_elevation")
    emitter = _eslogger(tmp_path, sm)
    rows = _render(emitter, ev)
    assert rows[0]["event_type"] == 130
    assert "su" in rows[0]["event"]
    assert rows[0]["event"]["su"]["from_username"] == "alice"


def test_macos_sudo_exec_triggers_privilege_elevation_hook():
    """A macOS process create for sudo/su fires the privilege_elevation producer."""
    gen, events, _sm = _make_gen()
    gen._maybe_emit_macos_privilege_elevation(MAC, TS, _proc("/usr/bin/sudo", "sudo -l"))
    assert any(e.event_type == "privilege_elevation" for e in events)


def test_non_sudo_macos_exec_does_not_trigger_hook():
    """Ordinary macOS process creates do not emit a privilege_elevation event."""
    gen, events, _sm = _make_gen()
    gen._maybe_emit_macos_privilege_elevation(MAC, TS, _proc("/usr/bin/curl", "curl https://x"))
    assert not any(e.event_type == "privilege_elevation" for e in events)


def test_windows_sudo_basename_does_not_trigger_hook():
    """The hook is macOS-only even when a non-macOS host runs a sudo-named binary."""
    gen, events, _sm = _make_gen()
    gen._maybe_emit_macos_privilege_elevation(WIN, TS, _proc("/usr/bin/sudo", "sudo x"))
    assert not any(e.event_type == "privilege_elevation" for e in events)
