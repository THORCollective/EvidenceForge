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

"""Emitter for macOS Endpoint Security (eslogger) NDJSON telemetry.

``ESLoggerEmitter`` renders the canonical ``SecurityEvent`` model into
``eslogger``-style Endpoint Security (ESF) NDJSON, one ``eslogger.ndjson`` file
per macOS host (per-FQDN directory routing, like eCAR).  It is a pure renderer:
process identity, code-signing identity, audit-token session identity, and file
paths all come from contexts and ``StateManager`` state that upstream layers
already built (AGENTS.md realism rules #1/#1a).  ES-native envelope fields
(``schema_version``, ``mach_time``, ``seq_num``/``global_seq_num``,
``event_type``) are derived deterministically here.

The record is assembled as a Python dict and serialized with ``json.dumps``,
bypassing Jinja2 exactly like ``EcarEmitter._render_event`` — the
``config/formats/eslogger.yaml`` ``output.template`` is a placeholder only.

Deliberately NO network/connection events: ESF has no TCP-connect event, so
macOS network egress is correlated via the host's existing Zeek conn/dns logs
(design doc "No network events, deliberately").
"""

import json
import logging
import shlex
from datetime import UTC, datetime
from typing import Any

from evidenceforge.events.base import SecurityEvent
from evidenceforge.events.contexts import HostContext
from evidenceforge.generation.activity.macos_signing import get_signing_identity
from evidenceforge.generation.emitters.host_base import HostMultiplexEmitter
from evidenceforge.utils.rng import _stable_seed

logger = logging.getLogger(__name__)

_SCHEMA_VERSION = 1

# KAUTH_UID_NONE == (uid_t)-1 — the audit user id reported for processes that do
# not belong to an authenticated login session (system daemons, launchd jobs).
_KAUTH_UID_NONE = 4294967295

# The macOS "System" audit session id.  Real kernel-assigned login-session asids
# are seeded well above this reserved value (see
# StateManager.next_macos_audit_session_id); daemons run in the system session.
_MACOS_SYSTEM_ASID = 100000

# Fixed reference only used to derive mach_time when no boot time is registered
# (unit tests without a seeded process tree).  In real runs StateManager returns
# the per-host boot time registered during process-tree seeding.
_MACH_TIME_FALLBACK_BOOT = datetime(2024, 1, 1, tzinfo=UTC)

# ES event name -> es_event_type_t integer.  DESIGN NOTE (plan risk #6): no real
# eslogger capture is available to verify these enum integers, so they are a
# best-effort mapping.  The authoritative, hunt-relevant identity is the STRING
# key of the ``event`` object (which the eslogger CLI --events flag and the
# Nebulock macos-coresigma Sigma/ECS pipeline key on); the integer is rendered
# for structural fidelity only and nothing downstream depends on its exact value.
_ES_EVENT_TYPE_CODES: dict[str, int] = {
    "exec": 9,
    "open": 10,
    "fork": 11,
    "close": 12,
    "create": 13,
    "exit": 15,
    "write": 24,
    "rename": 26,
    "unlink": 27,
    "btm_launch_item_add": 105,
    "openssh_login": 106,
    "openssh_logout": 107,
    "lw_session_lock": 108,
    "lw_session_unlock": 109,
    "su": 130,
    "sudo": 131,
}

# Canonical file event_type -> ES file event name.  macOS file activity uses the
# open/write/rename/unlink vocabulary widened onto FileContext by Task 6; plain
# create is shared with other OSes.
_FILE_EVENT_NAMES: dict[str, str] = {
    "file_create": "create",
    "file_open": "open",
    "file_write": "write",
    "file_rename": "rename",
    "file_unlink": "unlink",
}

# Canonical screen lock/unlock event_type -> ES lw_session event name.  The
# generic ``workstation_locked``/``workstation_unlocked`` canonical events (also
# used by Windows 4800/4801) render on macOS as loginwindow lw_session events.
_LW_SESSION_EVENT_NAMES: dict[str, str] = {
    "workstation_locked": "lw_session_lock",
    "workstation_unlocked": "lw_session_unlock",
}

# Event types whose eslogger record belongs to the destination host (the macOS
# box being logged into / whose console is being locked), not the source host.
_SESSION_EVENT_TYPES = {"ssh_session", "logoff", "workstation_locked", "workstation_unlocked"}


class ESLoggerEmitter(HostMultiplexEmitter):
    """Render canonical events to macOS Endpoint Security (eslogger) NDJSON.

    Per-host FQDN directory routing: each macOS host gets its own
    ``eslogger.ndjson``.  Unlike eCAR (cross-platform EDR), this emitter is
    macOS-only — ``can_handle`` gates on the target host's ``os_category``.
    """

    _log_filename = "eslogger.ndjson"

    _supported_types: set[str] = {
        "process_create",
        "system_process_create",
        "process_terminate",
        "file_create",
        "file_open",
        "file_write",
        "file_rename",
        "file_unlink",
        "ssh_session",
        "logoff",
        "workstation_locked",
        "workstation_unlocked",
        "privilege_elevation",
        "btm_launch_item_add",
    }

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize per-host and global record sequence counters."""
        super().__init__(*args, **kwargs)
        # Format-native ordering counters (not shared StateManager truth): a
        # per-host seq_num and a run-global global_seq_num, incremented once per
        # emitted record in the single writer/consumer thread.  Determinism
        # follows from the single-producer/single-consumer FIFO dispatch path.
        self._seq_by_host: dict[str, int] = {}
        self._global_seq: int = 0
        # (hostname, audit_session_id) of every SSH session for which this
        # emitter rendered an `openssh_login`. An `openssh_logout` is only
        # rendered for a session in this set — see can_handle() for why.
        self._openssh_login_sessions: set[tuple[str, int]] = set()

    # ------------------------------------------------------------------
    # Dispatch / selection
    # ------------------------------------------------------------------

    @staticmethod
    def _target_host(event: SecurityEvent) -> HostContext | None:
        """Return the host whose eslogger log this event belongs to.

        Session/auth events (SSH) are logged on the destination macOS host;
        everything else (process, file, BTM) on the acting source host.
        """
        if event.event_type in _SESSION_EVENT_TYPES:
            return event.dst_host
        return event.src_host

    def can_handle(self, event: SecurityEvent) -> bool:
        """Handle only supported types on a macOS target host."""
        if event.event_type not in self._supported_types:
            return False
        host = self._target_host(event)
        if host is None or getattr(host, "os_category", "") != "macos":
            return False
        # A `logoff` renders as `openssh_logout` ONLY for a session whose
        # `openssh_login` this emitter already rendered (recorded from the
        # `ssh_session` event). This is symmetric with the login side — only
        # `ssh_session` events (never generic interactive `logon`s) render as
        # `openssh_login` — and it is robust: local/console (type 2), network
        # (type 3), cached-interactive (type 11), and any spurious non-SSH
        # `logon_type == 10` session teardown has no recorded login, so it is
        # dropped here instead of surfacing as an orphan `openssh_logout` with
        # no preceding login (Task 11c watch item). Dispatch is single-threaded
        # and delivers a session's login before its logout, so the set is
        # populated by the time the logout is evaluated.
        if event.event_type == "logoff":
            auth = getattr(event, "auth", None)
            if auth is None:
                return False
            return (host.hostname, auth.session_id) in self._openssh_login_sessions
        return True

    def emit(self, event: SecurityEvent) -> None:
        """Dispatch a SecurityEvent to the matching ES renderer."""
        et = event.event_type
        if et in ("process_create", "system_process_create"):
            self._render_process_create(event)
        elif et == "process_terminate":
            self._render_process_terminate(event)
        elif et in _FILE_EVENT_NAMES:
            self._render_file_event(event)
        elif et == "ssh_session":
            self._render_openssh_login(event)
        elif et == "logoff":
            self._render_openssh_logout(event)
        elif et in _LW_SESSION_EVENT_NAMES:
            self._render_lw_session(event)
        elif et == "privilege_elevation":
            self._render_privilege_elevation(event)
        elif et == "btm_launch_item_add":
            self._render_btm_launch_item_add(event)
        else:  # pragma: no cover - guarded by can_handle/_supported_types
            raise NotImplementedError(f"ESLoggerEmitter: no renderer for {et}")

    # ------------------------------------------------------------------
    # Record queueing + finalization
    # ------------------------------------------------------------------

    def _queue_record(self, host: HostContext | None, record: dict[str, Any]) -> None:
        """Attach routing metadata and hand the record to the writer pipeline."""
        self.emit_event({"_host_fqdn": self._host_fqdn(host), "_record": record})

    def _render_event(self, event_data: dict[str, Any]) -> str:
        """Assign sequence numbers and serialize the record to one NDJSON line.

        Called once per record in the single writer/consumer thread, so the
        counter increments are ordering-stable and deterministic.
        """
        record = event_data["_record"]
        host_fqdn = event_data.get("_host_fqdn", "")
        self._seq_by_host[host_fqdn] = self._seq_by_host.get(host_fqdn, 0) + 1
        record["seq_num"] = self._seq_by_host[host_fqdn]
        self._global_seq += 1
        record["global_seq_num"] = self._global_seq
        return json.dumps(record, separators=(",", ":"))

    def _envelope(
        self,
        *,
        host: HostContext | None,
        event_name: str,
        event_time: datetime,
        process_obj: dict[str, Any],
        event_payload: dict[str, Any],
    ) -> dict[str, Any]:
        """Build a complete ES record envelope (seq_num filled at render time)."""
        return {
            "schema_version": _SCHEMA_VERSION,
            "time": self._iso(event_time),
            "mach_time": self._mach_time(host, event_time),
            "seq_num": 0,
            "global_seq_num": 0,
            "event_type": _ES_EVENT_TYPE_CODES.get(event_name, -1),
            "event": {event_name: event_payload},
            "process": process_obj,
        }

    # ------------------------------------------------------------------
    # Per-event renderers
    # ------------------------------------------------------------------

    def _render_process_create(self, event: SecurityEvent) -> None:
        """Render an ES ``fork`` then ``exec`` pair for one process launch.

        Real ``eslogger`` output shows both a fork (subject = parent, child in
        the event) and an exec (subject = new image, argv + cwd in the event)
        for a typical launch, so one canonical ``process_create`` maps to two
        ES lines.
        """
        host = event.src_host
        proc = event.process
        if host is None or proc is None:
            return
        start_time = proc.start_time or event.timestamp

        child_obj = self._build_process_object(
            host,
            pid=proc.pid,
            ppid=proc.parent_pid,
            image=proc.image,
            username=proc.username,
            logon_id=proc.logon_id,
            start_time=start_time,
        )
        parent_obj = self._parent_process_object(host, proc, start_time)

        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="fork",
                event_time=start_time,
                process_obj=parent_obj,
                event_payload={"child": child_obj},
            ),
        )
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="exec",
                event_time=start_time,
                process_obj=child_obj,
                event_payload={
                    "args": self._argv(proc.command_line, proc.image),
                    "cwd": {"path": proc.current_directory or self._default_cwd(proc.username)},
                    "target": {"executable": {"path": proc.image}},
                },
            ),
        )

    def _render_process_terminate(self, event: SecurityEvent) -> None:
        """Render an ES ``exit`` event completing a process lifecycle."""
        host = event.src_host
        proc = event.process
        if host is None or proc is None:
            return
        process_obj = self._build_process_object(
            host,
            pid=proc.pid,
            ppid=proc.parent_pid,
            image=proc.image,
            username=proc.username,
            logon_id=proc.logon_id,
            start_time=proc.start_time or event.timestamp,
        )
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="exit",
                event_time=event.timestamp,
                process_obj=process_obj,
                # Exit status is not modeled canonically; report a clean exit.
                event_payload={"stat": 0},
            ),
        )

    def _render_file_event(self, event: SecurityEvent) -> None:
        """Render an ES file event (create/open/write/rename/unlink)."""
        host = event.src_host
        fc = event.file
        if host is None or fc is None:
            return
        event_name = _FILE_EVENT_NAMES[event.event_type]
        path = fc.path
        pid_hint = fc.pid or (event.process.pid if event.process else 0)
        process_obj = self._process_object_for(host, event, pid_hint)

        if event_name == "create":
            payload: dict[str, Any] = {"destination": {"path": path}}
        elif event_name == "open":
            payload = {"file": {"path": path}}
        elif event_name == "rename":
            # FileContext carries a single path; the destination is not modeled.
            payload = {"source": {"path": path}}
        else:  # write, unlink
            payload = {"target": {"path": path}}

        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name=event_name,
                event_time=event.timestamp,
                process_obj=process_obj,
                event_payload=payload,
            ),
        )

    def _render_openssh_login(self, event: SecurityEvent) -> None:
        """Render an ES ``openssh_login`` from an SSH session on a macOS target."""
        host = event.dst_host
        auth = event.auth
        if host is None or auth is None:
            return
        # Record the session so its matching `openssh_logout` is allowed to
        # render (see can_handle()); an SSH close with no rendered login is an
        # orphan and must be dropped.
        self._openssh_login_sessions.add((host.hostname, auth.session_id))
        process_obj = self._sshd_process_object(host, auth.session_id)
        uid = self._macos_ids(auth.username)["uid"]
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="openssh_login",
                event_time=event.timestamp,
                process_obj=process_obj,
                event_payload={
                    "success": True,
                    "result_type": "AUTHORIZED",
                    "source_address_type": self._addr_type(auth.source_ip),
                    "source_address": auth.source_ip,
                    "username": auth.username,
                    "has_uid": True,
                    "uid": uid,
                },
            ),
        )

    def _render_openssh_logout(self, event: SecurityEvent) -> None:
        """Render an ES ``openssh_logout`` for an SSH session close on macOS."""
        host = event.dst_host
        auth = event.auth
        if host is None or auth is None:
            return
        process_obj = self._sshd_process_object(host, auth.session_id)
        uid = self._macos_ids(auth.username)["uid"]
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="openssh_logout",
                event_time=event.timestamp,
                process_obj=process_obj,
                event_payload={
                    "source_address_type": self._addr_type(auth.source_ip),
                    "source_address": auth.source_ip,
                    "username": auth.username,
                    "uid": uid,
                },
            ),
        )

    def _render_lw_session(self, event: SecurityEvent) -> None:
        """Render an ES ``lw_session_lock``/``lw_session_unlock`` for a macOS console.

        The generic ``workstation_locked``/``workstation_unlocked`` canonical
        event is reported on macOS by ``loginwindow`` (the ES lw_session events),
        carrying the locking user and the graphical (audit) session id.
        """
        host = event.dst_host
        auth = event.auth
        if host is None or auth is None:
            return
        event_name = _LW_SESSION_EVENT_NAMES[event.event_type]
        graphical_session_id = auth.session_id or self._resolve_asid(
            host.hostname, auth.username, auth.logon_id, 0, True
        )
        process_obj = self._loginwindow_process_object(host, graphical_session_id)
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name=event_name,
                event_time=event.timestamp,
                process_obj=process_obj,
                event_payload={
                    "username": auth.username,
                    "graphical_session_id": graphical_session_id,
                },
            ),
        )

    def _render_privilege_elevation(self, event: SecurityEvent) -> None:
        """Render an ES ``sudo``/``su`` for a macOS privilege-elevation event.

        macOS ES (14+) reports a distinct NOTIFY_SUDO / NOTIFY_SU signal for a
        privilege elevation, separate from the exec of the sudo/su binary. The
        acting process image selects between the two: ``/usr/bin/su`` renders as
        ``su``, everything else (``/usr/bin/sudo``) as ``sudo``.
        """
        host = event.src_host
        proc = event.process
        if host is None or proc is None:
            return
        tool = "su" if str(proc.image).rsplit("/", 1)[-1] == "su" else "sudo"
        process_obj = self._build_process_object(
            host,
            pid=proc.pid,
            ppid=proc.parent_pid,
            image=proc.image,
            username=proc.username,
            logon_id=proc.logon_id,
            start_time=proc.start_time or event.timestamp,
        )
        auth = event.auth
        from_username = (auth.subject_username if auth is not None else "") or proc.username
        to_username = (auth.username if auth is not None else "") or "root"
        success = not (auth is not None and auth.result == "failure")
        payload: dict[str, Any] = {
            "success": success,
            "from_uid": self._macos_ids(from_username)["uid"],
            "from_username": from_username,
            "to_uid": self._macos_ids(to_username)["uid"],
            "to_username": to_username,
        }
        if tool == "sudo":
            payload["command"] = proc.command_line or proc.image
        else:
            payload["shell"] = proc.command_line or "/bin/zsh"
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name=tool,
                event_time=event.timestamp,
                process_obj=process_obj,
                event_payload=payload,
            ),
        )

    def _render_btm_launch_item_add(self, event: SecurityEvent) -> None:
        """Render an ES ``btm_launch_item_add`` for a LaunchAgents/Daemons plist."""
        host = event.src_host
        if host is None:
            return
        plist = event.file.path if event.file else ""
        proc = event.process
        process_obj = self._process_object_for(host, event, proc.pid if proc else 0)
        item_type = "agent" if "LaunchAgents" in plist else "daemon"
        username = ""
        if event.auth is not None:
            username = event.auth.username
        elif proc is not None:
            username = proc.username
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="btm_launch_item_add",
                event_time=event.timestamp,
                process_obj=process_obj,
                event_payload={
                    "item": {
                        "item_type": item_type,
                        "legacy": False,
                        "managed": False,
                        "uid": self._macos_ids(username)["uid"] if username else _KAUTH_UID_NONE,
                        "url": {"path": plist},
                    },
                    "executable_path": proc.image if proc is not None else "",
                },
            ),
        )

    # ------------------------------------------------------------------
    # Process-object construction
    # ------------------------------------------------------------------

    def _build_process_object(
        self,
        host: HostContext,
        *,
        pid: int,
        ppid: int,
        image: str,
        username: str,
        logon_id: str = "",
        session_id: int = 0,
        start_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Build the ES ``process`` object: audit token, parents, and signing."""
        hostname = host.hostname
        sm = getattr(self, "_state_manager", None)
        pidversion = sm.get_pidversion(hostname, pid) if sm is not None and pid > 0 else 0

        is_login = self._is_login_session(username, logon_id, session_id)
        asid = self._resolve_asid(hostname, username, logon_id, session_id, is_login)
        audit_token = self._audit_token(pid, pidversion, username, asid, is_login)
        parent_audit_token = self._parent_audit_token(host, ppid, asid)

        signing = get_signing_identity(image)
        tty = self._tty(hostname, username, logon_id, is_login)
        return {
            "pid": pid,
            "ppid": ppid,
            "original_ppid": ppid,
            "session_id": asid,
            "audit_token": audit_token,
            "parent_audit_token": parent_audit_token,
            "executable": {"path": image},
            "tty": {"path": tty} if tty else None,
            "start_time": self._iso(start_time) if start_time is not None else None,
            "is_platform_binary": signing["is_platform_binary"],
            "signing_id": signing["signing_id"],
            "team_id": signing["team_id"],
            "cdhash": signing["cdhash"],
            "codesigning_flags": signing["codesigning_flags"],
        }

    def _parent_process_object(
        self, host: HostContext, proc: Any, child_start: datetime
    ) -> dict[str, Any]:
        """Build the fork-subject (parent) process object for a launch."""
        sm = getattr(self, "_state_manager", None)
        parent_rp = (
            sm.get_process(host.hostname, proc.parent_pid)
            if sm is not None and proc.parent_pid > 0
            else None
        )
        if parent_rp is not None:
            return self._build_process_object(
                host,
                pid=parent_rp.pid,
                ppid=parent_rp.parent_pid,
                image=parent_rp.image,
                username=parent_rp.username,
                logon_id=parent_rp.logon_id,
                start_time=parent_rp.start_time,
            )
        return self._build_process_object(
            host,
            pid=proc.parent_pid,
            ppid=0,
            image=proc.parent_image or "/sbin/launchd",
            username="root",
            start_time=proc.parent_start_time or child_start,
        )

    def _process_object_for(
        self, host: HostContext, event: SecurityEvent, pid_hint: int
    ) -> dict[str, Any]:
        """Resolve the acting process object for file/BTM events.

        Prefers the event's own ProcessContext, then a StateManager lookup by
        pid, then a minimal object — never independently invents a process the
        canonical layer does not own (AGENTS.md rule #1a).
        """
        proc = event.process
        if proc is not None:
            return self._build_process_object(
                host,
                pid=proc.pid,
                ppid=proc.parent_pid,
                image=proc.image,
                username=proc.username,
                logon_id=proc.logon_id,
                start_time=proc.start_time or event.timestamp,
            )
        sm = getattr(self, "_state_manager", None)
        rp = sm.get_process(host.hostname, pid_hint) if sm is not None and pid_hint > 0 else None
        if rp is not None:
            return self._build_process_object(
                host,
                pid=rp.pid,
                ppid=rp.parent_pid,
                image=rp.image,
                username=rp.username,
                logon_id=rp.logon_id,
                start_time=rp.start_time,
            )
        username = event.auth.username if event.auth is not None else "root"
        return self._build_process_object(
            host,
            pid=pid_hint,
            ppid=0,
            image="",
            username=username,
            start_time=event.timestamp,
        )

    def _named_system_process_object(
        self,
        host: HostContext,
        *,
        image_suffix: str,
        session_id: int,
        fallback_image: str,
        fallback_username: str = "root",
    ) -> dict[str, Any]:
        """Build a process object for a seeded system daemon reporting an event.

        Some ES events are reported by a long-lived system process rather than
        the acting user process (``sshd`` for openssh_login/logout,
        ``loginwindow`` for lw_session).  Locate the seeded daemon in
        StateManager by image suffix; fall back to a minimal object if state is
        unavailable.
        """
        sm = getattr(self, "_state_manager", None)
        found_rp = None
        if sm is not None:
            running = getattr(getattr(sm, "state", None), "running_processes", {}) or {}
            candidates = [
                rp
                for (rp_host, _pid), rp in running.items()
                if rp_host == host.hostname and str(rp.image).endswith(image_suffix)
            ]
            if candidates:
                found_rp = min(candidates, key=lambda rp: rp.pid)
        if found_rp is not None:
            return self._build_process_object(
                host,
                pid=found_rp.pid,
                ppid=found_rp.parent_pid,
                image=found_rp.image,
                username=found_rp.username,
                session_id=session_id,
                start_time=found_rp.start_time,
            )
        return self._build_process_object(
            host,
            pid=0,
            ppid=1,
            image=fallback_image,
            username=fallback_username,
            session_id=session_id,
        )

    def _sshd_process_object(self, host: HostContext, session_id: int) -> dict[str, Any]:
        """Build the process object for the target-side sshd handling a login.

        ES openssh_login/logout events are reported by the sshd process on the
        macOS target.
        """
        return self._named_system_process_object(
            host,
            image_suffix="sshd",
            session_id=session_id,
            fallback_image="/usr/sbin/sshd",
        )

    def _loginwindow_process_object(self, host: HostContext, session_id: int) -> dict[str, Any]:
        """Build the process object for loginwindow, which reports lw_session events."""
        return self._named_system_process_object(
            host,
            image_suffix="loginwindow",
            session_id=session_id,
            fallback_image=(
                "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
            ),
        )

    # ------------------------------------------------------------------
    # Audit-token / credential helpers
    # ------------------------------------------------------------------

    def _audit_token(
        self, pid: int, pidversion: int, username: str, asid: int, is_login: bool
    ) -> dict[str, Any]:
        """Build an ES audit token for a process."""
        ids = self._macos_ids(username)
        auid = ids["uid"] if is_login else _KAUTH_UID_NONE
        return {
            "pid": pid,
            "pidversion": pidversion,
            "euid": ids["uid"],
            "ruid": ids["uid"],
            "egid": ids["gid"],
            "rgid": ids["gid"],
            "auid": auid,
            "asid": asid,
        }

    def _parent_audit_token(self, host: HostContext, ppid: int, asid: int) -> dict[str, Any]:
        """Build the parent audit token, resolving the parent's identity if known."""
        sm = getattr(self, "_state_manager", None)
        parent_rp = sm.get_process(host.hostname, ppid) if sm is not None and ppid > 0 else None
        parent_pidversion = (
            sm.get_pidversion(host.hostname, ppid) if sm is not None and ppid > 0 else 0
        )
        parent_username = parent_rp.username if parent_rp is not None else "root"
        is_login = self._is_login_session(
            parent_username, parent_rp.logon_id if parent_rp is not None else "", 0
        )
        return self._audit_token(ppid, parent_pidversion, parent_username, asid, is_login)

    @staticmethod
    def _is_login_session(username: str, logon_id: str, session_id: int) -> bool:
        """Return whether a process belongs to an authenticated login session."""
        if logon_id:
            return True
        if session_id and session_id != _MACOS_SYSTEM_ASID:
            return True
        # A regular (non-service) user's process belongs to a login session even
        # when no explicit session id was threaded through.
        return bool(username) and not username.startswith("_") and username != "root"

    @staticmethod
    def _macos_ids(username: str) -> dict[str, int]:
        """Return a deterministic macOS uid/gid for a username.

        macOS reserves 0 for root, the 200-399 band for system service accounts
        (``_``-prefixed), and 501+ for regular users (gid 20 == ``staff``).  No
        other source owns a macOS uid, so it is derived here via ``_stable_seed``
        (never ``hash()``) so the same user resolves identically across runs.
        """
        if username == "root":
            return {"uid": 0, "gid": 0}
        if username.startswith("_"):
            uid = 200 + (_stable_seed(f"macos_service_uid:{username}") % 200)
            return {"uid": uid, "gid": uid}
        uid = 501 + (_stable_seed(f"macos_uid:{username}") % 100)
        return {"uid": uid, "gid": 20}

    @staticmethod
    def _resolve_asid(
        hostname: str, username: str, logon_id: str, session_id: int, is_login: bool
    ) -> int:
        """Resolve the audit session id (asid) for a process.

        Prefers an explicit upstream-allocated session id (SSH bundle); derives
        a stable per-login asid otherwise; system processes run in the reserved
        system audit session.
        """
        if session_id and session_id > 0:
            return session_id
        if is_login:
            scope = logon_id or username
            return _MACOS_SYSTEM_ASID + 1 + (_stable_seed(f"macos_asid:{hostname}:{scope}") % 90000)
        return _MACOS_SYSTEM_ASID

    @staticmethod
    def _tty(hostname: str, username: str, logon_id: str, is_login: bool) -> str | None:
        """Return a stable pseudo-tty path for login sessions, else None."""
        if not is_login:
            return None
        scope = logon_id or username
        n = _stable_seed(f"macos_tty:{hostname}:{scope}") % 8
        return f"/dev/ttys{n:03d}"

    # ------------------------------------------------------------------
    # Small formatters
    # ------------------------------------------------------------------

    @staticmethod
    def _host_fqdn(host: HostContext | None) -> str:
        """Extract FQDN for per-host routing (falls back to hostname)."""
        if host is None:
            return ""
        return host.fqdn or host.hostname

    @staticmethod
    def _iso(dt: datetime) -> str:
        """Render a datetime as ISO 8601 UTC with microseconds and a Z suffix."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

    def _mach_time(self, host: HostContext | None, event_time: datetime) -> int:
        """Derive mach_time: nanoseconds of monotonic uptime since host boot."""
        boot: datetime | None = None
        sm = getattr(self, "_state_manager", None)
        if sm is not None and host is not None:
            boot = sm.get_boot_time(host.hostname)
        if boot is None:
            boot = _MACH_TIME_FALLBACK_BOOT
        if boot.tzinfo is None:
            boot = boot.replace(tzinfo=UTC)
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=UTC)
        delta_ns = int((event_time - boot).total_seconds() * 1_000_000_000)
        return max(0, delta_ns)

    @staticmethod
    def _addr_type(source_ip: str) -> str:
        """Classify an SSH source address as ipv4/ipv6 (ES source_address_type)."""
        return "ipv6" if source_ip and ":" in source_ip else "ipv4"

    @staticmethod
    def _default_cwd(username: str) -> str:
        """Return a plausible working directory when none is tracked."""
        if username == "root":
            return "/var/root"
        if not username or username.startswith("_"):
            return "/"
        return f"/Users/{username}"

    @staticmethod
    def _argv(command_line: str, image: str) -> list[str]:
        """Split a command line into an argv list (macOS/posix shell semantics)."""
        if not command_line:
            return [image] if image else []
        try:
            argv = shlex.split(command_line, posix=True)
        except ValueError:
            argv = command_line.split()
        return argv or [command_line]
