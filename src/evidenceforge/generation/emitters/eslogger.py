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

``ESLoggerEmitter`` renders the canonical ``CanonicalOccurrence`` model into
``eslogger``-style Endpoint Security (ESF) NDJSON, one ``eslogger.ndjson`` file
per macOS host (per-FQDN directory routing, like eCAR).  It is a pure renderer:
process identity, code-signing identity, audit-token session identity, and file
paths all come from contexts and ``StateManager`` state that upstream layers
already built (AGENTS.md realism rules #1/#1a).  ES-native envelope fields
(``schema_version``, ``version``, ``mach_time``, ``thread``,
``seq_num``/``global_seq_num``, ``action``, ``event_type``) are derived
deterministically here.  Record shapes follow Apple's ``es_message_t`` /
``es_process_t`` / ``es_event_*_t`` structs in <EndpointSecurity/ESMessage.h>.
``es_file_t.stat`` is not rendered: no canonical layer owns inode metadata.

The record is assembled as a Python dict and serialized with ``json.dumps``,
bypassing Jinja2 exactly like ``EcarEmitter._render_event`` — the
``config/formats/eslogger.yaml`` ``output.template`` is a placeholder only.

Deliberately NO network/connection events: ESF has no TCP-connect event, so
macOS network egress is correlated via the host's existing Zeek conn/dns logs
(design doc "No network events, deliberately").
"""

import json
import logging
import re
import shlex
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from evidenceforge.events.base import CanonicalOccurrence
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

# ES event name -> es_event_type_t integer, from Apple's
# <EndpointSecurity/ESTypes.h> (the enum is implicitly numbered; values checked
# against the macOS 15 SDK). ES consumers -- including collectors that switch
# on ``event_type`` rather than the ``event`` key -- depend on these exact
# values, so never guess one: add it from the header.
_ES_EVENT_TYPE_CODES: dict[str, int] = {
    "exec": 9,  # ES_EVENT_TYPE_NOTIFY_EXEC
    "open": 10,  # ES_EVENT_TYPE_NOTIFY_OPEN
    "fork": 11,  # ES_EVENT_TYPE_NOTIFY_FORK
    "close": 12,  # ES_EVENT_TYPE_NOTIFY_CLOSE
    "create": 13,  # ES_EVENT_TYPE_NOTIFY_CREATE
    "exit": 15,  # ES_EVENT_TYPE_NOTIFY_EXIT
    "rename": 25,  # ES_EVENT_TYPE_NOTIFY_RENAME
    "unlink": 32,  # ES_EVENT_TYPE_NOTIFY_UNLINK
    "write": 33,  # ES_EVENT_TYPE_NOTIFY_WRITE
    "lw_session_lock": 116,  # ES_EVENT_TYPE_NOTIFY_LW_SESSION_LOCK
    "lw_session_unlock": 117,  # ES_EVENT_TYPE_NOTIFY_LW_SESSION_UNLOCK
    "openssh_login": 120,  # ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGIN
    "openssh_logout": 121,  # ES_EVENT_TYPE_NOTIFY_OPENSSH_LOGOUT
    "btm_launch_item_add": 124,  # ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD
    "su": 128,  # ES_EVENT_TYPE_NOTIFY_SU
    "sudo": 131,  # ES_EVENT_TYPE_NOTIFY_SUDO
}

# es_action_type_t / es_result_t values for a notify message.
_ES_ACTION_TYPE_NOTIFY = 1
_ES_NOTIFY_ACTION = {"result": {"result_type": 0, "result": {"auth": 0}}}

# es_destination_type_t: NOTIFY_CREATE fires after the object exists, so it
# reports ES_DESTINATION_TYPE_EXISTING_FILE (ESMessage.h, es_event_create_t).
_ES_DESTINATION_TYPE_EXISTING_FILE = 0
_ES_DESTINATION_TYPE_NEW_PATH = 1

# es_address_type_t
_ES_ADDRESS_TYPE_IPV4 = 1
_ES_ADDRESS_TYPE_IPV6 = 2

# es_openssh_login_result_type_t
_ES_OPENSSH_AUTH_SUCCESS = 2
_ES_OPENSSH_AUTH_FAIL_PASSWD = 4

# es_btm_item_type_t
_ES_BTM_ITEM_TYPE_AGENT = 3
_ES_BTM_ITEM_TYPE_DAEMON = 4

# open(2) fflag bits (FREAD/FWRITE) reported by NOTIFY_OPEN.
_FREAD = 0x1
_FWRITE = 0x2

# Apple Silicon mach_absolute_time() ticks at 24 MHz (timebase 125/3), not
# nanoseconds. Synthetic macOS hosts are modeled as Apple Silicon Macs.
_MACH_TICKS_PER_NS = (3, 125)
_CPU_TYPE_ARM64 = 0x0100000C
# arm64e with the pointer-auth ABI capability bit, as Apple platform binaries
# report; third-party arm64 code reports CPU_SUBTYPE_ARM64_ALL (0).
_CPU_SUBTYPE_ARM64E_PTRAUTH = -2147483646

# Reports BTM events: legacy LaunchAgent/LaunchDaemon plists are discovered by
# backgroundtaskmanagementd, which is the ES message subject; the process that
# dropped the plist (when known) is the ``instigator``.
_BTM_DAEMON_IMAGE = (
    "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/"
    "Versions/A/Resources/backgroundtaskmanagementd"
)

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


# Shells that own a controlling terminal when started by login(1) or sshd.
_TTY_SHELLS = {"zsh", "bash", "sh"}

# Order-dependent envelope fields, rewritten after the per-host time sort.
_SEQ_FIELDS_RE = re.compile(r'"seq_num":\d+,"global_seq_num":\d+')
_EVENT_TYPE_RE = re.compile(r'"event_type":(\d+)')
_TIME_RE = re.compile(r'"time":"([^"]+)"')


def _eslogger_sort_key(line: str) -> tuple[str, str]:
    """Order one host's records by message time.

    Ties break on the record with its sequence fields removed, so the key never
    depends on the numbers the publish transform assigns.
    """
    match = _TIME_RE.search(line)
    return (match.group(1) if match else "", _SEQ_FIELDS_RE.sub("", line, count=1))


def _es_client_sequence_numbering() -> Callable[[str], str]:
    """Return a fresh numbering pass for one ES client's time-ordered records.

    A Mac's eslogger client numbers messages in delivery order: ``global_seq_num``
    is contiguous across every event type, and ``seq_num`` is contiguous per
    ``event_type`` (ESMessage.h). Gaps would signal dropped messages.
    """
    per_type: dict[str, int] = {}
    total = 0

    def number(line: str) -> str:
        nonlocal total
        match = _EVENT_TYPE_RE.search(line)
        event_type = match.group(1) if match else ""
        per_type[event_type] = per_type.get(event_type, 0) + 1
        total += 1
        return _SEQ_FIELDS_RE.sub(
            f'"seq_num":{per_type[event_type]},"global_seq_num":{total}', line, count=1
        )

    return number


def _nest_dotted_fields(fields: dict[str, Any]) -> dict[str, Any]:
    """Rebuild a nested ES record from dotted field names (``a.b.c`` -> ``{a: {b: {c}}}``)."""
    record: dict[str, Any] = {}
    for name, value in fields.items():
        if name.startswith("_"):
            continue
        node = record
        *parents, leaf = name.split(".")
        for part in parents:
            child = node.get(part)
            if not isinstance(child, dict):
                child = {}
                node[part] = child
            node = child
        node[leaf] = value
    return record


class ESLoggerEmitter(HostMultiplexEmitter):
    """Render canonical events to macOS Endpoint Security (eslogger) NDJSON.

    Per-host FQDN directory routing: each macOS host gets its own
    ``eslogger.ndjson``.  Unlike eCAR (cross-platform EDR), this emitter is
    macOS-only — ``can_handle`` gates on the target host's ``os_category``.
    """

    _log_filename = "eslogger.ndjson"
    # eslogger writes messages in delivery order, so each host's file is sorted
    # by message time and numbered after the sort (see _es_client_sequence_numbering).
    _sort_flat_file = True
    _sort_key = staticmethod(_eslogger_sort_key)
    _defer_sorted_flush_until_close = True
    _external_sorting = True

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
        """Initialize the rendered-SSH-login registry."""
        super().__init__(*args, **kwargs)
        # (hostname, audit_session_id) -> the connection's sshd process object,
        # for every SSH session whose `openssh_login` this emitter rendered. An
        # `openssh_logout` renders only for a session in this map (see
        # can_handle()) and is reported by the same sshd.
        self._openssh_login_sessions: dict[tuple[str, int], dict[str, Any]] = {}

    def _publish_line_transform_factory(self) -> Callable[[], Callable[[str], str]] | None:
        """Assign ES client sequence numbers in each host file's final time order."""
        return _es_client_sequence_numbering

    # ------------------------------------------------------------------
    # Dispatch / selection
    # ------------------------------------------------------------------

    @staticmethod
    def _target_host(event: CanonicalOccurrence) -> HostContext | None:
        """Return the host whose eslogger log this event belongs to.

        Session/auth events (SSH) are logged on the destination macOS host;
        everything else (process, file, BTM) on the acting source host.
        """
        if event.event_type in _SESSION_EVENT_TYPES:
            return event.dst_host
        return event.src_host

    def can_handle(self, event: CanonicalOccurrence) -> bool:
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

    def emit(self, event: CanonicalOccurrence) -> None:
        """Dispatch a CanonicalOccurrence to the matching ES renderer."""
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
        """Serialize one record to an NDJSON line.

        Sequence numbers are placeholders here; the writer assigns them after
        sorting the host's records by time (_es_client_sequence_numbering).
        """
        if "_record" in event_data:
            # _envelope() already places the sequence fields after `thread`.
            return json.dumps(event_data["_record"], separators=(",", ":"))
        # Raw/native escape hatch: a flat dotted-field record (the parser's view)
        # is nested back into the ES message shape, with the sequence fields
        # adjacent after `thread` as the numbering pass expects.
        nested = _nest_dotted_fields(event_data)
        record: dict[str, Any] = {}
        for key, value in nested.items():
            if key in ("seq_num", "global_seq_num"):
                continue
            record[key] = value
            if key == "thread":
                record.update(seq_num=0, global_seq_num=0)
        if "seq_num" not in record:
            record = {"seq_num": 0, "global_seq_num": 0, **record}
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
        audit_token = process_obj.get("audit_token", {})
        return {
            "schema_version": _SCHEMA_VERSION,
            "version": self._message_version(host),
            "time": self._iso_ns(event_time, f"{event_name}:{audit_token.get('pid', 0)}"),
            "mach_time": self._mach_time(host, event_time),
            "thread": {"thread_id": self._thread_id(host, audit_token)},
            "seq_num": 0,
            "global_seq_num": 0,
            "action_type": _ES_ACTION_TYPE_NOTIFY,
            "action": _ES_NOTIFY_ACTION,
            "event_type": _ES_EVENT_TYPE_CODES[event_name],
            "event": {event_name: event_payload},
            "process": process_obj,
        }

    # ------------------------------------------------------------------
    # Per-event renderers
    # ------------------------------------------------------------------

    def _render_process_create(self, event: CanonicalOccurrence) -> None:
        """Render an ES ``fork`` then ``exec`` pair for one process launch.

        ``fork``: the subject is the parent; ``event.fork.child`` is the new
        PID still running the parent's image (pre-exec pidversion).
        ``exec``: the subject is that same pre-exec image; ``event.exec.target``
        is the new program image with its own signing identity and the
        post-exec pidversion. This matches es_event_fork_t / es_event_exec_t.
        """
        host = event.src_host
        proc = event.process
        if host is None or proc is None:
            return
        start_time = proc.start_time or event.timestamp

        parent_obj = self._parent_process_object(host, proc, start_time)
        parent_image = parent_obj["executable"]["path"]
        target_obj = self._build_process_object(
            host,
            pid=proc.pid,
            ppid=proc.parent_pid,
            image=proc.image,
            username=proc.username,
            logon_id=proc.logon_id,
            start_time=start_time,
        )
        # The forked child keeps the parent's image and signing identity until
        # it execs; XNU bumps pidversion on exec, so it is one generation older.
        pre_exec_obj = self._build_process_object(
            host,
            pid=proc.pid,
            ppid=proc.parent_pid,
            image=parent_image,
            username=proc.username,
            logon_id=proc.logon_id,
            start_time=start_time,
            pidversion_offset=-1,
        )

        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="fork",
                event_time=start_time,
                process_obj=parent_obj,
                event_payload={"child": pre_exec_obj},
            ),
        )
        platform = bool(target_obj["is_platform_binary"])
        # es_process_t.start_time is the fork; the exec message follows it once
        # the child has set up and called execve (tens to hundreds of µs).
        exec_gap_us = (
            40
            + _stable_seed(f"es_exec_gap:{host.hostname}:{proc.pid}:{start_time.isoformat()}") % 260
        )
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="exec",
                event_time=start_time + timedelta(microseconds=exec_gap_us),
                process_obj=pre_exec_obj,
                event_payload={
                    "target": target_obj,
                    "dyld_exec_path": proc.image,
                    "script": None,
                    "cwd": self._es_file(
                        proc.current_directory or self._default_cwd(proc.username)
                    ),
                    "last_fd": 2 + _stable_seed(f"es_last_fd:{host.hostname}:{proc.pid}") % 6,
                    "image_cputype": _CPU_TYPE_ARM64,
                    "image_cpusubtype": _CPU_SUBTYPE_ARM64E_PTRAUTH if platform else 0,
                    "args": self._argv(proc.command_line, proc.image),
                },
            ),
        )

    def _render_process_terminate(self, event: CanonicalOccurrence) -> None:
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

    def _render_file_event(self, event: CanonicalOccurrence) -> None:
        """Render an ES file event (create/open/write/rename/unlink)."""
        host = event.src_host
        fc = event.file
        if host is None or fc is None:
            return
        event_name = _FILE_EVENT_NAMES[event.event_type]
        path = fc.path
        pid_hint = fc.pid or (event.process.pid if event.process else 0)
        process_obj = self._process_object_for(host, event, pid_hint)
        parent_dir, _, filename = path.rpartition("/")

        if event_name == "create":
            payload: dict[str, Any] = {
                "destination_type": _ES_DESTINATION_TYPE_EXISTING_FILE,
                "destination": {"existing_file": self._es_file(path)},
            }
        elif event_name == "open":
            fflag = _FREAD | _FWRITE if fc.action == "write" else _FREAD
            payload = {"fflag": fflag, "file": self._es_file(path)}
        elif event_name == "rename":
            # FileContext carries a single path; the rename destination is not
            # modeled canonically, so report the new name in the same directory.
            payload = {
                "source": self._es_file(path),
                "destination_type": _ES_DESTINATION_TYPE_NEW_PATH,
                "destination": {
                    "new_path": {"dir": self._es_file(parent_dir or "/"), "filename": filename}
                },
            }
        elif event_name == "unlink":
            payload = {
                "target": self._es_file(path),
                "parent_dir": self._es_file(parent_dir or "/"),
            }
        else:  # write
            payload = {"target": self._es_file(path)}

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

    def _render_openssh_login(self, event: CanonicalOccurrence) -> None:
        """Render an ES ``openssh_login`` from an SSH session on a macOS target."""
        host = event.dst_host
        auth = event.auth
        if host is None or auth is None:
            return
        # Record the session so its matching `openssh_logout` is allowed to
        # render (see can_handle()); an SSH close with no rendered login is an
        # orphan and must be dropped.
        process_obj = self._connection_sshd_process_object(host, auth)
        self._openssh_login_sessions[(host.hostname, auth.session_id)] = process_obj
        uid = self._macos_ids(auth.username)["uid"]
        success = auth.result != "failure"
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="openssh_login",
                event_time=event.timestamp,
                process_obj=process_obj,
                event_payload={
                    "success": success,
                    "result_type": (
                        _ES_OPENSSH_AUTH_SUCCESS if success else _ES_OPENSSH_AUTH_FAIL_PASSWD
                    ),
                    "source_address_type": self._addr_type(auth.source_ip),
                    "source_address": auth.source_ip,
                    "username": auth.username,
                    "has_uid": True,
                    "uid": {"uid": uid},
                },
            ),
        )

    def _render_openssh_logout(self, event: CanonicalOccurrence) -> None:
        """Render an ES ``openssh_logout`` for an SSH session close on macOS."""
        host = event.dst_host
        auth = event.auth
        if host is None or auth is None:
            return
        process_obj = self._openssh_login_sessions.get(
            (host.hostname, auth.session_id)
        ) or self._connection_sshd_process_object(host, auth)
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

    def _render_lw_session(self, event: CanonicalOccurrence) -> None:
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

    def _render_privilege_elevation(self, event: CanonicalOccurrence) -> None:
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
        from_uid = self._macos_ids(from_username)["uid"]
        to_uid = self._macos_ids(to_username)["uid"]
        payload: dict[str, Any]
        if tool == "sudo":
            payload = {
                "success": success,
                "reject_info": None,
                "has_from_uid": True,
                "from_uid": {"uid": from_uid},
                "from_username": from_username,
                "has_to_uid": True,
                "to_uid": {"uid": to_uid},
                "to_username": to_username,
                "command": proc.command_line or proc.image,
            }
        else:
            argv = self._argv(proc.command_line, proc.image)
            payload = {
                "success": success,
                "failure_message": None if success else "Sorry",
                "from_uid": from_uid,
                "from_username": from_username,
                "has_to_uid": True,
                "to_uid": {"uid": to_uid},
                "to_username": to_username,
                "shell": "/bin/zsh",
                "argc": len(argv),
                "argv": argv,
                "env_count": 0,
                "env": [],
            }
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

    def _render_btm_launch_item_add(self, event: CanonicalOccurrence) -> None:
        """Render an ES ``btm_launch_item_add`` for a LaunchAgents/Daemons plist.

        backgroundtaskmanagementd discovers the legacy plist and is the message
        subject; the process that dropped the plist, when known, is the
        ``instigator`` (es_event_btm_launch_item_add_t).
        """
        host = event.src_host
        if host is None:
            return
        plist = event.file.path if event.file else ""
        proc = event.process
        instigator = self._process_object_for(host, event, proc.pid) if proc is not None else None
        btmd_obj = self._named_system_process_object(
            host,
            image_suffix="backgroundtaskmanagementd",
            session_id=_MACOS_SYSTEM_ASID,
            fallback_image=_BTM_DAEMON_IMAGE,
        )
        is_agent = "LaunchAgents" in plist
        username = ""
        if event.auth is not None:
            username = event.auth.username
        elif proc is not None:
            username = proc.username
        # LaunchDaemons run as root; LaunchAgents belong to the owning user.
        uid = self._macos_ids(username)["uid"] if is_agent and username else 0
        self._queue_record(
            host,
            self._envelope(
                host=host,
                event_name="btm_launch_item_add",
                event_time=event.timestamp,
                process_obj=btmd_obj,
                event_payload={
                    "instigator": instigator,
                    "app": None,
                    "item": {
                        "item_type": _ES_BTM_ITEM_TYPE_AGENT
                        if is_agent
                        else _ES_BTM_ITEM_TYPE_DAEMON,
                        "legacy": True,
                        "managed": False,
                        "uid": uid,
                        # NSURL file URLs leave RFC 3986 sub-delims (e.g. `@`) unescaped.
                        "item_url": "file://" + quote(plist, safe="/!$&'()*+,;=:@~"),
                        "app_url": None,
                    },
                    "executable_path": (
                        (event.file.launch_program if event.file is not None else "")
                        or (proc.image if proc is not None else None)
                    ),
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
        pidversion_offset: int = 0,
    ) -> dict[str, Any]:
        """Build an ES ``es_process_t``: audit tokens, identity, and signing.

        ``pidversion_offset=-1`` renders the pre-exec image of a process (the
        forked child before it execs), one XNU pidversion generation earlier.
        """
        hostname = host.hostname
        sm = getattr(self, "_state_manager", None)
        pidversion = sm.get_pidversion(hostname, pid) if sm is not None and pid > 0 else 0
        if pidversion:
            pidversion += pidversion_offset

        is_login = self._is_login_session(username, logon_id, session_id)
        asid = self._resolve_asid(hostname, username, logon_id, session_id, is_login)
        audit_token = self._audit_token(pid, pidversion, username, asid, is_login)
        parent_audit_token = self._parent_audit_token(host, ppid, asid)
        # Launchd jobs and apps are responsible for themselves; anything they
        # spawn is attributed to that responsible ancestor (approximated here
        # by the immediate parent).
        responsible_audit_token = audit_token if ppid <= 1 else parent_audit_token

        signing = get_signing_identity(image)
        tty = (
            self._tty(hostname, username, logon_id, is_login)
            if self._has_controlling_terminal(host, image, ppid)
            else None
        )
        return {
            "audit_token": audit_token,
            "ppid": ppid,
            "original_ppid": ppid,
            "group_id": pid if ppid <= 1 else ppid,
            "session_id": asid,
            "codesigning_flags": signing["codesigning_flags"],
            "is_platform_binary": signing["is_platform_binary"],
            "is_es_client": False,
            "cdhash": signing["cdhash"],
            "signing_id": signing["signing_id"],
            "team_id": signing["team_id"],
            "executable": self._es_file(image),
            "tty": self._es_file(tty) if tty else None,
            "start_time": self._iso(start_time) if start_time is not None else None,
            "responsible_audit_token": responsible_audit_token,
            "parent_audit_token": parent_audit_token,
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
        self, host: HostContext, event: CanonicalOccurrence, pid_hint: int
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

    def _connection_sshd_process_object(self, host: HostContext, auth: Any) -> dict[str, Any]:
        """Build the process object for the sshd that served one SSH connection.

        macOS launchd starts ``sshd -i`` per connection, and that process reports
        the connection's openssh_login/logout. The SSH bundle binds it to the
        session as the transport process.
        """
        sm = getattr(self, "_state_manager", None)
        session = sm.get_session(auth.logon_id) if sm is not None and auth.logon_id else None
        transport_pid = getattr(session, "transport_pid", None) if session is not None else None
        rp = (
            sm.get_process(host.hostname, transport_pid)
            if sm is not None and transport_pid
            else None
        )
        if rp is not None and str(rp.image).endswith("sshd"):
            return self._build_process_object(
                host,
                pid=rp.pid,
                ppid=rp.parent_pid,
                image=rp.image,
                username=rp.username,
                session_id=auth.session_id,
                start_time=rp.start_time,
            )
        return self._sshd_process_object(host, auth.session_id)

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

    def _has_controlling_terminal(self, host: HostContext, image: str, ppid: int) -> bool:
        """Return whether a process runs under a terminal session.

        A pty is the controlling terminal of login(1) (started by Terminal) or of
        the shell sshd starts, and of their descendants. launchd jobs and apps --
        and Terminal and sshd themselves -- have none.
        """
        sm = getattr(self, "_state_manager", None)
        current_image, parent_pid = image, ppid
        for _depth in range(10):
            name = current_image.rsplit("/", 1)[-1]
            if name == "login":
                return True
            if name == "sshd" or parent_pid <= 1 or sm is None:
                return False
            parent = sm.get_process(host.hostname, parent_pid)
            if parent is None:
                return False
            parent_name = str(parent.image).rsplit("/", 1)[-1]
            if parent_name == "sshd" and name.lstrip("-") in _TTY_SHELLS:
                return True
            current_image, parent_pid = str(parent.image), parent.parent_pid
        return False

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
        """Render a timeval (process start_time) as ISO 8601 UTC, microseconds."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"

    @staticmethod
    def _iso_ns(dt: datetime, scope: str) -> str:
        """Render the message timespec as ISO 8601 UTC with nanoseconds.

        Canonical timestamps carry microseconds; the sub-microsecond digits
        are derived deterministically so they are not a constant ``000``.
        """
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        dt = dt.astimezone(UTC)
        nanos = _stable_seed(f"es_time_ns:{dt.isoformat()}:{scope}") % 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + f"{nanos:03d}Z"

    def _mach_time(self, host: HostContext | None, event_time: datetime) -> int:
        """Derive mach_time: Apple Silicon mach_absolute_time() ticks since boot."""
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
        numerator, denominator = _MACH_TICKS_PER_NS
        return max(0, delta_ns * numerator // denominator)

    @staticmethod
    def _thread_id(host: HostContext | None, audit_token: dict[str, Any]) -> int:
        """Return a stable 64-bit-style Mach thread id for the acting process."""
        hostname = host.hostname if host is not None else ""
        pid = audit_token.get("pid", 0)
        pidversion = audit_token.get("pidversion", 0)
        return 1_000_000 + _stable_seed(f"es_thread:{hostname}:{pid}:{pidversion}") % 90_000_000

    @staticmethod
    def _message_version(host: HostContext | None) -> int:
        """Return the es_message_t version the host's macOS release emits."""
        os_name = getattr(host, "os", "") or ""
        digits = "".join(ch if ch.isdigit() or ch == "." else " " for ch in os_name).split()
        major = int(digits[0].split(".")[0]) if digits and digits[0].split(".")[0] else 14
        if major >= 15:
            return 8
        if major == 14:
            return 7
        return 6

    @staticmethod
    def _es_file(path: str) -> dict[str, Any]:
        """Render an es_file_t (path + truncation flag; stat is not modeled)."""
        return {"path": path, "path_truncated": False}

    @staticmethod
    def _addr_type(source_ip: str) -> int:
        """Classify an SSH source address as an es_address_type_t value."""
        return _ES_ADDRESS_TYPE_IPV6 if source_ip and ":" in source_ip else _ES_ADDRESS_TYPE_IPV4

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
