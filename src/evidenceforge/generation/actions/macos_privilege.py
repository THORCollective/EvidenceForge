# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""macOS sudo/su privilege-elevation occurrences (Endpoint Security NOTIFY_SUDO/SU)."""

from __future__ import annotations

from datetime import datetime, timedelta

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, HostContext, ProcessContext
from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.utils.rng import _stable_seed

_ELEVATION_TOOLS = frozenset({"sudo", "su"})


def dispatch_privilege_elevation(
    dispatcher: EventDispatcher,
    *,
    host: HostContext,
    time: datetime,
    process: ProcessContext,
    from_username: str,
    to_username: str = "root",
    success: bool = True,
) -> None:
    """Dispatch one canonical ``privilege_elevation`` occurrence.

    The eslogger emitter renders it as an ES ``sudo`` or ``su`` event depending
    on the acting process image; no other emitter consumes it.
    """
    dispatcher.dispatch_builder(
        OccurrenceBuilder(
            timestamp=time,
            event_type="privilege_elevation",
            src_host=host,
            process=process,
            auth=AuthContext(
                username=to_username,
                subject_username=from_username,
                elevated=True,
                result="success" if success else "failure",
            ),
        )
    )


def maybe_dispatch_process_privilege_elevation(
    dispatcher: EventDispatcher,
    *,
    host: HostContext | None,
    time: datetime,
    process: ProcessContext | None,
) -> None:
    """Emit the ES sudo/su signal that accompanies a macOS sudo/su exec.

    macOS ES (14+) reports a distinct NOTIFY_SUDO / NOTIFY_SU event for each
    elevation, separate from the exec of the ``sudo``/``su`` binary. No-op on
    non-macOS hosts and for any other process image.
    """
    if process is None or host is None or host.os_category != "macos":
        return
    if str(process.image).rsplit("/", 1)[-1] not in _ELEVATION_TOOLS:
        return
    seed = _stable_seed(
        f"macos_privilege_elevation:{host.hostname}:{process.pid}:{time.isoformat()}"
    )
    elevation_time = time + timedelta(
        milliseconds=8 + (seed % 40),
        microseconds=101 + (seed % 397),
    )
    dispatch_privilege_elevation(
        dispatcher,
        host=host,
        time=elevation_time,
        process=process,
        from_username=process.username,
    )
