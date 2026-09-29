# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Typed storyline file handler."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from evidenceforge.events.base import OccurrenceBuilder
from evidenceforge.events.contexts import AuthContext, FileContext, ProcessContext
from evidenceforge.models.scenario import FileEventSpec

from .context import TypedEventContext

if TYPE_CHECKING:
    from evidenceforge.generation.engine.storyline import StorylineMixin


def handle_file(
    self: StorylineMixin, spec: FileEventSpec, context: TypedEventContext
) -> dict[str, Any] | None:
    """Execute an authored file operation owned by an explicit or recent storyline process.

    ``create`` under LaunchAgents/LaunchDaemons also drives the macOS BTM causal
    rule; the eslogger-only actions render no evidence on non-macOS hosts.
    """
    from evidenceforge.generation.activity.generator import _FILE_ACTION_EVENT_TYPES

    actor = context.actor
    system = context.system
    time = context.time
    malicious_event = context.malicious_event

    explicit_actor = self._storyline_process_ref_for_parent(
        actor=actor,
        system=system,
        parent_ref=spec.process_ref,
    )
    if spec.pid is not None:
        pid = spec.pid
    elif explicit_actor is not None:
        pid = explicit_actor[0]
    else:
        last_pid, _last_image = self._last_storyline_process_for_system(system)
        pid = last_pid if last_pid > 0 else 0
    running_proc = self.state_manager.get_process(system.hostname, pid) if pid > 0 else None

    process_ctx: ProcessContext | None = None
    if running_proc is not None:
        process_ctx = ProcessContext(
            pid=running_proc.pid,
            parent_pid=running_proc.parent_pid,
            image=running_proc.image,
            command_line=running_proc.command_line,
            username=running_proc.username,
            logon_id=running_proc.logon_id,
            start_time=running_proc.start_time,
        )

    self.dispatcher.dispatch_builder(
        OccurrenceBuilder(
            timestamp=time,
            event_type=_FILE_ACTION_EVENT_TYPES[spec.action],
            src_host=self.activity_generator._build_host_context(system),
            auth=AuthContext(username=actor.username),
            process=process_ctx,
            file=FileContext(path=spec.path, action=spec.action, pid=pid),
            storyline_origin=True,
        )
    )
    malicious_event["path"] = spec.path
    malicious_event["action"] = spec.action
    if pid > 0:
        malicious_event["pid"] = pid

    if spec.action == "create":
        self.activity_generator._maybe_expand_file_create(
            file_path=spec.path,
            time=time,
            system=system,
            actor=actor,
            pid=pid if pid > 0 else None,
            process_image=running_proc.image if running_proc is not None else None,
        )
    return malicious_event
