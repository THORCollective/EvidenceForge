# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Tests for the `type: file` storyline event (schema + dispatch).

Covers Task 11b: the `FileEventSpec` schema addition and its dispatch branch
in `StorylineMixin._execute_typed_event`, including the reused Task 7 BTM
causal-expansion hook for LaunchAgents/LaunchDaemons `file_create` paths.
"""

from datetime import UTC, datetime

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.engine.storyline import StorylineMixin
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import FileEventSpec, StorylineEvent, System, User

START = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
LAUNCH_AGENT_PLIST = "/Users/jappleseed/Library/LaunchAgents/com.evil.agent.plist"


def _harness(os_name: str = "macOS 14"):
    """Build a StorylineMixin engine wired to a capturing dispatcher on one host."""
    state = StateManager()
    state.set_current_time(START)
    events: list = []
    dispatcher = EventDispatcher(state_manager=state, emitters={})
    original_dispatch = dispatcher.dispatch

    def capture(event):
        events.append(event)
        original_dispatch(event)

    dispatcher.dispatch = capture
    generator = ActivityGenerator(state, {}, dispatcher=dispatcher)
    user = User(username="jappleseed", full_name="J Appleseed", email="j@example.local")
    system = System(
        hostname="MAC-01",
        ip="10.10.9.20",
        os=os_name,
        type="workstation",
        assigned_user=user.username,
    )
    generator._ip_to_system = {system.ip: system}

    engine = object.__new__(StorylineMixin)
    engine.state_manager = state
    engine.activity_generator = generator
    engine.dispatcher = dispatcher

    return engine, state, generator, events, user, system


class TestFileEventSpecSchema:
    def test_type_file_with_open_action_validates(self) -> None:
        """A `type: file` storyline event with action=open validates via the union."""
        event = StorylineEvent(
            id="ev1",
            time="+0s",
            actor="jappleseed",
            system="MAC-01",
            activity="Attacker opens keychain file",
            events=[
                {
                    "type": "file",
                    "path": "/Users/jappleseed/Library/Keychains/login.keychain-db",
                    "action": "open",
                }
            ],
        )
        assert len(event.events) == 1
        spec = event.events[0]
        assert isinstance(spec, FileEventSpec)
        assert spec.type == "file"
        assert spec.action == "open"
        assert spec.pid is None

    def test_default_action_is_create(self) -> None:
        """Omitting `action` defaults to "create" per the schema."""
        spec = FileEventSpec(path="/tmp/whatever")
        assert spec.action == "create"

    def test_explicit_pid_override_accepted(self) -> None:
        """An explicit `pid` override is accepted and preserved."""
        spec = FileEventSpec(path="/tmp/whatever", action="write", pid=4242)
        assert spec.pid == 4242

    def test_rejects_unknown_field(self) -> None:
        """`_EventSpecBase`'s extra="forbid" should reject unknown fields."""
        import pytest
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            FileEventSpec(path="/tmp/whatever", bogus_field="nope")


class TestFileEventDispatch:
    def test_file_open_event_dispatches_file_context_event(self) -> None:
        """A bare `file` open event with an explicit pid dispatches a FileContext event."""
        engine, state, generator, events, user, system = _harness()
        pid = state.create_process(
            system.hostname,
            0,
            "/usr/bin/security",
            "security dump-keychain",
            user.username,
            "Medium",
        )

        spec = FileEventSpec(
            path="/Users/jappleseed/Library/Keychains/login.keychain-db",
            action="open",
            pid=pid,
        )
        engine._execute_typed_event(
            spec=spec,
            actor=user,
            system=system,
            time=START,
            activity="Keychain open",
            explicit_types={"file"},
        )

        file_opens = [e for e in events if e.event_type == "file_open"]
        assert len(file_opens) == 1
        event = file_opens[0]
        assert event.file is not None
        assert event.file.path == "/Users/jappleseed/Library/Keychains/login.keychain-db"
        assert event.file.action == "open"
        assert event.file.pid == pid
        assert event.process is not None
        assert event.process.pid == pid
        assert event.process.image == "/usr/bin/security"
        assert event.auth is not None
        assert event.auth.username == user.username
        assert event.src_host is not None
        assert event.storyline_origin is True

    def test_file_event_resolves_pid_from_last_storyline_process_when_not_given(self) -> None:
        """Without an explicit pid, the acting pid resolves from the last storyline process."""
        engine, state, generator, events, user, system = _harness()
        pid = state.create_process(
            system.hostname,
            0,
            "/bin/launchctl",
            "launchctl load agent.plist",
            user.username,
            "Medium",
        )
        engine._record_last_storyline_process(system, pid, "/bin/launchctl")

        spec = FileEventSpec(path="/tmp/notes.txt", action="read")
        engine._execute_typed_event(
            spec=spec,
            actor=user,
            system=system,
            time=START,
            activity="Read a file",
            explicit_types={"file"},
        )

        file_reads = [e for e in events if e.event_type == "file_read"]
        assert len(file_reads) == 1
        assert file_reads[0].process is not None
        assert file_reads[0].process.pid == pid

    def test_file_event_with_no_resolvable_pid_still_dispatches(self) -> None:
        """With no explicit pid and no prior storyline process, the event still dispatches."""
        engine, _state, _generator, events, user, system = _harness()

        spec = FileEventSpec(path="/tmp/notes.txt", action="read")
        engine._execute_typed_event(
            spec=spec,
            actor=user,
            system=system,
            time=START,
            activity="Read a file",
            explicit_types={"file"},
        )

        file_reads = [e for e in events if e.event_type == "file_read"]
        assert len(file_reads) == 1
        assert file_reads[0].process is None
        assert file_reads[0].file.pid == 0

    def test_file_create_under_launchagents_fires_btm_causal_hook(self) -> None:
        """action=create under LaunchAgents threads through Task 7's BTM causal hook."""
        engine, state, generator, events, user, system = _harness()
        pid = state.create_process(
            system.hostname,
            0,
            "/bin/cp",
            f"cp /tmp/payload {LAUNCH_AGENT_PLIST}",
            user.username,
            "Medium",
        )

        spec = FileEventSpec(path=LAUNCH_AGENT_PLIST, action="create", pid=pid)
        engine._execute_typed_event(
            spec=spec,
            actor=user,
            system=system,
            time=START,
            activity="Drop a LaunchAgent",
            explicit_types={"file"},
        )

        file_creates = [e for e in events if e.event_type == "file_create"]
        btm_events = [e for e in events if e.event_type == "btm_launch_item_add"]
        assert len(file_creates) == 1
        assert file_creates[0].file.path == LAUNCH_AGENT_PLIST
        assert len(btm_events) == 1
        assert btm_events[0].file is not None
        assert btm_events[0].file.path == LAUNCH_AGENT_PLIST

    def test_file_open_does_not_fire_btm_hook(self) -> None:
        """Only action=create should route through the BTM causal hook."""
        engine, state, generator, events, user, system = _harness()
        pid = state.create_process(
            system.hostname, 0, "/usr/bin/security", "security", user.username, "Medium"
        )

        spec = FileEventSpec(path=LAUNCH_AGENT_PLIST, action="open", pid=pid)
        engine._execute_typed_event(
            spec=spec,
            actor=user,
            system=system,
            time=START,
            activity="Open a LaunchAgent plist",
            explicit_types={"file"},
        )

        assert not [e for e in events if e.event_type == "btm_launch_item_add"]
