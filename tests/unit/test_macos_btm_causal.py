# Copyright (c) 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: MIT

"""Integration tests for the macOS BTM launch-item causal hook.

Covers the file_create -> btm_launch_item_add expansion added for macOS
Endpoint Security support: the hot-path pre-check on the file-create dispatch
sites (`ActivityGenerator._maybe_expand_file_create`) and the consequent event
builder (`ActivityGenerator._emit_btm_launch_item_add`).
"""

from datetime import UTC, datetime, timedelta

from evidenceforge.events.dispatcher import EventDispatcher
from evidenceforge.generation.activity import ActivityGenerator
from evidenceforge.generation.state_manager import StateManager
from evidenceforge.models.scenario import System, User

START = datetime(2024, 6, 1, 12, 0, 0, tzinfo=UTC)
LAUNCH_AGENT_PLIST = "/Users/jappleseed/Library/LaunchAgents/com.evil.agent.plist"


def _harness(os_name: str = "macOS 14"):
    """Build a generator wired to a capturing dispatcher on one host."""
    state = StateManager()
    state.set_current_time(START - timedelta(minutes=5))
    events: list = []
    dispatcher = EventDispatcher(state_manager=state, emitters={})
    original_prepare = dispatcher.prepare_builder

    def capture(event, *args, **kwargs):
        events.append(event)
        return original_prepare(event, *args, **kwargs)

    dispatcher.prepare_builder = capture
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
    logon_id = state.create_session(
        username=user.username,
        system=system.hostname,
        logon_type=2,
        source_ip="-",
        session_kind="interactive",
        start_time=START - timedelta(minutes=5),
    )
    state.set_current_time(START)
    return generator, state, events, user, system, logon_id


def test_macos_process_image_is_not_self_written() -> None:
    """A macOS process cannot write its own executable, so no image create is guaranteed.

    The executable was dropped earlier by a downloader or installer outside the
    process; LaunchAgents drops are authored as storyline ``file`` events.
    """
    generator, state, events, user, system, logon_id = _harness()
    state.set_current_time(START - timedelta(seconds=30))
    launchd_pid = state.create_process(
        system.hostname,
        0,
        "/sbin/launchd",
        "/sbin/launchd",
        "root",
        "System",
        os_category="macos",
    )
    shell_pid = state.create_process(
        system.hostname,
        launchd_pid,
        "/bin/zsh",
        "-zsh",
        user.username,
        "Medium",
        logon_id=logon_id,
        os_category="macos",
    )
    state.set_current_time(START)

    generator.generate_process(
        user=user,
        system=system,
        time=START,
        logon_id=logon_id,
        process_name="/Users/jappleseed/Downloads/payload",
        command_line="/Users/jappleseed/Downloads/payload",
        parent_pid=shell_pid,
        ensure_file_event=True,
        from_storyline=True,
    )

    image_creates = [
        e
        for e in events
        if e.event_type == "file_create" and e.file.path == "/Users/jappleseed/Downloads/payload"
    ]
    assert image_creates == []


def test_btm_carries_responsible_process_from_state() -> None:
    """The BTM event reuses the responsible process's canonical context."""
    generator, state, events, user, system, _logon_id = _harness()
    pid = state.create_process(
        system.hostname,
        0,
        "/bin/cp",
        f"cp /tmp/payload {LAUNCH_AGENT_PLIST}",
        user.username,
        "Medium",
    )

    generator._maybe_expand_file_create(
        file_path=LAUNCH_AGENT_PLIST,
        time=START,
        system=system,
        actor=user,
        pid=pid,
        process_image="/bin/cp",
    )

    btm_events = [e for e in events if e.event_type == "btm_launch_item_add"]
    assert len(btm_events) == 1
    btm = btm_events[0]
    assert btm.process is not None
    assert btm.process.pid == pid
    assert btm.process.image == "/bin/cp"
    assert btm.auth is not None and btm.auth.username == user.username


def test_hook_is_noop_for_ordinary_file_create_path() -> None:
    """The hot-path pre-check must skip _expand_and_emit for non-plist paths.

    file_create is a very hot dispatch path, so a non-LaunchAgents/LaunchDaemons
    path must not even build an ExpansionContext.
    """
    generator, _state, events, user, system, _logon_id = _harness()
    calls: list[str] = []
    original_expand = generator._expand_and_emit

    def spy(event_type, timestamp, **kwargs):
        calls.append(event_type)
        return original_expand(event_type, timestamp, **kwargs)

    generator._expand_and_emit = spy  # type: ignore[method-assign]

    generator._maybe_expand_file_create(
        file_path="/Users/jappleseed/Documents/notes.txt",
        time=START,
        system=system,
        actor=user,
    )

    assert calls == []  # pre-check short-circuited; no engine work at all
    assert not [e for e in events if e.event_type == "btm_launch_item_add"]

    # Sanity: a matching path does reach the engine.
    generator._maybe_expand_file_create(
        file_path=LAUNCH_AGENT_PLIST,
        time=START,
        system=system,
        actor=user,
    )
    assert calls == ["file_create"]
    assert [e for e in events if e.event_type == "btm_launch_item_add"]


def test_hook_does_not_fire_on_non_macos_host() -> None:
    """A LaunchAgents-looking path on a non-macOS host must not fire BTM."""
    generator, _state, events, user, system, _logon_id = _harness(os_name="Windows 11")

    # The pre-check passes on substring, but the rule's macOS gate rejects it.
    generator._maybe_expand_file_create(
        file_path=r"C:\ProgramData\LaunchAgents\com.evil.plist",
        time=START,
        system=system,
        actor=user,
    )

    assert not [e for e in events if e.event_type == "btm_launch_item_add"]
