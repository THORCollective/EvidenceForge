"""Deterministic ``struct stat`` model for macOS Endpoint Security ``es_file_t``.

Every ``es_file_t`` that ``eslogger`` prints carries the file's ``stat`` as the
kernel saw it when the message was produced.  The shapes here follow a live
``eslogger`` capture from an Apple Silicon Mac:

* **Signed system volume** (``/System``, ``/usr`` except ``/usr/local``,
  ``/bin``, ``/sbin``): root:wheel, ``nlink`` 1, ``SF_RESTRICTED`` (plus
  ``UF_COMPRESSED`` on files, so ``st_blocks`` undercounts ``st_size``), and
  all four timestamps equal to the OS build time with zero nanoseconds.
* **Applications** (``/Applications``): flags 0, birth == mtime (unpacked from
  an archive, whole seconds), later ctime/atime.
* **Data volume** (home folders, ``/private/var``, ``/Library``, Homebrew):
  flags 0, nanosecond timestamps, uncompressed 4 KiB-rounded blocks.
* **devfs** (``/dev/ttys*``): character device, gid ``tty`` (4), negative
  ``st_dev``, ``st_blksize`` 65536, ``st_rdev`` major 16.
* Directories: ``st_size`` = 32 x ``st_nlink`` (APFS), zero blocks.

State is kept per (host, path) so a file keeps its inode and baseline across
events, and a ``create`` starts a fresh, empty file owned by its creator.
Writes are applied later, in true time order, by ``FileWriteTimeline`` (the
generator can emit near-simultaneous events out of order, so mutating state at
emit time would let a later record show a file from before an earlier write).
All values come from ``_stable_seed`` so output is reproducible.
"""

from __future__ import annotations

import math
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from evidenceforge.utils.rng import _stable_seed

# Approximate build time of the macOS 14.5 system volume.
_SYSTEM_BUILD_TIME = datetime(2024, 4, 27, 7, 4, 0, tzinfo=UTC)

_S_IFDIR = 0o040000
_S_IFREG = 0o100000
_S_IFCHR = 0o020000
_SF_RESTRICTED = 0x00080000
_UF_COMPRESSED = 0x00000020
_TTY_GID = 4
_ADMIN_GID = 80
_STAFF_GID = 20
_TTY_MAJOR = 16

_SYSTEM_PREFIXES = ("/System/", "/usr/", "/bin/", "/sbin/")
_EXEC_DIR_MARKERS = ("/bin/", "/sbin/", "/libexec/", "/Contents/MacOS/", "/Support/")

FileKind = str  # "file" | "exec" | "dir" | "tty"


def _is_system_volume(path: str) -> bool:
    if path == "/":
        return True
    return path.startswith(_SYSTEM_PREFIXES) and not path.startswith("/usr/local/")


def _home_owner(path: str) -> str | None:
    """Return the username owning a path under ``/Users/<name>/``, if any."""
    parts = path.split("/")
    if len(parts) >= 3 and parts[1] == "Users" and parts[2] and parts[2] != "Shared":
        return parts[2]
    return None


def _log_uniform(seed: int, low: int, high: int) -> int:
    """Map a seed onto [low, high] on a log scale (file sizes are long-tailed)."""
    frac = (seed % 10_000) / 10_000
    return int(math.exp(math.log(low) + frac * (math.log(high) - math.log(low))))


def _file_size(path: str, kind: FileKind, seed: int) -> int:
    if kind == "exec":
        if "/Contents/MacOS/" in path and path.startswith("/Applications/"):
            return _log_uniform(seed, 2_000_000, 120_000_000)
        if _is_system_volume(path):
            return _log_uniform(seed, 40_000, 2_500_000)
        return _log_uniform(seed, 50_000, 90_000_000)
    name = path.rsplit("/", 1)[-1]
    if name.endswith("-shm"):
        return 32_768
    if name.endswith("-wal"):
        return _log_uniform(seed, 4_096, 4_000_000)
    if name.endswith(".plist"):
        return _log_uniform(seed, 300, 20_000)
    if name.endswith(".keychain-db"):
        return _log_uniform(seed, 40_000, 400_000)
    if name.endswith(".keychain"):
        return _log_uniform(seed, 100_000, 400_000)
    if name.endswith((".sqlite3", ".sqlite", ".db")):
        return _log_uniform(seed, 100_000, 25_000_000)
    return _log_uniform(seed, 1_000, 200_000)


@dataclass(slots=True)
class _FileState:
    ino: int
    mode: int
    nlink: int
    uid: int
    gid: int
    size: int
    flags: int
    birth: datetime
    mtime: datetime
    ctime: datetime
    atime: datetime
    rdev: int = 0
    compression: float = 1.0
    whole_seconds: bool = False
    # Archive-extracted files (/Applications) keep a whole-second birth time,
    # and mtime stays whole while it still equals birth.
    whole_birth: bool = False


class MacFileStatModel:
    """Stateful, deterministic ``struct stat`` source for ES ``es_file_t``."""

    def __init__(self, uid_for: Callable[[str, str], int]) -> None:
        # uid_for(username, hostname) -> the user's uid on that Mac.
        self._uid_for = uid_for
        self._files: dict[tuple[str, str], _FileState] = {}

    # -- public API -----------------------------------------------------

    def stat(
        self,
        hostname: str,
        path: str,
        at: datetime,
        *,
        kind: FileKind = "file",
        owner_uid: int | None = None,
    ) -> dict[str, Any]:
        """Return the ``stat`` object for ``path`` on ``hostname`` at ``at``."""
        state = self._state(hostname, path, at, kind, owner_uid)
        return self._render(hostname, path, state, kind)

    def record_create(self, hostname: str, path: str, at: datetime, owner_uid: int) -> None:
        """A process created ``path`` at ``at``: fresh inode, empty, owned by it."""
        seed = _stable_seed(f"es_stat_create:{hostname}:{path}:{at.isoformat()}")
        at = self._utc(at)
        gid = _STAFF_GID if owner_uid >= 500 else owner_uid
        self._files[(hostname, path)] = _FileState(
            ino=self._data_ino(seed),
            mode=_S_IFREG | 0o644,
            nlink=1,
            uid=owner_uid,
            gid=gid,
            size=0,
            flags=0,
            birth=at,
            mtime=at,
            ctime=at,
            atime=at,
        )

    # -- internals ------------------------------------------------------

    def _state(
        self,
        hostname: str,
        path: str,
        at: datetime,
        kind: FileKind,
        owner_uid: int | None,
    ) -> _FileState:
        key = (hostname, path)
        state = self._files.get(key)
        if state is None:
            state = self._initial_state(hostname, path, self._utc(at), kind, owner_uid)
            self._files[key] = state
        return state

    def _initial_state(
        self,
        hostname: str,
        path: str,
        at: datetime,
        kind: FileKind,
        owner_uid: int | None,
    ) -> _FileState:
        seed = _stable_seed(f"es_stat:{hostname}:{path}")
        if kind == "tty":
            return self._tty_state(hostname, path, at, seed, owner_uid)

        is_dir = kind == "dir"
        size = 0
        nlink = 1
        if is_dir:
            nlink = 22 if path == "/" else 3 + seed % 38
            size = 32 * nlink

        if _is_system_volume(path):
            built = min(_SYSTEM_BUILD_TIME, at - timedelta(days=30))
            stamp = built + timedelta(seconds=seed % 600)
            perm = 0o755 if is_dir or kind == "exec" or self._looks_executable(path) else 0o644
            return _FileState(
                ino=1_152_921_500_311_800_000 + seed % 1_000_000,
                mode=(_S_IFDIR if is_dir else _S_IFREG) | perm,
                nlink=nlink,
                uid=0,
                gid=0,
                size=size if is_dir else _file_size(path, kind, seed),
                flags=_SF_RESTRICTED if is_dir else _SF_RESTRICTED | _UF_COMPRESSED,
                birth=stamp,
                mtime=stamp,
                ctime=stamp,
                atime=stamp,
                compression=0.12 + (seed % 49) / 100,
                whole_seconds=True,
            )

        uid, gid = self._owner(hostname, path, seed, owner_uid)
        perm = self._permissions(path, kind, is_dir)
        if path.startswith("/Applications/"):
            # Offset the time of day too, so the install stamp never shares the
            # clock time of the event that first touches the file.
            installed = (
                at - timedelta(days=5 + seed % 300, seconds=(seed >> 12) % 86_400)
            ).replace(microsecond=0)
            later = self._with_ns(installed + timedelta(minutes=1 + seed % 90), seed)
            return _FileState(
                ino=self._data_ino(seed),
                mode=(_S_IFDIR if is_dir else _S_IFREG) | perm,
                nlink=nlink,
                uid=uid,
                gid=gid,
                size=size if is_dir else _file_size(path, kind, seed),
                flags=0,
                birth=installed,
                mtime=installed,
                ctime=later,
                atime=later,
                whole_birth=True,
            )

        birth = self._with_ns(at - timedelta(days=20 + seed % 400, seconds=seed % 86_400), seed)
        modified = self._with_ns(
            at - timedelta(days=seed % 12, seconds=1 + (seed >> 8) % 86_400), seed >> 4
        )
        modified = max(modified, birth)
        return _FileState(
            ino=self._data_ino(seed),
            mode=(_S_IFDIR if is_dir else _S_IFREG) | perm,
            nlink=nlink,
            uid=uid,
            gid=gid,
            size=size if is_dir else _file_size(path, kind, seed),
            flags=0,
            birth=birth,
            mtime=modified,
            ctime=modified,
            atime=modified,
        )

    def _tty_state(
        self, hostname: str, path: str, at: datetime, seed: int, owner_uid: int | None
    ) -> _FileState:
        minor = int(path[-3:]) if path[-3:].isdigit() else seed % 8
        opened = at - timedelta(minutes=5 + seed % 600)
        return _FileState(
            ino=800 + minor * 3 + seed % 3,
            mode=_S_IFCHR | 0o620,
            nlink=1,
            uid=owner_uid if owner_uid is not None else 0,
            gid=_TTY_GID,
            size=0,
            flags=0,
            birth=opened,
            mtime=opened,
            ctime=opened,
            atime=opened,
            rdev=(_TTY_MAJOR << 24) | minor,
        )

    def _owner(self, hostname: str, path: str, seed: int, owner_uid: int | None) -> tuple[int, int]:
        home_user = _home_owner(path)
        if home_user:
            return self._uid_for(home_user, hostname), _STAFF_GID
        if path.startswith("/private/var/protected/trustd/"):
            uid = self._uid_for("_trustd", hostname)
            return uid, uid
        if path.startswith("/opt/homebrew/"):
            return 501, _ADMIN_GID
        if path.startswith("/Applications/"):
            return (501, _STAFF_GID) if seed % 2 else (0, 0)
        if path.startswith(("/Users/Shared/", "/private/tmp/", "/tmp/")) and owner_uid is not None:
            return owner_uid, _STAFF_GID if owner_uid >= 500 else owner_uid
        return 0, 0

    @staticmethod
    def _permissions(path: str, kind: FileKind, is_dir: bool) -> int:
        if is_dir:
            home_user = _home_owner(path)
            if home_user and path.rstrip("/") == f"/Users/{home_user}":
                return 0o750
            if home_user and "/Library" in path:
                return 0o700
            return 0o755
        if kind == "exec" or MacFileStatModel._looks_executable(path):
            return 0o755
        if _home_owner(path) and "/Library/Preferences/" in path:
            return 0o600
        return 0o644

    @staticmethod
    def _looks_executable(path: str) -> bool:
        name = path.rsplit("/", 1)[-1]
        return "." not in name and any(marker in path for marker in _EXEC_DIR_MARKERS)

    @staticmethod
    def _data_ino(seed: int) -> int:
        return 300_000 + seed % 9_000_000

    @staticmethod
    def _utc(dt: datetime) -> datetime:
        return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)

    @classmethod
    def _with_ns(cls, dt: datetime, seed: int) -> datetime:
        # datetime holds microseconds; the extra nanosecond digits are added when
        # rendering (see _timespec), keyed on the same value so they are stable.
        return cls._utc(dt).replace(microsecond=seed % 1_000_000)

    @staticmethod
    def _timespec(dt: datetime, whole_seconds: bool) -> str:
        if whole_seconds:
            return dt.strftime("%Y-%m-%dT%H:%M:%S") + ".000000000Z"
        nanos = _stable_seed(f"es_stat_ns:{dt.isoformat()}") % 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + f"{nanos:03d}Z"

    @staticmethod
    def _dev(hostname: str, kind: FileKind) -> int:
        if kind == "tty":
            return -(100_000_000 + _stable_seed(f"es_devfs:{hostname}") % 50_000_000)
        return 16_777_220 + _stable_seed(f"es_apfs_dev:{hostname}") % 16

    def _render(
        self, hostname: str, path: str, state: _FileState, kind: FileKind
    ) -> dict[str, Any]:
        if kind == "dir" or state.mode & _S_IFDIR == _S_IFDIR or state.size == 0:
            blocks = 0
        else:
            stored = max(1, math.ceil(state.size * state.compression))
            blocks = math.ceil(stored / 4096) * 8
        whole = state.whole_seconds
        whole_birth = whole or state.whole_birth
        whole_mtime = whole or (state.whole_birth and state.mtime == state.birth)
        return {
            "st_dev": self._dev(hostname, kind),
            "st_mode": state.mode,
            "st_nlink": state.nlink,
            "st_ino": state.ino,
            "st_uid": state.uid,
            "st_gid": state.gid,
            "st_rdev": state.rdev,
            "st_atimespec": self._timespec(state.atime, whole),
            "st_mtimespec": self._timespec(state.mtime, whole_mtime),
            "st_ctimespec": self._timespec(state.ctime, whole),
            "st_birthtimespec": self._timespec(state.birth, whole_birth),
            "st_size": state.size,
            "st_blocks": blocks,
            "st_blksize": 65_536 if kind == "tty" else 4_096,
            "st_flags": state.flags,
            "st_gen": 0,
        }


# ---------------------------------------------------------------------------
# Time-ordered write application (runs over each host's sorted records)
# ---------------------------------------------------------------------------

_FILE_EVENT_PATHS: dict[int, tuple[str, ...]] = {
    10: ("open", "file"),
    12: ("close", "target"),
    13: ("create", "destination", "existing_file"),
    25: ("rename", "source"),
    32: ("unlink", "target"),
    33: ("write", "target"),
}
FILE_EVENT_TYPES = frozenset(_FILE_EVENT_PATHS)
_ES_EVENT_WRITE = 33
_ES_EVENT_CREATE = 13


def _ns_before(timespec: str, path: str) -> str:
    """Return a timespec a few hundred nanoseconds before ``timespec``.

    A write's mtime is stamped by the kernel just before ES delivers the
    message, so it never runs ahead of the message's own ``time``.
    """
    whole = datetime.strptime(timespec[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    total = int(whole.timestamp()) * 1_000_000_000 + int(timespec[20:29])
    total -= 50 + _stable_seed(f"es_write_mtime:{path}:{timespec}") % 900
    seconds, nanos = divmod(total, 1_000_000_000)
    stamp = datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S")
    return f"{stamp}.{nanos:09d}Z"


class FileWriteTimeline:
    """Apply writes to file ``stat`` in time order for one host's ES stream.

    Fed every record of one host in final time order.  For each path it keeps
    the current size/mtime/ctime: the first record seen supplies the baseline
    (or a ``create`` resets it), each ``write`` grows the file and stamps
    mtime/ctime, and every record carries the state current at its time.
    """

    def __init__(self) -> None:
        self._current: dict[str, dict[str, Any]] = {}

    def apply(self, record: dict[str, Any]) -> bool:
        """Update ``record``'s file stat in place; return True if it changed."""
        keys = _FILE_EVENT_PATHS.get(record.get("event_type", -1))
        if keys is None:
            return False
        node: Any = record.get("event")
        for key in keys:
            node = node.get(key) if isinstance(node, dict) else None
        stat = node.get("stat") if isinstance(node, dict) else None
        if not isinstance(stat, dict):
            return False
        path = node.get("path", "")
        event_type = record["event_type"]
        current = self._current.get(path)
        if event_type == _ES_EVENT_CREATE:
            # The inode is born, and stamped, just before the message's time.
            stamp = _ns_before(record.get("time", ""), path)
            stat["st_birthtimespec"] = stat["st_atimespec"] = stamp
            stat["st_mtimespec"] = stat["st_ctimespec"] = stamp
        if current is None or event_type == _ES_EVENT_CREATE:
            current = {
                k: stat[k] for k in ("st_size", "st_mtimespec", "st_ctimespec", "st_birthtimespec")
            }
            self._current[path] = current
        if event_type == _ES_EVENT_WRITE:
            time = record.get("time", "")
            current["st_size"] += 256 + _stable_seed(f"es_write_size:{path}:{time}") % 8_192
            stamp = _ns_before(time, path)
            if stamp > current["st_mtimespec"]:
                current["st_mtimespec"] = stamp
                current["st_ctimespec"] = stamp
        before = (
            None if event_type == _ES_EVENT_CREATE else stat["st_size"],
            stat["st_mtimespec"],
            stat["st_ctimespec"],
        )
        stat.update(current)
        if not stat["st_flags"] & _UF_COMPRESSED and not stat["st_mode"] & _S_IFDIR == _S_IFDIR:
            stat["st_blocks"] = math.ceil(stat["st_size"] / 4096) * 8
        return before != (stat["st_size"], stat["st_mtimespec"], stat["st_ctimespec"])
