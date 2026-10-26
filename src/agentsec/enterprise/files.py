"""Private no-overwrite durable local artifacts and explicit consistent SQLite backup."""

import os
import sqlite3
import stat
import tempfile
from pathlib import Path

from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.store import Store


def check_private_parent(path: Path) -> None:
    if os.name != "posix":
        raise ValueError
    info = path.parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError


def atomic_private_write(path: Path, data: bytes) -> None:
    if len(data) > 1_048_576:
        raise TeamError("TOO_LARGE")
    temporary: str | None = None
    published = False
    uncertain = False
    try:
        # Reject unsafe parent, existing file and symlink (including dangling).
        check_private_parent(path)
        fd, temporary = tempfile.mkstemp(prefix=".agentsec-", dir=path.parent)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)  # atomic exclusive publication, never replace
        published = True
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except (OSError, ValueError):
        if published and temporary is not None:
            try:
                source = os.stat(temporary, follow_symlinks=False)
                destination = os.stat(path, follow_symlinks=False)
                if (source.st_dev, source.st_ino) == (destination.st_dev, destination.st_ino):
                    os.unlink(path)
                    directory = os.open(path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
                else:
                    uncertain = True
            except FileNotFoundError:
                pass
            except OSError:
                uncertain = True
        raise TeamError("PUBLICATION_UNCERTAIN" if uncertain else "STORE_UNAVAILABLE") from None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def backup_database(source: Path, destination: Path) -> None:
    """Explicit offline backup, preserving original and removing failed output."""
    store = Store(source)
    created = False
    backup: sqlite3.Connection | None = None
    try:
        # Exclusive reservation; never replace operator data.
        check_private_parent(destination)
        with destination.open("xb"):
            created = True
        destination.chmod(0o600)
        backup = sqlite3.connect(destination)
        store.connection.backup(backup)
        if backup.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError
        backup.close()
        backup = None
        with destination.open("rb") as stream:
            os.fsync(stream.fileno())
    except (OSError, sqlite3.Error, ValueError):
        if backup is not None:
            backup.close()
        if created:
            destination.unlink(missing_ok=True)
        raise TeamError("STORE_UNAVAILABLE") from None
    finally:
        store.close()
