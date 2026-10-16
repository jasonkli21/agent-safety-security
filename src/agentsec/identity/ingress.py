"""Bounded out-of-band credential input. Never inherit credentials from MCP or env."""

import os
import stat
from pathlib import Path

from agentsec.identity.ports import IdentityError


def read_credential(path: Path) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
                raise ValueError
            raw = stream.read(16385)
            if len(raw) > 16384 or not raw:
                raise ValueError
            return raw.decode("ascii").strip()
    except Exception:
        raise IdentityError("IDENTITY_CREDENTIAL_FILE_INVALID") from None
