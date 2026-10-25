"""Single-instance transactional SQLite with tenant-qualified storage operations."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from threading import RLock
from typing import Literal

from agentsec.control_plane.errors import TeamError
from agentsec.control_plane.models import Binding

Kind = Literal[
    "member", "agent", "reporter", "revision", "publication", "receipt", "retry", "tombstone"
]
DDL = """
CREATE TABLE orgs (org TEXT PRIMARY KEY);
CREATE TABLE bindings (
 identity TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL, body TEXT NOT NULL,
 UNIQUE(issuer,subject));
CREATE TABLE records (
 org TEXT NOT NULL REFERENCES orgs(org), kind TEXT NOT NULL, id TEXT NOT NULL,
 version INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(org,kind,id));
CREATE UNIQUE INDEX reporter_single_org ON records(id) WHERE kind='reporter';
CREATE TABLE sources (
 org TEXT NOT NULL REFERENCES orgs(org), id TEXT NOT NULL, source TEXT NOT NULL,
 assessment TEXT NOT NULL, PRIMARY KEY(org,id));
CREATE TRIGGER immutable_source BEFORE UPDATE ON sources BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TRIGGER retain_source BEFORE DELETE ON sources BEGIN SELECT RAISE(ABORT,'immutable'); END;
CREATE TABLE audit (
 seq INTEGER PRIMARY KEY, org TEXT NOT NULL REFERENCES orgs(org), actor TEXT NOT NULL,
 action TEXT NOT NULL, target TEXT NOT NULL, version INTEGER NOT NULL, at TEXT NOT NULL);
PRAGMA user_version=1;
"""


class ScopedStore:
    """Only parameterized queries, always with a tenant qualifier."""

    def __init__(self, connection: sqlite3.Connection, org: str) -> None:
        self.connection, self.org = connection, org

    def get(self, kind: Kind, key: str) -> tuple[int, str] | None:
        row = self.connection.execute(
            "SELECT version,body FROM records WHERE org=? AND kind=? AND id=?",
            (self.org, kind, key),
        ).fetchone()
        return (int(row[0]), str(row[1])) if row else None

    def put(self, kind: Kind, key: str, body: str, expected: int = 0) -> int:
        if type(expected) is not int or not 0 <= expected < 1_000_000:
            raise TeamError("CONFLICT")
        existing = self.get(kind, key)
        if existing is None:
            if expected != 0:
                raise TeamError("CONFLICT")
            count = self.connection.execute(
                "SELECT count(*) FROM records WHERE org=? AND kind=?", (self.org, kind)
            ).fetchone()[0]
            if count >= 1000:
                raise TeamError("CONFLICT")
            self.connection.execute(
                "INSERT INTO records VALUES (?,?,?,?,?)", (self.org, kind, key, 1, body)
            )
            return 1
        cursor = self.connection.execute(
            "UPDATE records SET version=version+1,body=? "
            "WHERE org=? AND kind=? AND id=? AND version=?",
            (body, self.org, kind, key, expected),
        )
        if cursor.rowcount != 1:
            raise TeamError("CONFLICT")
        return expected + 1

    def rows(self, kind: Kind, offset: int = 0, limit: int = 100) -> list[tuple[str, int, str]]:
        if (
            type(offset) is not int
            or type(limit) is not int
            or not 0 <= offset <= 10000
            or not 1 <= limit <= 100
        ):
            raise TeamError("INVALID_INPUT")
        return [
            (str(r[0]), int(r[1]), str(r[2]))
            for r in self.connection.execute(
                "SELECT id,version,body FROM records WHERE org=? AND kind=? "
                "ORDER BY id LIMIT ? OFFSET ?",
                (self.org, kind, limit, offset),
            )
        ]

    def all_rows(self, kind: Kind) -> list[tuple[str, int, str]]:
        return [row for offset in range(0, 1000, 100) for row in self.rows(kind, offset)]

    def add_source(self, key: str, source: str, assessment: str) -> None:
        self.connection.execute(
            "INSERT INTO sources VALUES (?,?,?,?)", (self.org, key, source, assessment)
        )

    def source(self, key: str) -> tuple[str, str]:
        row = self.connection.execute(
            "SELECT source,assessment FROM sources WHERE org=? AND id=?", (self.org, key)
        ).fetchone()
        if row is None:
            raise TeamError("NOT_FOUND")
        return str(row[0]), str(row[1])

    def audit(self, actor: str, action: str, target: str, version: int, at: str) -> None:
        self.connection.execute(
            "INSERT INTO audit(org,actor,action,target,version,at) VALUES (?,?,?,?,?,?)",
            (self.org, actor, action, target, version, at),
        )

    def audit_rows(self, offset: int, limit: int) -> list[dict[str, object]]:
        # Use the same bounds as record pagination.
        self.rows("member", offset, limit)
        return [
            {
                "schema_version": "team-v1",
                **dict(
                    zip(
                        ("sequence", "actor", "action", "target", "version", "at"), row, strict=True
                    )
                ),
            }
            for row in self.connection.execute(
                "SELECT row_number() OVER (ORDER BY seq),actor,action,target,version,at FROM audit "
                "WHERE org=? ORDER BY seq LIMIT ? OFFSET ?",
                (self.org, limit, offset),
            )
        ]

    def delete_receipt(self, key: str) -> None:
        self.connection.execute(
            "DELETE FROM records WHERE org=? AND kind='receipt' AND id=?", (self.org, key)
        )


class Store:
    def __init__(self, path: Path, *, initialize: bool = False) -> None:
        self.lock = RLock()
        try:
            if initialize:
                # Explicit exclusive creation; never overwrite an existing DB.
                with path.open("xb"):
                    pass
                path.chmod(0o600)
            self.connection = sqlite3.connect(
                path.resolve().as_uri() + "?mode=rw",
                uri=True,
                timeout=2,
                check_same_thread=False,
                isolation_level=None,
            )
            self.connection.execute("PRAGMA foreign_keys=ON")
            self.connection.execute("PRAGMA journal_mode=WAL")
            if initialize:
                self.connection.executescript("BEGIN IMMEDIATE;" + DDL + "COMMIT;")
            if self.connection.execute("PRAGMA user_version").fetchone()[0] != 1:
                raise ValueError
            if self.connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError
            self.connection.execute("SELECT org FROM orgs LIMIT 0")
            self.connection.execute("SELECT body FROM bindings LIMIT 0")
        except (OSError, sqlite3.Error, ValueError):
            raise TeamError("STORE_UNAVAILABLE") from None

    @contextmanager
    def transaction(self) -> Iterator[None]:
        with self.lock:
            try:
                self.connection.execute("BEGIN IMMEDIATE")
                yield
                self.connection.execute("COMMIT")
            except BaseException as exc:
                try:
                    self.connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                if isinstance(exc, sqlite3.IntegrityError):
                    raise TeamError("CONFLICT") from None
                if isinstance(exc, sqlite3.Error):
                    raise TeamError("STORE_UNAVAILABLE") from None
                raise

    def scoped(self, org: str) -> ScopedStore:
        return ScopedStore(self.connection, org)

    def binding(self, issuer: str, subject: str) -> Binding:
        row = self.connection.execute(
            "SELECT body FROM bindings WHERE issuer=? AND subject=?", (issuer, subject)
        ).fetchone()
        if row is None:
            raise TeamError("DENIED")
        return Binding.model_validate_json(str(row[0]))

    def binding_by_id(self, identity: str) -> Binding:
        row = self.connection.execute(
            "SELECT body FROM bindings WHERE identity=?", (identity,)
        ).fetchone()
        if row is None:
            raise TeamError("DENIED")
        return Binding.model_validate_json(str(row[0]))

    def provision(self, binding: Binding) -> None:
        """Offline operator workflow, deliberately not an HTTP operation."""
        binding = Binding.model_validate_json(binding.model_dump_json())
        with self.transaction():
            self.connection.execute(
                "INSERT INTO bindings VALUES (?,?,?,?)",
                (binding.identity_id, binding.issuer, binding.subject, binding.model_dump_json()),
            )

    def close(self) -> None:
        self.connection.close()
