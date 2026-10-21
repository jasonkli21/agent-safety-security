"""Explicit host backend and real Docker CLI isolation with no fallback."""

import asyncio
from tempfile import TemporaryDirectory
from typing import Literal, Protocol, Self
from uuid import uuid4

from pydantic import Field, model_validator

from agentsec.domain.base import Identifier, VersionedModel
from agentsec.domain.serialization import content_digest
from agentsec.isolation.process import ProcessRequest, ProcessResult, run_process
from agentsec.runtime.models import RuntimeFailure


class IsolationBackend(Protocol):
    @property
    def identity_digest(self) -> str: ...
    async def execute(self, request: ProcessRequest) -> ProcessResult: ...


class HostBackend:
    """Explicitly unisolated execution, selected only by protected application wiring."""

    @property
    def identity_digest(self) -> str:
        return content_digest({"backend": "host", "version": "1"})

    async def execute(self, request: ProcessRequest) -> ProcessResult:
        return await run_process(request)


class DockerMount(VersionedModel):
    source: str
    target: str
    read_only: bool = True

    @model_validator(mode="after")
    def safe_mount(self) -> Self:
        from pathlib import PurePosixPath

        for path in (self.source, self.target):
            if (
                not path.startswith("/")
                or any(c in path for c in (",", "\0", "\n", "\r"))
                or ".." in PurePosixPath(path).parts
            ):
                raise ValueError("Invalid mount")
        import os
        import stat

        resolved = os.path.realpath(self.source)
        restricted = ("/dev", "/proc", "/sys", "/run", "/var/run")
        if (
            self.source in {"/", "/var"}
            or self.target == "/"
            or any(resolved == root or resolved.startswith(root + "/") for root in restricted)
            or any(self.target == root or self.target.startswith(root + "/") for root in restricted)
            or "docker.sock" in self.source
            or "docker.sock" in self.target
        ):
            raise ValueError("Unsafe mount")
        try:
            if stat.S_ISSOCK(os.stat(self.source).st_mode):
                raise ValueError("Socket mount forbidden")
        except FileNotFoundError:
            pass
        return self


class DockerProfile(VersionedModel):
    executable: str = "/usr/bin/docker"
    image: str
    runtime: Identifier | None = None
    network: Literal["none"] = "none"
    read_only: bool = True
    memory_mb: int = Field(default=256, ge=16, le=65536)
    cpus: int = Field(default=1, ge=1, le=64)
    pids: int = Field(default=64, ge=1, le=4096)
    user: str = "65534:65534"
    mounts: tuple[DockerMount, ...] = ()

    @model_validator(mode="after")
    def valid_profile(self) -> Self:
        import re

        if not self.executable.startswith("/") or "\0" in self.executable:
            raise ValueError("Absolute Docker executable required")
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_./:@-]{0,255}", self.image):
            raise ValueError("Invalid image")
        if not re.fullmatch(r"[0-9]+:[0-9]+", self.user) or self.user.split(":")[0] == "0":
            raise ValueError("Non-root numeric user required")
        targets = [m.target for m in self.mounts]
        if len(set(targets)) != len(targets):
            raise ValueError("Duplicate mount")
        return self


class DockerBackend:
    _cleanup_wait_seconds = 12.0

    def __init__(self, profile: DockerProfile) -> None:
        self.__profile_json = profile.model_dump_json()
        self.__cleanup_tasks: dict[asyncio.Task[ProcessResult], TemporaryDirectory[str]] = {}
        self.__cleanup_failed = False

    @property
    def identity_digest(self) -> str:
        return content_digest(
            {
                "backend": "docker",
                "version": "2",
                "profile": DockerProfile.model_validate_json(self.__profile_json),
            }
        )

    def command(self, request: ProcessRequest, name: str, config_directory: str) -> ProcessRequest:
        p = DockerProfile.model_validate_json(self.__profile_json)
        argv = [
            p.executable,
            "--config",
            config_directory,
            "run",
            "--pull=never",
            "--name",
            name,
            "--network=none",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true",
            "--memory",
            f"{p.memory_mb}m",
            "--cpus",
            str(p.cpus),
            "--pids-limit",
            str(p.pids),
            "--user",
            p.user,
            "--workdir",
            request.cwd,
            "--entrypoint",
            request.argv[0],
        ]
        if p.read_only:
            argv.append("--read-only")
        if p.runtime:
            argv.extend(["--runtime", p.runtime])
        for mount in p.mounts:
            argv.extend(
                [
                    "--mount",
                    f"type=bind,src={mount.source},dst={mount.target}"
                    + (",readonly" if mount.read_only else ""),
                ]
            )
        for key, value in sorted(request.env.items()):
            argv.extend(["--env", f"{key}={value}"])
        argv.extend([p.image, *request.argv[1:]])
        # Empty client env: no DOCKER_HOST, proxy, credential or config inheritance.
        return ProcessRequest(
            schema_version="0.1",
            argv=tuple(argv),
            cwd="/",
            env={},
            timeout_seconds=request.timeout_seconds,
            output_limit=request.output_limit,
        )

    async def execute(self, request: ProcessRequest) -> ProcessResult:
        name = "agentsec-" + uuid4().hex
        private_config = TemporaryDirectory(prefix="agentsec-docker-")
        command = self.command(request, name, private_config.name)
        try:
            result = await run_process(command)
            if result.exit_code in {125, 126, 127}:
                raise RuntimeFailure("ISOLATION_UNAVAILABLE")
            return result
        finally:
            cleanup_task = asyncio.create_task(
                self._remove_container(command, name, private_config.name)
            )
            self.__cleanup_tasks[cleanup_task] = private_config
            cleanup_task.add_done_callback(self._cleanup_finished)
            await self._await_cleanup(cleanup_task, timeout_seconds=self._cleanup_wait_seconds)

    async def _remove_container(
        self, command: ProcessRequest, name: str, config_directory: str
    ) -> ProcessResult:
        # CLI termination does not prove daemon-side termination; remove by protected random name.
        cleanup = ProcessRequest(
            schema_version="0.1",
            argv=(command.argv[0], "--config", config_directory, "rm", "-f", name),
            cwd="/",
            env={},
            timeout_seconds=10,
            output_limit=8192,
        )
        try:
            result = await run_process(cleanup)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            raise RuntimeFailure("ISOLATION_CLEANUP_UNCONFIRMED") from exc
        if result.exit_code != 0:
            raise RuntimeFailure("ISOLATION_CLEANUP_UNCONFIRMED")
        return result

    def _cleanup_finished(self, task: asyncio.Task[ProcessResult]) -> None:
        directory = self.__cleanup_tasks.get(task)
        if directory is not None:
            directory.cleanup()
        try:
            result = task.result()
            if result.exit_code != 0:
                self.__cleanup_failed = True
        except Exception:
            self.__cleanup_failed = True
        except asyncio.CancelledError:
            self.__cleanup_failed = True

    def _release_cleanup(self, task: asyncio.Task[ProcessResult]) -> None:
        directory = self.__cleanup_tasks.pop(task, None)
        if directory is not None:
            directory.cleanup()

    async def _await_cleanup(
        self, task: asyncio.Task[ProcessResult], *, timeout_seconds: float
    ) -> ProcessResult:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        cancelled = False
        while not task.done():
            remaining = deadline - loop.time()
            if remaining <= 0:
                break
            try:
                await asyncio.wait_for(asyncio.shield(task), timeout=remaining)
            except asyncio.CancelledError:
                cancelled = True
            except TimeoutError:
                break
        if not task.done():
            raise RuntimeFailure("ISOLATION_CLEANUP_UNCONFIRMED")
        try:
            result = task.result()
        except asyncio.CancelledError as exc:
            self.__cleanup_failed = True
            self._release_cleanup(task)
            raise RuntimeFailure("ISOLATION_CLEANUP_UNCONFIRMED") from exc
        except Exception:
            self.__cleanup_failed = True
            self._release_cleanup(task)
            raise
        self._release_cleanup(task)
        if cancelled:
            raise asyncio.CancelledError
        return result

    @property
    def pending_cleanup_count(self) -> int:
        return sum(not task.done() for task in self.__cleanup_tasks)

    async def drain_cleanup(self, timeout_seconds: float = 12) -> bool:
        """Wait for owned late cleanup work during orderly application shutdown."""
        tasks = tuple(self.__cleanup_tasks)
        if not tasks:
            return not self.__cleanup_failed
        deadline = asyncio.get_running_loop().time() + timeout_seconds
        for task in tasks:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                return False
            try:
                await self._await_cleanup(task, timeout_seconds=remaining)
            except (RuntimeFailure, asyncio.CancelledError):
                return False
        return not self.__cleanup_failed
