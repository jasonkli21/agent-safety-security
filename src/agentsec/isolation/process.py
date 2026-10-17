"""Bounded argv execution with explicit environment and kill-on-cancellation."""

import asyncio
import os
import signal
from typing import Self

from pydantic import Field, model_validator

from agentsec.domain.base import VersionedModel
from agentsec.runtime.models import RuntimeFailure


class ProcessRequest(VersionedModel):
    argv: tuple[str, ...]
    cwd: str
    env: dict[str, str] = Field(default_factory=dict, repr=False)
    timeout_seconds: int = Field(default=10, ge=1, le=300)
    output_limit: int = Field(default=65536, ge=1, le=1048576)

    @model_validator(mode="after")
    def safe_process(self) -> Self:
        if not self.argv or not os.path.isabs(self.argv[0]) or not os.path.isabs(self.cwd):
            raise ValueError("Absolute executable and cwd required")
        values = [*self.argv, self.cwd, *self.env.keys(), *self.env.values()]
        if any("\0" in v for v in values) or any(not k or "=" in k for k in self.env):
            raise ValueError("Invalid argv/env")
        return self


class ProcessResult(VersionedModel):
    exit_code: int
    stdout: str
    stderr: str


async def run_process(request: ProcessRequest) -> ProcessResult:
    try:
        process = await asyncio.create_subprocess_exec(
            *request.argv,
            cwd=request.cwd,
            env=dict(request.env),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except (OSError, ValueError) as exc:
        raise RuntimeFailure("PROCESS_UNAVAILABLE") from exc
    used = 0

    async def read(stream: asyncio.StreamReader | None) -> bytes:
        nonlocal used
        assert stream is not None
        chunks: list[bytes] = []
        while chunk := await stream.read(8192):
            used += len(chunk)
            if used > request.output_limit:
                raise RuntimeFailure("PROCESS_OUTPUT_LIMIT")
            chunks.append(chunk)
        return b"".join(chunks)

    tasks = [asyncio.create_task(read(process.stdout)), asyncio.create_task(read(process.stderr))]
    try:
        async with asyncio.timeout(request.timeout_seconds):
            stdout, stderr = await asyncio.gather(*tasks)
            code = await process.wait()
        return ProcessResult(
            schema_version="0.1",
            exit_code=code,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
        )
    except TimeoutError as exc:
        raise RuntimeFailure("PROCESS_TIMEOUT") from exc
    finally:
        # Kill descendants too, including those holding output pipes open.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await process.wait()
