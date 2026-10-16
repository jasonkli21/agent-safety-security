"""Approval uses a separate controlling TTY, never protocol stdin/stdout."""

import asyncio
import os
import termios
from datetime import UTC, datetime

from agentsec.domain.approvals import ApprovalDecision, ApprovalRequest
from agentsec.domain.identity import PrincipalRef
from agentsec.domain.taxonomy import ApprovalOutcome, PrincipalType
from agentsec.runtime.models import RuntimeFailure


class TerminalApprovalBroker:
    def __init__(self) -> None:
        self._lock = asyncio.Lock()

    async def decide(self, request: ApprovalRequest, presentation: str) -> ApprovalDecision:
        async with self._lock:
            loop = asyncio.get_running_loop()
            try:
                fd = os.open("/dev/tty", os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
            except OSError as exc:
                raise RuntimeFailure("APPROVAL_UNAVAILABLE") from exc
            try:
                if not os.isatty(fd) or request.expires_at is None:
                    raise RuntimeFailure("APPROVAL_UNAVAILABLE")
                remaining = (request.expires_at - datetime.now(UTC)).total_seconds()
                if remaining <= 0:
                    raise RuntimeFailure("APPROVAL_TIMEOUT")
                prompt = f"\n{presentation}\nType approve or deny: ".encode()
                termios.tcflush(fd, termios.TCIFLUSH)
                os.write(fd, prompt)
                answer: asyncio.Future[bytes] = loop.create_future()

                def ready() -> None:
                    try:
                        data = os.read(fd, 128)
                        if not answer.done():
                            answer.set_result(data)
                    except BlockingIOError:
                        pass
                    except OSError:
                        if not answer.done():
                            answer.set_result(b"")

                loop.add_reader(fd, ready)
                try:
                    data = await asyncio.wait_for(answer, remaining)
                except TimeoutError as exc:
                    raise RuntimeFailure("APPROVAL_TIMEOUT") from exc
                finally:
                    loop.remove_reader(fd)
                return ApprovalDecision(
                    schema_version="0.1",
                    approval_id=request.approval_id,
                    approver=PrincipalRef(
                        principal_id="local-terminal", principal_type=PrincipalType.USER
                    ),
                    outcome=ApprovalOutcome.APPROVE
                    if data.strip() == b"approve"
                    else ApprovalOutcome.DENY,
                    decided_at=datetime.now(UTC),
                )
            except OSError as exc:
                raise RuntimeFailure("APPROVAL_UNAVAILABLE") from exc
            finally:
                os.close(fd)
