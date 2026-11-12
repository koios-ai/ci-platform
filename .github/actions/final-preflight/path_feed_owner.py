"""Order a trusted Git acquisition and verify custody before admitting evidence."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

_CLEANUP_GRACE_SECONDS = 5


class AcquisitionRefused(RuntimeError):
    """The session cannot provide evidence for the requested subject."""


@dataclass(frozen=True)
class TransferTerminal:
    leader_exit_code: int | None
    framing_complete: bool


@dataclass(frozen=True)
class OwnerClosure:
    descendants_closed: bool | None
    writers_closed: bool | None

    @property
    def confirmed(self) -> bool:
        return self.descendants_closed is True and self.writers_closed is True


class AcquisitionSession[Evidence](Protocol):
    """Single-use ports from a trusted launcher bound to one immutable subject.

    The launcher enforces the native limits and watchdog. Each operation takes
    an absolute monotonic deadline and refuses incomplete observations. Cleanup
    operations also handle a partly established session or an already closed
    resource. Quarantine must make the store ineligible for reuse.
    """

    def establish(self, deadline: float) -> None: ...
    def fetch(self, deadline: float) -> TransferTerminal: ...
    def revoke_bridge(self, deadline: float) -> None: ...
    def observe_closure(self, deadline: float) -> OwnerClosure: ...
    def verify_offline(self, deadline: float) -> Evidence: ...
    def refresh_pr(self, deadline: float) -> None: ...
    def quarantine(self, deadline: float) -> None: ...
    def terminate_and_reap(self, deadline: float) -> OwnerClosure: ...


def acquire[Evidence](
    session: AcquisitionSession[Evidence], *, deadline: float, clock: Callable[[], float] = time.monotonic
) -> Evidence:
    """Acquire and check one session without publishing from any phase."""

    def require_time() -> None:
        if not math.isfinite(deadline) or not clock() < deadline:
            raise TimeoutError("Git acquisition deadline expired")

    require_time()
    bridge_revoked = False
    try:
        session.establish(deadline)
        require_time()
        terminal = session.fetch(deadline)
        require_time()
        if type(terminal.leader_exit_code) is not int or terminal.leader_exit_code != 0:
            raise AcquisitionRefused("Git leader exit was not observed as successful")
        if terminal.framing_complete is not True:
            raise AcquisitionRefused("incomplete transfer at Git leader exit")
        session.revoke_bridge(deadline)
        bridge_revoked = True
        require_time()
        closure = session.observe_closure(deadline)
        require_time()
        if not closure.confirmed:
            raise AcquisitionRefused("whole owner closure was not confirmed")
        evidence = session.verify_offline(deadline)
        require_time()
        session.refresh_pr(deadline)
        require_time()
        return evidence
    except BaseException as primary:
        cleanup_deadline = clock() + _CLEANUP_GRACE_SECONDS
        failures: list[BaseException] = [primary]

        def terminate(bound: float) -> None:
            closure = session.terminate_and_reap(bound)
            if not isinstance(closure, OwnerClosure) or not closure.confirmed:
                raise AcquisitionRefused("cleanup closure was not confirmed")

        actions = [session.quarantine, terminate]
        if not bridge_revoked:
            actions.insert(0, session.revoke_bridge)
        for action in actions:
            try:
                action(cleanup_deadline)
            except BaseException as error:
                failures.append(error)
        if len(failures) > 1:
            raise BaseExceptionGroup("Git acquisition refused and cleanup was incomplete", failures) from None
        raise
