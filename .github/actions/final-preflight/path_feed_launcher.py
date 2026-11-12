"""Acquire exact Git paths through a credential-separated Linux launcher."""

from __future__ import annotations

import json
import multiprocessing
import os
import re
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from path_feed_broker import UploadPackBroker
from path_feed_owner import OwnerClosure, TransferTerminal, acquire
from path_feed_worker import ENVIRONMENT, MAX_EVIDENCE_BYTES, MAX_REQUEST_BYTES, MAX_TRANSFER_BYTES, ROUTES

_SESSION_SECONDS = 90
_MAX_REQUESTS = 12
_BRIDGE_ROUTES = {wire_method: (method, path) for method, (wire_method, path, _) in ROUTES.items()}


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("path feed deadline expired")
    return remaining


def _serve(
    listener: socket.socket,
    repository: str,
    token: str,
    terminal: Any,
    deadline: float,
    opener: Callable[..., Any] | None,
) -> None:
    try:
        options = {"opener": opener} if opener is not None else {}
        broker = UploadPackBroker(
            repository,
            token,
            deadline=deadline,
            max_bytes=MAX_TRANSFER_BYTES,
            max_requests=_MAX_REQUESTS,
            **options,
        )
        while True:
            listener.settimeout(_remaining(deadline))
            with listener.accept()[0] as connection:
                terminal.value = 0
                connection.settimeout(min(15, _remaining(deadline)))
                with connection.makefile("rb") as request:
                    method, route = _BRIDGE_ROUTES[request.read(1)]
                    (size,) = struct.unpack("!I", request.read(4))
                    if size > MAX_REQUEST_BYTES:
                        raise ValueError("Git worker request exceeded its limit")
                    body = request.read(size)
                    if len(body) != size:
                        raise ValueError("incomplete Git worker request")
                    payload = bytearray()
                    broker.forward(method, route, body, payload.extend)
                connection.sendall(struct.pack("!I", len(payload)))
                connection.sendall(payload)
                if method == "POST":
                    terminal.value = 1
                connection.sendall(b"\x01")
    except Exception:
        # Peer-controlled HTTP errors must never reach the Actions log.
        terminal.value = -1


class _Session:
    def __init__(
        self,
        directory: Path,
        repository: str,
        token: str,
        base: str,
        head: str,
        refresh: Callable[[], None],
        opener: Callable[..., Any] | None,
    ) -> None:
        self.directory = directory
        self.socket_path = directory / "bridge/broker.sock"
        self.subject = (base, head)
        self.repository = repository
        self.token = token
        self.refresh = refresh
        self.opener = opener
        self.context = multiprocessing.get_context("spawn")
        self.terminal = self.context.Value("b", 0, lock=False)
        self.relay: multiprocessing.Process | None = None
        self.custodian: subprocess.Popen[bytes] | None = None
        self.buffer = bytearray()
        self.closed = False
        self.custody_closed = False
        self.quarantined = False

    def establish(self, deadline: float) -> None:
        (self.directory / "root").mkdir(mode=0o700)
        self.socket_path.parent.mkdir(mode=0o755)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(str(self.socket_path))
            self.socket_path.chmod(0o666)
            listener.listen(1)
            self.relay = self.context.Process(
                target=_serve, args=(listener, self.repository, self.token, self.terminal, deadline, self.opener)
            )
            self.relay.start()
        self.custodian = subprocess.Popen(
            [
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/bin/timeout",
                "--foreground",
                "--kill-after=2s",
                f"{_remaining(deadline):.3f}s",
                "/usr/bin/unshare",
                "--mount",
                "--propagation",
                "private",
                "/usr/bin/python3",
                "-IB",
                str(Path(__file__).with_name("path_feed_worker.py").resolve()),
                "custody",
                str(self.directory),
                *self.subject,
                str(deadline),
            ],
            env=ENVIRONMENT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

    def _line(self, deadline: float) -> bytes:
        assert self.custodian is not None and self.custodian.stdout is not None
        descriptor = self.custodian.stdout.fileno()
        while b"\n" not in self.buffer:
            if not select.select([descriptor], [], [], _remaining(deadline))[0]:
                raise TimeoutError("Git custodian did not respond before the deadline")
            block = os.read(descriptor, 65_536)
            if not block or len(self.buffer) + len(block) > MAX_EVIDENCE_BYTES:
                raise ValueError("Git custodian returned incomplete or oversized evidence")
            self.buffer.extend(block)
        line, _, rest = self.buffer.partition(b"\n")
        self.buffer = rest
        if line == b"CLOSED":
            self.custody_closed = True
        return bytes(line)

    def fetch(self, deadline: float) -> TransferTerminal:
        self.closed = self._line(deadline) == b"FETCHED"
        return TransferTerminal(0 if self.closed else None, self.terminal.value == 1)

    def revoke_bridge(self, deadline: float) -> None:
        self.socket_path.unlink(missing_ok=True)
        if self.relay is not None:
            if self.relay.is_alive():
                self.relay.kill()
            self.relay.join(_remaining(deadline))
            if self.relay.is_alive():
                raise TimeoutError("Git broker did not exit")
            self.relay.close()
            self.relay = None

    def observe_closure(self, deadline: float) -> OwnerClosure:
        _remaining(deadline)
        return OwnerClosure(self.closed, self.closed and self.relay is None)

    def verify_offline(self, deadline: float) -> list[str]:
        assert self.custodian is not None and self.custodian.stdin is not None and self.custodian.stdout is not None
        if self.quarantined or not self.observe_closure(deadline).confirmed:
            raise ValueError("Git object store is unavailable for verification")
        self.custodian.stdin.write(b"VERIFY\n")
        value = json.loads(self._line(deadline))
        if (
            self._line(deadline) != b"CLOSED"
            or self.custodian.wait(timeout=_remaining(deadline))
            or self.buffer
            or self.custodian.stdout.read(1)
            or not isinstance(value, list)
            or not value
            or len(value) > 5_000
            or any(
                not isinstance(path, str)
                or any(component in {"", ".", ".."} for component in path.split("/"))
                or any(character in path for character in "\\\r\n\x00")
                for path in value
            )
            or value != sorted(set(value))
        ):
            raise ValueError("Git custodian returned malformed paths")
        return value

    def refresh_pr(self, deadline: float) -> None:
        _remaining(deadline)
        self.refresh()

    def quarantine(self, deadline: float) -> None:
        _remaining(deadline)
        self.quarantined = True

    def terminate_and_reap(self, deadline: float) -> OwnerClosure:
        if self.custodian is not None and self.custodian.poll() is None:
            self.custodian.terminate()
            self.custodian.wait(timeout=_remaining(deadline))
        if self.custodian is None:
            return OwnerClosure(True, self.relay is None)
        while not self.custody_closed:
            try:
                self._line(deadline)
            except (ValueError, TimeoutError):
                break
        return OwnerClosure(self.custody_closed, self.custody_closed and self.relay is None)

    def close_control_streams(self) -> None:
        if self.custodian is not None:
            for stream in (self.custodian.stdin, self.custodian.stdout):
                if stream is not None:
                    stream.close()


def changed_paths(
    repository: str,
    token: str,
    base: str,
    head: str,
    refresh: Callable[[], None],
    *,
    opener: Callable[..., Any] | None = None,
) -> list[str]:
    """Return a verified canonical list after Git and the broker have exited."""
    if sys.platform != "linux" or any(not re.fullmatch(r"[0-9a-f]{40}", sha) for sha in (base, head)):
        raise ValueError("path feed requires Linux and full commit identities")
    with tempfile.TemporaryDirectory(prefix="ci-path-", dir="/tmp") as directory:
        session = _Session(Path(directory), repository, token, base, head, refresh, opener)
        try:
            return acquire(session, deadline=time.monotonic() + _SESSION_SECONDS)
        finally:
            session.close_control_streams()
