"""Trusted-side HTTP body relay for read-only Git object acquisition."""

from __future__ import annotations

import base64
import math
import re
import time
import urllib.request
from collections.abc import Callable
from email.message import Message
from http.client import HTTPResponse, HTTPSConnection
from typing import Any

_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_CHUNK_BYTES = 65_536
_ROUTES = {
    ("GET", "/info/refs?service=git-upload-pack"): "application/x-git-upload-pack-advertisement",
    ("POST", "/git-upload-pack"): "application/x-git-upload-pack-result",
}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        raise ValueError("Git object-feed redirect refused")


class _StrictResponse(HTTPResponse):
    """Reject incomplete or ambiguous HTTP/1.1 chunk boundaries."""

    chunk_complete = False
    framing_bytes = 0

    def _get_chunk_left(self) -> int | None:
        if self.chunk_complete:
            return None
        if self.chunk_left:
            return self.chunk_left
        if self.chunk_left == 0:
            if self._safe_read(2) != b"\r\n":
                raise ValueError("invalid Git object-feed chunk delimiter")
            self.framing_bytes += 2
        assert self.fp is not None
        size = self.fp.readline(15)
        if not re.fullmatch(rb"[0-9A-Fa-f]{1,12}\r\n", size):
            raise ValueError("invalid Git object-feed chunk size")
        self.framing_bytes += len(size)
        self.chunk_left = int(size[:-2], 16)
        if self.chunk_left:
            return self.chunk_left
        if self.fp.readline(3) != b"\r\n":
            raise ValueError("invalid Git object-feed chunk terminator")
        self.framing_bytes += 2
        self.chunk_complete = True
        self._close_conn()
        return None


class _StrictConnection(HTTPSConnection):
    response_class = _StrictResponse


class _StrictHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, request: urllib.request.Request) -> HTTPResponse:
        return self.do_open(_StrictConnection, request, context=self._context)


_OPEN_HTTPS = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), _StrictHTTPSHandler()).open


def _header(headers: Message, name: str) -> str | None:
    values = headers.get_all(name, [])
    if len(values) > 1:
        raise ValueError(f"Git object-feed response repeats {name}")
    return values[0] if values else None


class UploadPackBroker:
    """Relay one serial acquisition session without sharing its read credential.

    The caller owns the deadline watchdog, trusted destination identity, bounded
    incoming worker request and quota-owned sink. A failed session is spent.
    """

    def __init__(
        self,
        repository: str,
        token: str,
        *,
        deadline: float,
        max_bytes: int,
        max_requests: int,
        clock: Callable[[], float] = time.monotonic,
        opener: Callable[..., HTTPResponse] = _OPEN_HTTPS,
    ) -> None:
        if not _REPOSITORY.fullmatch(repository) or {".", ".."}.intersection(repository.split("/")):
            raise ValueError("invalid repository for Git object feed")
        if not re.fullmatch(r"[!-~]+", token):
            raise ValueError("invalid Git object-feed credential")
        if not math.isfinite(deadline) or any(
            type(limit) is not int or limit <= 0 for limit in (max_bytes, max_requests)
        ):
            raise ValueError("invalid Git object-feed limits")
        self._url = f"https://github.com/{repository}.git"
        self._authorization = "Basic " + base64.b64encode(f"x-access-token:{token}".encode("ascii")).decode("ascii")
        self._clock = clock
        self._deadline = deadline
        self._max_bytes = max_bytes
        self._max_requests = max_requests
        self._open = opener
        self._consumed_bytes = 0
        self._requests = 0
        self._spent = False

    @property
    def consumed_bytes(self) -> int:
        return self._consumed_bytes

    def _remaining_time(self) -> float:
        remaining = self._deadline - self._clock()
        if remaining <= 0:
            raise TimeoutError("Git object-feed deadline expired")
        return remaining

    def _available_bytes(self) -> int:
        return self._max_bytes - self._consumed_bytes

    def _charge(self, size: int) -> None:
        if size > self._available_bytes():
            raise ValueError("Git object-feed byte budget exceeded")
        self._consumed_bytes += size

    def _relay(self, response: HTTPResponse, media_type: str, write: Callable[[bytes], None]) -> None:
        if _header(response.headers, "Content-Type") != media_type:
            raise ValueError("unexpected Git object-feed media type")
        if _header(response.headers, "Content-Encoding") not in (None, "identity"):
            raise ValueError("unexpected Git object-feed content encoding")
        length = _header(response.headers, "Content-Length")
        transfer_encoding = _header(response.headers, "Transfer-Encoding")
        if length is not None and transfer_encoding is None and re.fullmatch(r"[0-9]{1,12}", length):
            expected = int(length)
        elif length is None and transfer_encoding == "chunked" and isinstance(response, _StrictResponse):
            expected = None
        else:
            raise ValueError("invalid Git object-feed response framing")
        if expected is not None and expected > self._available_bytes():
            raise ValueError("Git object-feed byte budget exceeded")

        sent = 0
        framing_bytes = 0
        while True:
            self._remaining_time()
            block = response.read1(min(_CHUNK_BYTES, self._available_bytes() + 1))
            self._remaining_time()
            if isinstance(response, _StrictResponse):
                self._charge(response.framing_bytes - framing_bytes)
                framing_bytes = response.framing_bytes
            if not block:
                break
            self._charge(len(block))
            sent += len(block)
            if expected is not None and sent > expected:
                raise ValueError("Git object-feed response exceeds its declared length")
            write(block)
        if expected is None:
            complete = isinstance(response, _StrictResponse) and response.chunk_complete
        else:
            complete = sent == expected
        if not sent or not complete:
            raise ValueError("truncated or empty Git object-feed response")

    def forward(self, method: str, route: str, body: bytes, write: Callable[[bytes], None]) -> None:
        if self._spent:
            raise ValueError("Git object-feed session is spent")
        self._spent = True
        media_type = _ROUTES.get((method, route))
        if media_type is None or bool(body) != (method == "POST"):
            raise ValueError("invalid Git upload-pack route or request body")
        if self._requests >= self._max_requests:
            raise ValueError("Git object-feed request budget exceeded")
        self._charge(len(body))
        self._requests += 1
        headers = {
            "Authorization": self._authorization,
            "Accept": media_type,
            "Accept-Encoding": "identity",
            "Git-Protocol": "version=2",
        }
        if method == "POST":
            headers["Content-Type"] = "application/x-git-upload-pack-request"
        url = self._url + route
        request = urllib.request.Request(url, data=body or None, headers=headers, method=method)
        with self._open(request, timeout=self._remaining_time()) as response:
            if response.status != 200 or response.geturl() != url:
                raise ValueError("unexpected Git object-feed response destination or status")
            self._relay(response, media_type, write)
        self._remaining_time()
        self._spent = False
