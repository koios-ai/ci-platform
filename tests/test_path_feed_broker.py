from __future__ import annotations

import base64
import importlib.util
import os
import subprocess
import threading
from email.message import Message
from http.client import HTTPResponse
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request

import pytest

BROKER = Path(__file__).resolve().parents[1] / ".github/actions/final-preflight/path_feed_broker.py"
ADVERTISEMENT = "application/x-git-upload-pack-advertisement"
RESULT = "application/x-git-upload-pack-result"


def broker_module():
    spec = importlib.util.spec_from_file_location("path_feed_broker", BROKER)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Response:
    def __init__(self, body: bytes, media_type: str, *, length: int | None = None) -> None:
        self.url = ""
        self.status = 200
        self.headers = Message()
        self.headers["Content-Type"] = media_type
        self.headers["Content-Length"] = str(len(body) if length is None else length)
        self.body = body
        self.on_read = lambda: None
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *_args) -> None:
        self.closed = True

    def geturl(self) -> str:
        return self.url

    def read1(self, count: int) -> bytes:
        self.on_read()
        block, self.body = self.body[:count], self.body[count:]
        return block


class Transport:
    def __init__(self, *responses: Response) -> None:
        self.responses = iter(responses)
        self.requests: list[tuple[Request, float]] = []

    def __call__(self, request: Request, *, timeout: float) -> Response:
        self.requests.append((request, timeout))
        response = next(self.responses)
        response.url = response.url or request.full_url
        return response


def make_broker(module, transport, *, budget: int = 80, requests: int = 3, clock=lambda: 0.0):
    return module.UploadPackBroker(
        "private/fixture",
        "invented-token",
        deadline=10.0,
        max_bytes=budget,
        max_requests=requests,
        clock=clock,
        opener=transport,
    )


def test_broker_uses_only_confirmed_destination_and_holds_token() -> None:
    module = broker_module()
    transport = Transport(Response(b"refs", ADVERTISEMENT), Response(b"pack", RESULT))
    broker = make_broker(module, transport)
    sink: list[bytes] = []

    broker.forward("GET", "/info/refs?service=git-upload-pack", b"", sink.append)
    broker.forward("POST", "/git-upload-pack", b"want synthetic", sink.append)

    assert sink == [b"refs", b"pack"]
    assert broker.consumed_bytes == 22
    assert [request.full_url for request, _ in transport.requests] == [
        "https://github.com/private/fixture.git/info/refs?service=git-upload-pack",
        "https://github.com/private/fixture.git/git-upload-pack",
    ]
    assert all(timeout == 10 for _, timeout in transport.requests)
    encoded = base64.b64encode(b"x-access-token:invented-token").decode("ascii")
    assert transport.requests[1][0].get_header("Authorization") == "Basic " + encoded


@pytest.mark.parametrize(
    ("method", "target"),
    [
        ("POST", "/git-receive-pack"),
        ("GET", "https://other.invalid/info/refs?service=git-upload-pack"),
        ("GET", "/info/refs?service=git-upload-pack&other=1"),
        ("GET", "/../info/refs?service=git-upload-pack"),
    ],
)
def test_broker_refuses_other_endpoints_before_open(method: str, target: str) -> None:
    module = broker_module()
    transport = Transport()
    with pytest.raises(ValueError, match="upload-pack route"):
        make_broker(module, transport).forward(method, target, b"", lambda _: None)
    assert not transport.requests


def test_broker_bounds_request_and_response_bytes_across_requests() -> None:
    module = broker_module()
    transport = Transport(Response(b"1234", ADVERTISEMENT), Response(b"5678", RESULT))
    broker = make_broker(module, transport, budget=10)
    sink: list[bytes] = []
    broker.forward("GET", "/info/refs?service=git-upload-pack", b"", sink.append)
    with pytest.raises(ValueError, match="byte budget"):
        broker.forward("POST", "/git-upload-pack", b"abc", sink.append)
    assert sink == [b"1234"]
    assert transport.requests[1][0].data == b"abc"


def test_broker_refuses_over_budget_block_before_forwarding() -> None:
    module = broker_module()
    response = Response(b"too much", RESULT, length=3)
    sink: list[bytes] = []
    with pytest.raises(ValueError, match="byte budget"):
        make_broker(module, Transport(response), budget=4).forward("POST", "/git-upload-pack", b"x", sink.append)
    assert not sink
    assert response.closed


@pytest.mark.parametrize(
    ("framing", "raw_body", "supported"),
    [
        (b"Transfer-Encoding: chunked", b"4\r\ndataXX0\r\n\r\n", False),
        (b"Transfer-Encoding: chunked", b"4\r\ndata\r\n0\r\n", False),
        (b"Transfer-Encoding: chunked", b"4\r\ndata\r\n0\r\n\r\n", False),
        (b"Content-Length: 4", b"data", True),
    ],
    ids=["bad-separator", "missing-trailer-end", "valid-chunked-unsupported", "fixed-length"],
)
def test_broker_checks_raw_http_framing_before_forwarding(framing: bytes, raw_body: bytes, supported: bool) -> None:
    module = broker_module()
    raw = BytesIO(b"HTTP/1.1 200 OK\r\nContent-Type: " + RESULT.encode() + b"\r\n" + framing + b"\r\n\r\n" + raw_body)

    class FixtureSocket:
        def makefile(self, mode: str) -> BytesIO:
            assert mode == "rb"
            return raw

    def open_response(request: Request, *, timeout: float) -> HTTPResponse:
        assert timeout > 0
        response = HTTPResponse(FixtureSocket())
        response.url = request.full_url
        response.begin()
        return response

    sink: list[bytes] = []
    broker = make_broker(module, open_response)
    if supported:
        broker.forward("POST", "/git-upload-pack", b"x", sink.append)
        assert sink == [b"data"]
    else:
        with pytest.raises(ValueError, match="response framing"):
            broker.forward("POST", "/git-upload-pack", b"x", sink.append)
        assert not sink
    assert raw.closed


@pytest.mark.parametrize("complete", [True, False])
def test_broker_checks_terminal_chunk(complete: bool) -> None:
    module = broker_module()
    raw = BytesIO(
        b"HTTP/1.1 200 OK\r\nContent-Type: "
        + RESULT.encode()
        + b"\r\nTransfer-Encoding: chunked\r\n\r\n"
        + b"2\r\nda\r\n2\r\nta\r\n0\r\n"
        + (b"\r\n" if complete else b"")
    )

    class FixtureSocket:
        def makefile(self, mode: str) -> BytesIO:
            assert mode == "rb"
            return raw

    def open_response(request: Request, *, timeout: float) -> HTTPResponse:
        assert timeout > 0
        response = module._StrictResponse(FixtureSocket())
        response.url = request.full_url
        response.begin()
        return response

    sink: list[bytes] = []
    broker = make_broker(module, open_response)
    if complete:
        broker.forward("POST", "/git-upload-pack", b"x", sink.append)
        assert b"".join(sink) == b"data"
    else:
        with pytest.raises(ValueError, match="chunk terminator"):
            broker.forward("POST", "/git-upload-pack", b"x", sink.append)
        with pytest.raises(ValueError, match="spent"):
            broker.forward("POST", "/git-upload-pack", b"x", sink.append)
    assert raw.closed


@pytest.mark.parametrize("failure", ["truncated", "redirected", "unframed", "compressed", "wrong-media", "duplicate"])
def test_broker_refuses_incomplete_or_unexpected_responses(failure: str) -> None:
    module = broker_module()
    response = Response(b"data", RESULT)
    if failure == "truncated":
        response.headers.replace_header("Content-Length", "5")
    elif failure == "redirected":
        response.url = "https://other.invalid/private/fixture.git/git-upload-pack"
    elif failure == "unframed":
        del response.headers["Content-Length"]
    elif failure == "compressed":
        response.headers["Content-Encoding"] = "gzip"
    elif failure == "wrong-media":
        response.headers.replace_header("Content-Type", "text/html")
    else:
        response.headers["Content-Length"] = "9"

    with pytest.raises(ValueError):
        make_broker(module, Transport(response)).forward("POST", "/git-upload-pack", b"x", lambda _: None)
    assert response.closed


def test_native_redirect_handler_does_not_reissue_request() -> None:
    module = broker_module()
    with pytest.raises(ValueError, match="redirect refused"):
        module._NoRedirect().redirect_request(None, None, 302, "moved", Message(), "https://other.invalid/")


def test_broker_refuses_response_bytes_returned_after_original_deadline() -> None:
    module = broker_module()
    now = [0.0]
    response = Response(b"late", RESULT)
    response.on_read = lambda: now.__setitem__(0, 10.0)
    sink: list[bytes] = []
    with pytest.raises(TimeoutError, match="deadline"):
        make_broker(module, Transport(response), clock=lambda: now[0]).forward(
            "POST", "/git-upload-pack", b"x", sink.append
        )
    assert not sink


def test_broker_refuses_excess_requests_and_is_spent_after_incomplete_transfer() -> None:
    module = broker_module()
    transport = Transport(Response(b"refs", ADVERTISEMENT))
    broker = make_broker(module, transport, requests=1)
    broker.forward("GET", "/info/refs?service=git-upload-pack", b"", lambda _: None)
    with pytest.raises(ValueError, match="request budget"):
        broker.forward("POST", "/git-upload-pack", b"x", lambda _: None)
    assert len(transport.requests) == 1

    broken = Transport(Response(b"x", RESULT, length=2))
    broker = make_broker(module, broken)
    with pytest.raises(ValueError, match="truncated"):
        broker.forward("POST", "/git-upload-pack", b"x", lambda _: None)
    with pytest.raises(ValueError, match="spent"):
        broker.forward("POST", "/git-upload-pack", b"retry", lambda _: None)
    assert len(broken.requests) == 1


def test_broker_relays_native_git_upload_pack_without_exposing_credential(tmp_path: Path) -> None:
    module = broker_module()
    source = tmp_path / "private" / "fixture.git"
    source.mkdir(parents=True)
    receiver = tmp_path / "receiver.git"
    receiver.mkdir()

    def git(root: Path, *arguments: str, data: bytes | None = None) -> bytes:
        return subprocess.check_output(["git", *arguments], cwd=root, input=data, stderr=subprocess.PIPE, timeout=10)

    git(source, "init", "--bare", "--quiet", "--template=")
    tree = git(source, "mktree", data=b"").decode().strip()
    head = (
        git(
            source,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit-tree",
            tree,
            data=b"synthetic upload-pack subject\n",
        )
        .decode()
        .strip()
    )
    git(source, "update-ref", "HEAD", head)
    git(receiver, "init", "--bare", "--quiet", "--template=")
    broker_calls: list[Request] = []
    worker_headers: list[str | None] = []

    def native_upstream(request: Request, *, timeout: float) -> Response:
        broker_calls.append(request)
        url = urlsplit(request.full_url)
        body = request.data or b""
        environment = os.environ | {
            "GIT_PROJECT_ROOT": str(tmp_path),
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": url.path,
            "QUERY_STRING": url.query,
            "REQUEST_METHOD": request.get_method(),
            "CONTENT_TYPE": request.get_header("Content-type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_GIT_PROTOCOL": request.get_header("Git-protocol", ""),
        }
        raw = subprocess.check_output(
            ["git", "http-backend"], input=body, env=environment, cwd=tmp_path, stderr=subprocess.PIPE, timeout=timeout
        )
        headers, payload = raw.split(b"\r\n\r\n", 1)
        media_type = next(
            line.split(b":", 1)[1].strip() for line in headers.splitlines() if line.startswith(b"Content-Type:")
        )
        response = Response(payload, media_type.decode("ascii"))
        response.url = request.full_url
        return response

    broker = module.UploadPackBroker(
        "private/fixture",
        "invented-token",
        deadline=module.time.monotonic() + 15,
        max_bytes=32_768,
        max_requests=8,
        opener=native_upstream,
    )

    class FixtureHandler(BaseHTTPRequestHandler):
        def exchange(self) -> None:
            worker_headers.append(self.headers.get("Authorization"))
            length = int(self.headers.get("Content-Length", "0"))
            assert 0 <= length <= 8_192
            blocks: list[bytes] = []
            broker.forward(self.command, self.path, self.rfile.read(length), blocks.append)
            payload = b"".join(blocks)
            self.send_response(200)
            self.send_header("Content-Type", ADVERTISEMENT if self.command == "GET" else RESULT)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = exchange
        do_POST = exchange

    with HTTPServer(("127.0.0.1", 0), FixtureHandler) as server:
        listener = threading.Thread(target=server.serve_forever, daemon=True)
        listener.start()
        try:
            git(
                receiver,
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.http.allow=always",
                "-c",
                "http.proxy=",
                "fetch",
                "--quiet",
                "--no-tags",
                f"http://127.0.0.1:{server.server_port}",
                head,
            )
        finally:
            server.shutdown()
            listener.join(timeout=2)

    assert git(receiver, "cat-file", "-t", head).strip() == b"commit"
    assert {request.get_method() for request in broker_calls} == {"GET", "POST"}
    assert all(request.has_header("Authorization") for request in broker_calls)
    assert worker_headers and set(worker_headers) == {None}
