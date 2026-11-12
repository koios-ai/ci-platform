from __future__ import annotations

import os
import shutil
import subprocess
import sys
from functools import partial
from pathlib import Path
from urllib.request import Request

import pytest
from test_path_feed_broker import Response

ACTION = Path(__file__).resolve().parents[1] / ".github/actions/final-preflight"


def upstream(tmp_path: Path, request: Request, *, timeout: float) -> Response:
    from urllib.parse import urlsplit

    assert request.has_header("Authorization")
    url = urlsplit(request.full_url)
    body = request.data or b""
    raw = subprocess.check_output(
        [shutil.which("git") or "git", "http-backend"],
        input=body,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env={
            "GIT_PROJECT_ROOT": str(tmp_path),
            "GIT_HTTP_EXPORT_ALL": "1",
            "PATH_INFO": url.path,
            "QUERY_STRING": url.query,
            "REQUEST_METHOD": request.get_method(),
            "CONTENT_TYPE": request.get_header("Content-type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "HTTP_GIT_PROTOCOL": request.get_header("Git-protocol", ""),
        },
    )
    headers, payload = raw.split(b"\r\n\r\n", 1)
    media_type = next(
        line.split(b":", 1)[1].strip() for line in headers.splitlines() if line.startswith(b"Content-Type:")
    )
    response = Response(payload, media_type.decode("ascii"))
    response.url = request.full_url
    return response


@pytest.mark.skipif(
    sys.platform != "linux"
    or (os.environ.get("GITHUB_ACTIONS") != "true" and os.environ.get("CI_PLATFORM_NATIVE_TEST") != "1"),
    reason="requires explicit access to the native Linux namespace fixture",
)
@pytest.mark.parametrize("missing_head", [False, True])
def test_native_launcher_returns_exact_paths_after_releasing_fetch_worker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing_head: bool
) -> None:
    monkeypatch.syspath_prepend(str(ACTION))
    from path_feed_launcher import changed_paths

    repo = tmp_path / "private" / "fixture.git"
    repo.mkdir(parents=True)

    def git(*args: str, data: bytes | None = None) -> str:
        return (
            subprocess.check_output(["git", *args], cwd=repo, input=data, stderr=subprocess.PIPE, timeout=10)
            .decode()
            .strip()
        )

    git("init", "--bare", "--quiet", "--template=")
    config = ("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid")
    blob = git("hash-object", "-w", "--stdin", data=b"source bytes\n")
    removed = git("hash-object", "-w", "--stdin", data=b"removed bytes\n")
    original = git("mktree", data=f"100644 blob {blob}\told.py\n100644 blob {removed}\tremoved.txt\n".encode())
    base = git(*config, "commit-tree", original, data=b"base\n")
    tree = git("mktree", data=f"100644 blob {blob}\twidget.py\n".encode())
    head = git(*config, "commit-tree", tree, "-p", base, data=b"head\n")
    git("update-ref", "HEAD", head)

    refreshed = []

    def launch(subject_head: str) -> list[str]:
        return changed_paths(
            "private/fixture",
            "synthetic-credential",
            base,
            subject_head,
            lambda: refreshed.append(True),
            opener=partial(upstream, tmp_path),
        )

    if missing_head:
        with pytest.raises((ValueError, RuntimeError)):
            launch("f" * 40)
        assert refreshed == []
    else:
        assert launch(head) == ["old.py", "removed.txt", "widget.py"]
        assert refreshed == [True]


def test_custodian_withholds_closure_when_a_namespace_is_unconfirmed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.syspath_prepend(str(ACTION))
    import path_feed_worker as worker

    def unconfirmed(_root: Path, phase: str, _base: str, _head: str, _deadline: float, pending: set[str]) -> bytes:
        pending.add(phase)
        raise TimeoutError("namespace exit was not observed")

    monkeypatch.setattr(worker.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(worker, "_sandbox", lambda *_args: None)
    monkeypatch.setattr(worker, "_run_namespace", unconfirmed)
    with pytest.raises(TimeoutError, match="exit was not observed"):
        worker._custody(str(tmp_path), "a" * 40, "b" * 40, "1")
    assert capsys.readouterr().out == ""


def test_sealer_refuses_pack_with_another_link(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.syspath_prepend(str(ACTION))
    from path_feed_worker import _sealed_repository

    pack_directory = tmp_path / "store/objects/pack"
    pack_directory.mkdir(parents=True)
    stem = "pack-" + "a" * 40
    pack = pack_directory / (stem + ".pack")
    pack.touch()
    (pack_directory / (stem + ".idx")).touch()
    os.link(pack, tmp_path / "alternate-link")

    with pytest.raises(ValueError, match="unsupported pack files"):
        _sealed_repository(tmp_path)
    assert not (tmp_path / "verify").exists()
