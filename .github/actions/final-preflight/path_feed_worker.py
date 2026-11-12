"""Native Linux supervisor and unprivileged Git worker for final preflight."""

from __future__ import annotations

import ctypes
import json
import os
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

MAX_REQUEST_BYTES = 256 * 1024
MAX_TRANSFER_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_BYTES = 2_100_000
ROUTES = {
    "GET": (b"G", "/info/refs?service=git-upload-pack", "application/x-git-upload-pack-advertisement"),
    "POST": (b"P", "/git-upload-pack", "application/x-git-upload-pack-result"),
}
WORKER_UID = 65534
ENVIRONMENT = {
    "PATH": "/usr/bin:/usr/sbin",
    "HOME": "/",
    "LANG": "C.UTF-8",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_NO_LAZY_FETCH": "1",
}
GIT = ["/usr/bin/git", "--no-replace-objects", "-c", "core.fsmonitor=false", "-c", "pack.threads=1"]
ROOT_RUNTIME = Path("/runtime")


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("path feed deadline expired")
    return remaining


class BridgeHandler(BaseHTTPRequestHandler):
    def exchange(self) -> None:
        method, path, media_type = ROUTES[self.command]
        lengths = self.headers.get_all("Content-Length", [])
        if (
            self.path != path
            or len(lengths) > 1
            or self.headers.get("Transfer-Encoding") is not None
            or self.headers.get("Authorization") is not None
            or (lengths and not re.fullmatch(r"[0-9]{1,6}", lengths[0]))
        ):
            self.send_error(400)
            return
        size = int(lengths[0]) if lengths else 0
        if size > MAX_REQUEST_BYTES or bool(size) != (method == b"P"):
            self.send_error(400)
            return
        body = self.rfile.read(size)
        if len(body) != size:
            self.send_error(400)
            return
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as bridge:
                bridge.settimeout(15)
                bridge.connect("/bridge/broker.sock")
                bridge.sendall(method + struct.pack("!I", size) + body)
                with bridge.makefile("rb") as response:
                    (length,) = struct.unpack("!I", response.read(4))
                    if not 0 < length <= MAX_TRANSFER_BYTES:
                        raise ValueError("invalid broker response length")
                    self.send_response(200)
                    self.send_header("Content-Type", media_type)
                    self.send_header("Content-Length", str(length))
                    self.end_headers()
                    while length:
                        block = response.read(min(length, 65_536))
                        if not block:
                            raise EOFError("broker response ended early")
                        if len(block) == length and response.read(1) != b"\x01":
                            raise EOFError("broker did not confirm response delivery")
                        self.wfile.write(block)
                        length -= len(block)
        except (OSError, ValueError, EOFError, struct.error):
            self.close_connection = True

    do_GET = exchange
    do_POST = exchange

    def setup(self) -> None:
        self.request.settimeout(15)
        super().setup()

    def log_message(self, *_args: object) -> None:
        pass


def _git(args: list[str], deadline: float, *, cwd: str = "/store") -> None:
    subprocess.run(
        [*GIT, *args],
        env=ENVIRONMENT,
        cwd=cwd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=True,
        timeout=_remaining(deadline),
    )


def _fetch(base: str, head: str, deadline: float) -> None:
    _git(["init", "--bare", "--quiet", "--template=", "--object-format=sha1", "."], deadline)
    with HTTPServer(("127.0.0.1", 0), BridgeHandler) as server:
        relay = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        relay.start()
        try:
            _git(
                [
                    "-c",
                    "protocol.allow=never",
                    "-c",
                    "protocol.http.allow=always",
                    "-c",
                    "http.followRedirects=false",
                    "-c",
                    "fetch.fsckObjects=true",
                    "-c",
                    "fetch.unpackLimit=1",
                    "-c",
                    "pack.writeReverseIndex=false",
                    "fetch",
                    "--quiet",
                    "--no-tags",
                    "--no-write-fetch-head",
                    "--no-recurse-submodules",
                    "--refmap=",
                    f"http://127.0.0.1:{server.server_port}",
                    f"{base}:refs/path-feed/base",
                    f"{head}:refs/path-feed/head",
                ],
                deadline,
            )
        finally:
            server.shutdown()


def _verify(base: str, head: str, deadline: float) -> None:
    sys.path.insert(0, str(ROOT_RUNTIME))
    from merge_gate_policy import git_changed_files

    store = Path("/verify")
    _git(["fsck", "--strict", "--no-reflogs", base, head], deadline, cwd=str(store))
    for expected in (base, head):
        actual = subprocess.check_output(
            [*GIT, "rev-parse", "--verify", f"{expected}^{{commit}}"],
            env=ENVIRONMENT,
            cwd=store,
            stderr=subprocess.DEVNULL,
            timeout=_remaining(deadline),
        )
        if actual != (expected + "\n").encode("ascii"):
            raise ValueError("Git object store does not match the subject")
    paths = git_changed_files(store, base, head)
    sys.stdout.buffer.write(json.dumps(paths, ensure_ascii=False, separators=(",", ":")).encode() + b"\n")


def _command(*args: str) -> None:
    subprocess.run(args, env=ENVIRONMENT, stdin=subprocess.DEVNULL, check=True, timeout=5)


def _bind(source: Path, target: Path, *, device: bool = False) -> None:
    _command("/usr/bin/mount", "--bind", str(source), str(target))
    options = "remount,bind,ro,nosuid" if device else "remount,bind,ro,nosuid,nodev"
    _command("/usr/bin/mount", "-o", options, str(target))


def _sandbox(root: Path, bridge: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ValueError("invalid path feed mountpoint")
    _command(
        "/usr/bin/mount",
        "-t",
        "tmpfs",
        "-o",
        "size=128m,nr_inodes=16384,mode=755,nosuid,nodev,noexec",
        "tmpfs",
        str(root),
    )
    for name in ("usr/bin", "usr/lib", "usr/lib64"):
        target = root / name
        target.mkdir(parents=True, exist_ok=True)
        _bind(Path("/") / name, target)
    for name in ("bin", "lib", "lib64"):
        (root / name).symlink_to(f"usr/{name}")
    (root / "dev").mkdir()
    for name in ("null", "urandom"):
        device = Path("/dev") / name
        target = root / "dev" / name
        target.touch()
        _bind(device, target, device=True)
    runtime = root / "runtime"
    runtime.mkdir()
    here = Path(__file__).resolve()
    for source in (here, here.parents[3] / "scripts/merge_gate_policy.py"):
        shutil.copyfile(source, runtime / source.name)
        (runtime / source.name).chmod(0o444)
    for name in ("tmp", "store", "bridge"):
        (root / name).mkdir()
    (root / "tmp").chmod(0o1777)
    os.chown(root / "store", WORKER_UID, WORKER_UID)
    _bind(bridge, root / "bridge")


def _run_namespace(root: Path, phase: str, base: str, head: str, deadline: float, pending: set[str]) -> bytes:
    import resource

    owner_pid = os.getpid()

    def limits() -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != owner_pid:
            os._exit(1)
        for kind, limit in (
            (resource.RLIMIT_AS, 256 * 1024 * 1024),
            (resource.RLIMIT_FSIZE, MAX_TRANSFER_BYTES),
            (resource.RLIMIT_NPROC, 16),
            (resource.RLIMIT_NOFILE, 64),
            (resource.RLIMIT_CPU, 30),
            (resource.RLIMIT_CORE, 0),
        ):
            resource.setrlimit(kind, (limit, limit))

    pending.add(phase)
    with subprocess.Popen(
        [
            "/usr/bin/unshare",
            "--pid",
            "--fork",
            "--kill-child=KILL",
            "--net",
            "--ipc",
            "--uts",
            "/usr/bin/python3",
            "-IB",
            str(Path(__file__).resolve()),
            "enter",
            str(root),
            phase,
            base,
            head,
            str(deadline),
        ],
        env=ENVIRONMENT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        preexec_fn=limits,
    ) as child:
        try:
            assert child.stdout is not None
            output = child.stdout.read(MAX_EVIDENCE_BYTES + 1)
            if len(output) > MAX_EVIDENCE_BYTES:
                raise RuntimeError("isolated Git worker exceeded its output limit")
            status = child.wait(timeout=_remaining(deadline))
            if status >= 0:
                # The unshare wrapper waited for namespace PID 1. Linux reaps
                # the remaining processes before completing that PID 1 exit.
                pending.remove(phase)
            if status:
                raise RuntimeError("isolated Git worker failed")
            return output
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)


def _sealed_repository(root: Path) -> None:
    objects = root / "store/objects"
    packs = objects / "pack"
    if not all(stat.S_ISDIR(path.lstat().st_mode) for path in (root / "store", objects, packs)):
        raise ValueError("Git object store layout is invalid")
    entries = list(packs.iterdir())
    if (
        not entries
        or len(entries) > 24
        or any(
            not re.fullmatch(r"pack-[0-9a-f]{40}\.(pack|idx)", path.name)
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            for path in entries
            for metadata in (path.lstat(),)
        )
        or {path.stem for path in entries if path.suffix == ".pack"}
        != {path.stem for path in entries if path.suffix == ".idx"}
    ):
        raise ValueError("Git object store contains incomplete or unsupported pack files")
    verifier = root / "verify"
    destination = verifier / "objects/pack"
    destination.mkdir(parents=True)
    (verifier / "refs").mkdir()
    (verifier / "HEAD").write_text("ref: refs/heads/unused\n", encoding="ascii")
    (verifier / "config").write_text("[core]\nrepositoryformatversion = 0\nbare = true\n", encoding="ascii")
    for path in entries:
        target = destination / path.name
        os.link(path, target, follow_symlinks=False)
        os.chown(target, 0, 0, follow_symlinks=False)
        target.chmod(0o444)
    os.chown(verifier, WORKER_UID, WORKER_UID)
    _bind(verifier, verifier)


def _custody(directory: str, base: str, head: str, deadline: str) -> None:
    limit = float(deadline)
    root = Path(directory) / "root"
    pending: set[str] = set()

    def stop(_signal: int, _frame: object) -> None:
        raise InterruptedError("Git custodian was stopped")

    signal.signal(signal.SIGTERM, stop)
    try:
        _sandbox(root, Path(directory) / "bridge")
        if _run_namespace(root, "fetch", base, head, limit, pending):
            raise ValueError("unexpected output from fetch worker")
        _command("/usr/bin/umount", str(root / "bridge"))
        _sealed_repository(root)
        _bind(root / "store", root / "store")
        print("FETCHED", flush=True)
        if sys.stdin.buffer.readline(8) != b"VERIFY\n":
            raise ValueError("verification was not authorized")
        evidence = json.loads(_run_namespace(root, "verify", base, head, limit, pending))
        print(json.dumps(evidence, ensure_ascii=False, separators=(",", ":")), flush=True)
    finally:
        if not pending:
            print("CLOSED", flush=True)


def _enter(directory: str, phase: str, base: str, head: str, deadline: str) -> None:
    if phase == "fetch":
        _command("/usr/sbin/ip", "link", "set", "lo", "up")
    identity = str(WORKER_UID)
    command = [
        "/usr/sbin/chroot",
        directory,
        "/usr/bin/setpriv",
        "--reuid",
        identity,
        "--regid",
        identity,
        "--clear-groups",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
        "/usr/bin/python3",
        "-IB",
        str(ROOT_RUNTIME / Path(__file__).name),
        phase,
        base,
        head,
        deadline,
    ]
    # Keep the trusted root PID 1 in the namespace throughout the worker's
    # privilege drop. Its death ends the namespace, including any descendants.
    subprocess.run(command, env=ENVIRONMENT, check=True, timeout=_remaining(float(deadline)))


if __name__ == "__main__":
    mode, *arguments = sys.argv[1:]
    match mode:
        case "custody":
            _custody(*arguments)
        case "enter":
            _enter(*arguments)
        case "fetch":
            base, head, deadline = arguments
            _fetch(base, head, float(deadline))
        case "verify":
            base, head, deadline = arguments
            _verify(base, head, float(deadline))
        case _:
            raise SystemExit("unsupported path feed phase")
