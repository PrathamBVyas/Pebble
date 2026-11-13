#!/usr/bin/env python3
"""One-run measurements for the LLS10 evidence checklist.

The password stretch is timed on its own. The folder operations below it
include that stretch, because each command unlocks again. The mount line is
only the write and fsync through the folder, after the mount is already up.

Run from the repository root, with the package installed:

    python scripts/bench.py
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from pebble.errors import PasswordError
from pebble.vault import Layout, commit, init, put, read_file, status

PASSWORD = b"bench-password"
MIB = 1024 * 1024


def main() -> None:
    root = Path(tempfile.mkdtemp(prefix="pebble-bench-"))
    try:
        rows = measure(root)
    finally:
        subprocess.run(["fusermount3", "-u", str(root / "mnt")], check=False, capture_output=True)
        shutil.rmtree(root, ignore_errors=True)
    machine = f"{platform.system()} {platform.release()} {platform.machine()}"
    distro = _distro()
    print(f"Machine: {machine}")
    print(f"Distribution: {distro}")
    print(f"Python: {platform.python_version()}")
    print(f"libfuse: {_fuse_version()}")
    print()
    print("| Measurement | Time | Detail |")
    print("| --- | ---: | --- |")
    for name, seconds, detail in rows:
        print(f"| {name} | {seconds:.3f} s | {detail} |")


def measure(root: Path) -> list[tuple[str, float, str]]:
    layout = Layout(root / "cipher", root / "state", root / "witness")
    init(layout, bytearray(PASSWORD))
    rows: list[tuple[str, float, str]] = []

    started = time.perf_counter()
    try:
        read_file(layout, bytearray(b"wrong-password"), "missing.txt")
    except PasswordError:
        pass
    rows.append(("Wrong password", time.perf_counter() - started, "clear refusal, Argon2id"))

    _write(layout, root, b"small", "note.txt")
    commit(layout, bytearray(PASSWORD))
    started = time.perf_counter()
    assert read_file(layout, bytearray(PASSWORD), "note.txt") == b"small"
    rows.append(("Open and read a small file", time.perf_counter() - started, "includes the password stretch"))

    for size in (1, 8):
        payload = b"x" * (size * MIB)
        started = time.perf_counter()
        _write(layout, root, payload, f"blob-{size}.bin")
        commit(layout, bytearray(PASSWORD))
        elapsed = time.perf_counter() - started
        rate = (size * MIB) / elapsed / MIB
        rows.append((f"Save {size} MiB", elapsed, f"{rate:.1f} MiB/s, put and commit"))
        started = time.perf_counter()
        assert read_file(layout, bytearray(PASSWORD), f"blob-{size}.bin") == payload
        elapsed = time.perf_counter() - started
        rate = (size * MIB) / elapsed / MIB
        rows.append((f"Read {size} MiB", elapsed, f"{rate:.1f} MiB/s, includes the password stretch"))

    target = _largest_object(layout.cipher / "objects")
    original = target.read_bytes()
    flipped = bytearray(original)
    flipped[-1] ^= 0x01
    target.write_bytes(flipped)
    started = time.perf_counter()
    try:
        read_file(layout, bytearray(PASSWORD), "blob-8.bin")
        detected = False
    except (PasswordError, Exception):
        detected = True
    elapsed = time.perf_counter() - started
    target.write_bytes(original)
    if not detected:
        raise SystemExit("tampered object was accepted")
    rows.append(("Tampered object", elapsed, "one flipped byte, read refused"))

    head = (layout.cipher / "HEAD").read_text()
    _write(layout, root, b"later", "later.txt")
    commit(layout, bytearray(PASSWORD))
    current = (layout.cipher / "HEAD").read_text()
    (layout.cipher / "HEAD").write_text(head)
    started = time.perf_counter()
    code, _text = status(layout, bytearray(PASSWORD))
    elapsed = time.perf_counter() - started
    (layout.cipher / "HEAD").write_text(current)
    if code != 2:
        raise SystemExit(f"rewind was not noticed, status {code}")
    rows.append(("Restored older HEAD", elapsed, "status exit 2, rewind"))

    fuse_write, fuse_read = _fuse(layout, root, 64 * MIB)
    rows.append(("Mount write 64 MiB and fsync", fuse_write, "one save, objects synced once then HEAD renamed"))
    rows.append(("Mount read 64 MiB", fuse_read, "after unmount and a fresh read-only mount"))
    return rows


def _write(layout: Layout, root: Path, payload: bytes, name: str) -> None:
    local = root / "local.bin"
    local.write_bytes(payload)
    put(layout, bytearray(PASSWORD), local, name)


def _largest_object(directory: Path) -> Path:
    files = [path for path in directory.rglob("*") if path.is_file()]
    return max(files, key=lambda path: path.stat().st_size)


def _fuse(layout: Layout, root: Path, size: int) -> tuple[float, float]:
    mountpoint = root / "mnt"
    mountpoint.mkdir()
    password = root / "password"
    password.write_bytes(PASSWORD)
    process = _mount(layout, mountpoint, password, read_write=True)
    try:
        _wait_mount(process, mountpoint)
        started = time.perf_counter()
        fd = os.open(mountpoint / "fuse.bin", os.O_CREAT | os.O_RDWR, 0o644)
        try:
            remaining = size
            chunk = b"y" * (1024 * 1024)
            while remaining:
                piece = chunk if remaining >= len(chunk) else chunk[:remaining]
                os.write(fd, piece)
                remaining -= len(piece)
            os.fsync(fd)
        finally:
            os.close(fd)
        write_s = time.perf_counter() - started
    finally:
        _unmount(mountpoint, process)
    if process.returncode != 0:
        raise SystemExit(process.stderr.read().decode() if process.stderr else "mount failed")

    process = _mount(layout, mountpoint, password, read_write=False)
    try:
        _wait_mount(process, mountpoint)
        _wait_file(process, mountpoint / "fuse.bin")
        started = time.perf_counter()
        fd = os.open(mountpoint / "fuse.bin", os.O_RDONLY)
        try:
            got = 0
            while True:
                block = os.read(fd, 1024 * 1024)
                if not block:
                    break
                got += len(block)
        finally:
            os.close(fd)
        read_s = time.perf_counter() - started
    finally:
        _unmount(mountpoint, process)
    if got != size:
        raise SystemExit(f"mount read returned {got} bytes")
    return write_s, read_s


def _mount(layout: Layout, mountpoint: Path, password: Path, *, read_write: bool) -> subprocess.Popen:
    command = [
        sys.executable,
        "-m",
        "pebble",
        "mount",
        str(layout.cipher),
        str(mountpoint),
        "--state",
        str(layout.state),
        "--witness",
        str(layout.witness),
        "--password-file",
        str(password),
    ]
    if read_write:
        command.append("--read-write")
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _wait_mount(process: subprocess.Popen, mountpoint: Path) -> None:
    for _ in range(100):
        if os.path.ismount(mountpoint):
            return
        if process.poll() is not None:
            err = process.stderr.read().decode() if process.stderr else ""
            raise SystemExit(err or "mount exited before it was ready")
        time.sleep(0.05)
    raise SystemExit("mount did not come up")


def _wait_file(process: subprocess.Popen, marker: Path) -> None:
    for _ in range(100):
        if marker.is_file():
            return
        if process.poll() is not None:
            err = process.stderr.read().decode() if process.stderr else ""
            raise SystemExit(err or "mount exited before the file appeared")
        time.sleep(0.05)
    raise SystemExit("mounted file did not appear")


def _unmount(mountpoint: Path, process: subprocess.Popen) -> None:
    subprocess.run(["fusermount3", "-u", str(mountpoint)], check=False)
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def _distro() -> str:
    text = Path("/etc/os-release").read_text()
    for line in text.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return "unknown"


def _fuse_version() -> str:
    try:
        out = subprocess.check_output(["fusermount3", "-V"], text=True, stderr=subprocess.STDOUT)
    except (OSError, subprocess.CalledProcessError) as exc:
        return str(exc)
    return out.strip().splitlines()[0]


if __name__ == "__main__":
    main()
