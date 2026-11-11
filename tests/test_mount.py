"""The read-only mount shows committed files and does not move HEAD."""

import os
import subprocess
import sys
import time
from pathlib import Path

from pebble.vault import Layout, commit, init, put


def test_readonly_mount_lists_and_reads(tmp_path: Path):
    layout = _vault(tmp_path)
    _put(layout, tmp_path, b"hello-mount", "hello.txt")
    _put(layout, tmp_path, b"nested-body", "dir/note.txt")
    commit(layout, bytearray(b"mount-password"))
    head = (layout.cipher / "HEAD").read_bytes()
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    process = _mount(layout, tmp_path, mountpoint)
    try:
        _wait_until_mounted(process, mountpoint / "hello.txt")
        assert sorted(os.listdir(mountpoint)) == ["dir", "hello.txt"]
        assert (mountpoint / "hello.txt").read_bytes() == b"hello-mount"
        assert sorted(os.listdir(mountpoint / "dir")) == ["note.txt"]
        assert (mountpoint / "dir" / "note.txt").read_bytes() == b"nested-body"
        missing = subprocess.run(
            ["ls", str(mountpoint / "missing")],
            check=False,
            capture_output=True,
            text=True,
        )
        assert missing.returncode != 0
        denied = subprocess.run(
            [
                sys.executable,
                "-c",
                "import pathlib,sys; pathlib.Path(sys.argv[1]).write_bytes(b'x')",
                str(mountpoint / "hello.txt"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        assert denied.returncode != 0
        assert (mountpoint / "hello.txt").read_bytes() == b"hello-mount"
        assert (layout.cipher / "HEAD").read_bytes() == head
    finally:
        subprocess.run(["fusermount3", "-u", str(mountpoint)], check=False)
        process.wait(timeout=10)
    assert process.returncode == 0, _output(process)
    assert (layout.cipher / "HEAD").read_bytes() == head


def test_rewind_refuses_to_mount(tmp_path: Path):
    layout = _vault(tmp_path)
    _put(layout, tmp_path, b"one", "one.txt")
    first = commit(layout, bytearray(b"mount-password"))
    _put(layout, tmp_path, b"two", "two.txt")
    commit(layout, bytearray(b"mount-password"))
    (layout.cipher / "HEAD").write_text(first + "\n")
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    process = _mount(layout, tmp_path, mountpoint)
    try:
        stdout, stderr = process.communicate(timeout=15)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    assert process.returncode == 2, stdout.decode() + stderr.decode()
    assert list(mountpoint.iterdir()) == []
    assert b"rewind" in stdout


def _vault(tmp_path: Path) -> Layout:
    layout = Layout(tmp_path / "cipher", tmp_path / "state", tmp_path / "witness")
    init(layout, bytearray(b"mount-password"))
    return layout


def _put(layout: Layout, tmp_path: Path, body: bytes, name: str) -> None:
    local = tmp_path / name.replace("/", "_")
    local.write_bytes(body)
    put(layout, bytearray(b"mount-password"), local, name)


def _mount(
    layout: Layout, tmp_path: Path, mountpoint: Path, *, read_write: bool = False
) -> subprocess.Popen:
    password = tmp_path / "password"
    password.write_text("mount-password")
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


def test_vim_rename_mkdir_and_unlink(tmp_path: Path):
    layout = _vault(tmp_path)
    _put(layout, tmp_path, b"before", "file.txt")
    commit(layout, bytearray(b"mount-password"))
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    process = _mount(layout, tmp_path, mountpoint, read_write=True)
    try:
        _wait_until_mounted(process, mountpoint / "file.txt")
        temporary = mountpoint / ".file.txt.swp"
        fd = os.open(temporary, os.O_CREAT | os.O_RDWR, 0o644)
        os.write(fd, b"after")
        os.fsync(fd)
        os.close(fd)
        os.rename(temporary, mountpoint / "file.txt")
        os.mkdir(mountpoint / "folder")
        note = mountpoint / "folder" / "gone.txt"
        fd = os.open(note, os.O_CREAT | os.O_RDWR, 0o644)
        os.write(fd, b"temp")
        os.fsync(fd)
        os.close(fd)
        os.unlink(note)
    finally:
        _unmount(mountpoint, process)
    assert process.returncode == 0, _output(process)
    reread = _mount(layout, tmp_path, mountpoint)
    try:
        _wait_until_mounted(reread, mountpoint / "file.txt")
        assert (mountpoint / "file.txt").read_bytes() == b"after"
        assert not temporary.exists()
        assert (mountpoint / "folder").is_dir()
        assert not note.exists()
    finally:
        _unmount(mountpoint, reread)
    assert reread.returncode == 0, _output(reread)


def test_kill_during_write_keeps_the_previous_save(tmp_path: Path):
    layout = _vault(tmp_path)
    _put(layout, tmp_path, b"previous-save", "one.txt")
    commit(layout, bytearray(b"mount-password"))
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    process = _mount(layout, tmp_path, mountpoint, read_write=True)
    writer = None
    try:
        _wait_until_mounted(process, mountpoint / "one.txt")
        writer = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import os,sys,time; fd=os.open(sys.argv[1], os.O_RDWR); "
                "os.write(fd, b'killed-write-should-not-land'); time.sleep(60)",
                str(mountpoint / "one.txt"),
            ]
        )
        time.sleep(0.5)
        os.kill(writer.pid, 9)
        writer.wait(timeout=5)
    finally:
        if writer is not None and writer.poll() is None:
            writer.kill()
            writer.wait(timeout=5)
        _unmount(mountpoint, process)
    reread = _mount(layout, tmp_path, mountpoint)
    try:
        _wait_until_mounted(reread, mountpoint / "one.txt")
        assert (mountpoint / "one.txt").read_bytes() == b"previous-save"
    finally:
        _unmount(mountpoint, reread)


def test_sixty_four_mib_round_trip(tmp_path: Path):
    layout = _vault(tmp_path)
    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    payload = bytes(64 * 1024 * 1024)
    process = _mount(layout, tmp_path, mountpoint, read_write=True)
    try:
        _wait_until_mounted(process, mountpoint)
        started = time.perf_counter()
        fd = os.open(mountpoint / "big.bin", os.O_CREAT | os.O_RDWR, 0o644)
        view = memoryview(payload)
        offset = 0
        while offset < len(view):
            offset += os.write(fd, view[offset : offset + 1024 * 1024])
        os.fsync(fd)
        os.close(fd)
        write_seconds = time.perf_counter() - started
    finally:
        _unmount(mountpoint, process)
    assert process.returncode == 0, _output(process)
    reread = _mount(layout, tmp_path, mountpoint)
    try:
        _wait_until_mounted(reread, mountpoint / "big.bin")
        started = time.perf_counter()
        found = (mountpoint / "big.bin").read_bytes()
        read_seconds = time.perf_counter() - started
        assert found == payload
    finally:
        _unmount(mountpoint, reread)
    print(f"64MiB write {write_seconds:.3f}s read {read_seconds:.3f}s")


def _unmount(mountpoint: Path, process: subprocess.Popen) -> None:
    subprocess.run(["fusermount3", "-u", str(mountpoint)], check=False)
    if process.poll() is None:
        process.wait(timeout=15)


def _wait_until_mounted(process: subprocess.Popen, marker: Path) -> None:
    mountpoint = marker if marker.is_dir() else marker.parent
    for _ in range(80):
        mounted = os.path.ismount(mountpoint)
        if mounted and (marker.is_dir() or marker.exists()):
            return
        if process.poll() is not None:
            raise AssertionError(_output(process))
        time.sleep(0.1)
    raise AssertionError("mount did not show the committed file\n" + _output(process))


def _output(process: subprocess.Popen) -> str:
    stdout, stderr = process.communicate()
    return stdout.decode() + stderr.decode()
