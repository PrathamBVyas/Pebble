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


def _mount(layout: Layout, tmp_path: Path, mountpoint: Path) -> subprocess.Popen:
    password = tmp_path / "password"
    password.write_text("mount-password")
    return subprocess.Popen(
        [
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
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def _wait_until_mounted(process: subprocess.Popen, marker: Path) -> None:
    for _ in range(50):
        if marker.exists():
            return
        if process.poll() is not None:
            raise AssertionError(_output(process))
        time.sleep(0.1)
    raise AssertionError("mount did not show the committed file\n" + _output(process))


def _output(process: subprocess.Popen) -> str:
    stdout, stderr = process.communicate()
    return stdout.decode() + stderr.decode()
