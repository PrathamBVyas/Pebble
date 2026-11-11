"""The cipher directory can be copied. Memory of it stays outside."""

import subprocess
import sys
from pathlib import Path

import pytest

from pebble.errors import PasswordError
from pebble.vault import Layout, commit, init, ls, put, read_file, status


def _layout(tmp_path: Path) -> Layout:
    return Layout(tmp_path / "cipher", tmp_path / "state", tmp_path / "witness")


def _password() -> bytearray:
    return bytearray(b"test-password")


def _write(directory: Path, name: str, text: bytes) -> Path:
    path = directory / name
    path.write_bytes(text)
    return path


def test_put_commit_and_reload(tmp_path: Path):
    layout = _layout(tmp_path)
    init(layout, _password())
    put(layout, _password(), _write(tmp_path, "local", b"alpha-bytes"), "notes/alpha.txt")
    assert ls(layout, _password(), "notes") == ["alpha.txt"]
    commit(layout, _password())
    assert read_file(layout, _password(), "notes/alpha.txt") == b"alpha-bytes"
    stored = b"".join(
        path.read_bytes() for path in (layout.cipher / "objects").rglob("*") if path.is_file()
    )
    assert b"alpha-bytes" not in stored


def test_password_buffer_is_wiped(tmp_path: Path):
    password = bytearray(b"secret-password")
    init(_layout(tmp_path), password)
    assert password == bytearray(len(b"secret-password"))


def test_wrong_password(tmp_path: Path):
    layout = _layout(tmp_path)
    init(layout, _password())
    with pytest.raises(PasswordError, match="^wrong password$"):
        ls(layout, bytearray(b"not-the-password"))


def test_rewind_names_the_hidden_head_and_split_writes_a_receipt(tmp_path: Path):
    layout = _layout(tmp_path)
    init(layout, _password())
    put(layout, _password(), _write(tmp_path, "one", b"one"), "one.txt")
    first = commit(layout, _password())
    snap = tmp_path / "snap"
    _copy_tree(layout.cipher, snap)
    put(layout, _password(), _write(tmp_path, "two", b"two"), "two.txt")
    second = commit(layout, _password())

    fresh = Layout(snap, tmp_path / "state2", tmp_path / "witness2")
    (fresh.witness).mkdir()
    (fresh.witness / "log").write_bytes(b"")
    code, text = status(fresh, _password())
    assert code == 0 and text == f"update {first}"
    fresh = Layout(layout.cipher, fresh.state, fresh.witness)
    code, text = status(fresh, _password())
    assert code == 0 and text == f"update {second}"

    (layout.cipher / "HEAD").write_text(snap.joinpath("HEAD").read_text())
    code, text = status(fresh, _password())
    assert code == 2
    assert text.startswith(f"rewind {second} ")

    (layout.cipher / "HEAD").write_text(second + "\n")
    side = Layout(layout.cipher, tmp_path / "side-state", tmp_path / "side-witness")
    side.witness.mkdir()
    (side.witness / "log").write_bytes(b"")
    seen = Layout(snap, side.state, side.witness)
    assert status(seen, _password())[0] == 0
    (layout.cipher / "HEAD").write_text(first + "\n")
    put(side, _password(), _write(tmp_path, "side", b"side"), "side.txt")
    sibling = commit(side, _password())
    code, text = status(fresh, _password())
    assert code == 3
    lines = text.splitlines()
    assert lines[0] == f"split {second} {sibling}"
    receipt = Path(lines[1])
    empty = tmp_path / "empty"
    empty.mkdir()
    completed = subprocess.run(
        [sys.executable, "-m", "pebble", "verify-proof", str(receipt)],
        check=False,
        cwd=empty,
        capture_output=True,
        text=True,
        env={"PATH": "/usr/bin:/bin"},
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.splitlines() == ["fork", second, sibling]


def test_missing_witness_refuses_open(tmp_path: Path):
    layout = _layout(tmp_path)
    init(layout, _password())
    (layout.witness / "log").unlink()
    with pytest.raises(Exception, match="witness log is missing"):
        status(layout, _password())


def _copy_tree(source: Path, dest: Path) -> None:
    import shutil

    shutil.copytree(source, dest)
