"""Password change, a restored keybag, and a removed member."""

from pathlib import Path

import pytest

from pebble.errors import PasswordError
from pebble.grants import member_volume
from pebble.keybag import Keybag
from pebble.vault import (
    Layout,
    VaultError,
    add_user,
    change_keybag,
    change_password,
    commit,
    init,
    keygen,
    put,
    read_file,
    remove_user,
)
from pebble.volume import VDir, wipe_volume


def _layout(tmp_path: Path) -> Layout:
    return Layout(tmp_path / "cipher", tmp_path / "state", tmp_path / "witness")


def _put(layout: Layout, tmp_path: Path, body: bytes, name: str) -> None:
    local = tmp_path / name.replace("/", "_")
    local.write_bytes(body)
    put(layout, bytearray(b"alice-password"), local, name)


def _flatten(node: VDir, prefix: str = "") -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    for name, data in node.files.items():
        found[f"{prefix}{name}"] = bytes(data)
    for name, child in node.dirs.items():
        if isinstance(child, VDir):
            found.update(_flatten(child, f"{prefix}{name}/"))
    return found


def _member_files(layout: Layout, keybag: Path, password: bytes) -> dict[str, bytes]:
    opened = Keybag.unlock(bytearray(password), keybag.read_bytes())
    volume = None
    try:
        head = (layout.cipher / "HEAD").read_text().strip()
        volume = member_volume(layout.store, head, opened)
        return _flatten(volume)
    finally:
        opened.close()
        if volume is not None:
            wipe_volume(volume)


def test_owner_password_change(tmp_path: Path):
    layout = _layout(tmp_path)
    init(layout, bytearray(b"old-password"))
    local = tmp_path / "notes.txt"
    local.write_bytes(b"kept")
    put(layout, bytearray(b"old-password"), local, "notes.txt")
    commit(layout, bytearray(b"old-password"))
    old_blob = (layout.cipher / "keybag").read_bytes()

    change_password(layout, bytearray(b"old-password"), bytearray(b"new-password"))
    assert read_file(layout, bytearray(b"new-password"), "notes.txt") == b"kept"
    with pytest.raises(PasswordError, match="^wrong password$"):
        read_file(layout, bytearray(b"old-password"), "notes.txt")

    (layout.cipher / "keybag").write_bytes(old_blob)
    with pytest.raises(PasswordError, match="^wrong password$"):
        read_file(layout, bytearray(b"new-password"), "notes.txt")
    with pytest.raises(VaultError, match="^keybag was replaced$"):
        read_file(layout, bytearray(b"old-password"), "notes.txt")


def test_member_keybag_password_change(tmp_path: Path):
    keybag = tmp_path / "bob.keybag"
    public = tmp_path / "bob.pub"
    keygen(bytearray(b"bob-old"), keybag, public)
    change_keybag(keybag, bytearray(b"bob-old"), bytearray(b"bob-new"))
    opened = Keybag.unlock(bytearray(b"bob-new"), keybag.read_bytes())
    opened.close()
    with pytest.raises(PasswordError, match="^wrong password$"):
        Keybag.unlock(bytearray(b"bob-old"), keybag.read_bytes())


def test_each_member_reads_only_their_home_and_removal_hides_new_files(tmp_path: Path):
    layout = _layout(tmp_path)
    init(layout, bytearray(b"alice-password"))
    bob_key = tmp_path / "bob.keybag"
    bob_pub = tmp_path / "bob.pub"
    carol_key = tmp_path / "carol.keybag"
    carol_pub = tmp_path / "carol.pub"
    keygen(bytearray(b"bob-password"), bob_key, bob_pub)
    keygen(bytearray(b"carol-password"), carol_key, carol_pub)
    add_user(layout, bytearray(b"alice-password"), "bob", bob_key, bob_pub)
    add_user(layout, bytearray(b"alice-password"), "carol", carol_key, carol_pub)
    _put(layout, tmp_path, b"bob-old", "home/bob/old.txt")
    commit(layout, bytearray(b"alice-password"))
    _put(layout, tmp_path, b"carol-own", "home/carol/own.txt")
    _put(layout, tmp_path, b"alice-own", "private/secret.txt")
    commit(layout, bytearray(b"alice-password"))

    bob_files = _member_files(layout, layout.cipher / "keybags" / "bob", b"bob-password")
    carol_files = _member_files(layout, layout.cipher / "keybags" / "carol", b"carol-password")
    assert bob_files["home/bob/old.txt"] == b"bob-old"
    assert "home/carol/own.txt" not in bob_files
    assert "private/secret.txt" not in bob_files
    assert carol_files["home/carol/own.txt"] == b"carol-own"
    assert "home/bob/old.txt" not in carol_files

    remove_user(layout, bytearray(b"alice-password"), "bob")
    assert not (layout.cipher / "members" / "bob").exists()
    assert not (layout.cipher / "keybags" / "bob").exists()
    _put(layout, tmp_path, b"bob-new", "home/bob/new.txt")
    commit(layout, bytearray(b"alice-password"))

    bob_files = _member_files(layout, bob_key, b"bob-password")
    assert bob_files["home/bob/old.txt"] == b"bob-old"
    assert "home/bob/new.txt" not in bob_files
    assert read_file(layout, bytearray(b"alice-password"), "home/bob/new.txt") == b"bob-new"
    assert read_file(layout, bytearray(b"alice-password"), "private/secret.txt") == b"alice-own"
