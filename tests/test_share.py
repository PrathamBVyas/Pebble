"""One folder is shared. Revoke keeps the old file and hides the new one."""

import subprocess
import sys
import time
from pathlib import Path

from pebble.commit import create_granted_commit, load_commit
from pebble.keybag import Keybag
from pebble.secret import wipe_buffer
from pebble.store import Kind, Store
from pebble.vault import EXIT_GRANT, Layout, add_user, commit, init, keygen, put, revoke, share, status


def test_share_revoke_and_restored_grants(tmp_path: Path):
    layout = Layout(tmp_path / "cipher", tmp_path / "state", tmp_path / "witness")
    init(layout, bytearray(b"alice-password"))
    _put(layout, tmp_path, b"secret-bytes", "private/secret.txt")
    _put(layout, tmp_path, b"old-bytes", "shared/old.txt")
    commit(layout, bytearray(b"alice-password"))
    bob_key = tmp_path / "bob.keybag"
    bob_pub = tmp_path / "bob.pub"
    keygen(bytearray(b"bob-password"), bob_key, bob_pub)
    add_user(layout, bytearray(b"alice-password"), "bob", bob_key, bob_pub)
    shared = share(layout, bytearray(b"alice-password"), "shared", "bob")
    _put(layout, tmp_path, b"extra-bytes", "shared/extra.txt")
    commit(layout, bytearray(b"alice-password"))

    mountpoint = tmp_path / "mnt"
    mountpoint.mkdir()
    bob = _mount(layout, tmp_path, mountpoint, keybag=layout.cipher / "keybags" / "bob", password=b"bob-password")
    try:
        _wait(bob, mountpoint / "shared" / "extra.txt")
        assert (mountpoint / "shared" / "old.txt").read_bytes() == b"old-bytes"
        assert (mountpoint / "shared" / "extra.txt").read_bytes() == b"extra-bytes"
        missing = subprocess.run(["ls", str(mountpoint / "private")], check=False, capture_output=True)
        assert missing.returncode != 0
    finally:
        _unmount(mountpoint, bob)

    revoke(layout, bytearray(b"alice-password"), "shared", "bob")
    _put(layout, tmp_path, b"new-bytes", "shared/new.txt")
    commit(layout, bytearray(b"alice-password"))
    bob = _mount(layout, tmp_path, mountpoint, keybag=layout.cipher / "keybags" / "bob", password=b"bob-password")
    try:
        _wait(bob, mountpoint / "shared" / "old.txt")
        assert (mountpoint / "shared" / "old.txt").read_bytes() == b"old-bytes"
        assert (mountpoint / "shared" / "extra.txt").read_bytes() == b"extra-bytes"
        assert not (mountpoint / "shared" / "new.txt").exists()
        assert not (mountpoint / "private").exists()
    finally:
        _unmount(mountpoint, bob)

    _restore_old_grants(layout, shared)
    code, text = status(layout, bytearray(b"alice-password"))
    assert code == EXIT_GRANT
    assert text == "grant history is not valid"
    alice = _mount(layout, tmp_path, mountpoint, password=b"alice-password")
    try:
        _wait(alice, mountpoint / "shared" / "new.txt")
        assert (mountpoint / "shared" / "old.txt").read_bytes() == b"old-bytes"
        assert (mountpoint / "shared" / "new.txt").read_bytes() == b"new-bytes"
        assert (mountpoint / "private" / "secret.txt").read_bytes() == b"secret-bytes"
    finally:
        _unmount(mountpoint, alice)


def _restore_old_grants(layout: Layout, old_commit: str) -> None:
    store = Store(layout.cipher / "objects")
    old = load_commit(store, old_commit)
    head = (layout.cipher / "HEAD").read_text().strip()
    current = load_commit(store, head)
    opened = Keybag.unlock(bytearray(b"alice-password"), (layout.cipher / "keybag").read_bytes())
    seed = opened._copy_signing()
    try:
        blob = create_granted_commit(
            parents=(head,),
            listing=current.listing.hex(),
            seed=seed,
            grants=old.grants,
        )
    finally:
        wipe_buffer(seed)
        opened.close()
    forged = store.put(blob, kind=Kind.META)
    (layout.cipher / "HEAD").write_text(forged + "\n")


def _put(layout: Layout, tmp_path: Path, body: bytes, name: str) -> None:
    local = tmp_path / name.replace("/", "_")
    local.write_bytes(body)
    put(layout, bytearray(b"alice-password"), local, name)


def _mount(layout, tmp_path, mountpoint, *, password: bytes, keybag: Path | None = None):
    password_file = tmp_path / "password"
    password_file.write_bytes(password)
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
        str(password_file),
    ]
    if keybag is not None:
        command.extend(["--keybag", str(keybag)])
    return subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _wait(process, marker: Path) -> None:
    for _ in range(80):
        if marker.exists():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            raise AssertionError(stdout.decode() + stderr.decode())
        time.sleep(0.1)
    stdout, stderr = process.communicate()
    raise AssertionError(stdout.decode() + stderr.decode())


def _unmount(mountpoint: Path, process) -> None:
    subprocess.run(["fusermount3", "-u", str(mountpoint)], check=False)
    if process.poll() is None:
        process.wait(timeout=15)
