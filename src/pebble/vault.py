"""A cipher directory, a local accepted set, and a witness log.

The cipher directory is the folder a provider can replace: encrypted objects,
signed commits, HEAD, and the password keybag. The accepted hashes and the
witness log live outside it. Copying the cipher directory does not copy the
record of what this device has already seen.

status is the open check. An update is remembered and witnessed. A rewind
refuses to move forward. A split writes a receipt and leaves the accepted
head where it was.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from dataclasses import dataclass
from pathlib import Path

from pebble.commit import create_commit, load_commit
from pebble.errors import AuthenticationError, FormatError
from pebble.history import classify
from pebble.keybag import Keybag
from pebble.receipt import write_receipt
from pebble.seal import seal
from pebble.secret import wipe_buffer
from pebble.store import Kind, Store
from pebble.tree import Dir, load, save
from pebble.witness import append_view, read_views

EXIT_OK = 0
EXIT_REWIND = 2
EXIT_SPLIT = 3


class VaultError(Exception):
    """The vault command cannot do what was asked."""


@dataclass(frozen=True)
class Layout:
    """Where this device keeps the folder, its memory, and its witness log."""

    cipher: Path
    state: Path
    witness: Path

    @property
    def store(self) -> Store:
        return Store(self.cipher / "objects")


def init(layout: Layout, password: bytearray) -> str:
    """Create an empty vault and sign the first commit. Returns its id."""
    if (layout.cipher / "HEAD").exists():
        raise VaultError("vault is already initialized")
    layout.cipher.mkdir(parents=True, exist_ok=True)
    layout.state.mkdir(parents=True, exist_ok=True)
    layout.witness.mkdir(parents=True, exist_ok=True)
    blob, opened = Keybag.create(password)
    root_key = bytearray(secrets.token_bytes(32))
    try:
        _atomic_write(layout.cipher / "keybag", blob)
        _atomic_write(layout.cipher / "root.seal", seal(opened.exchange_public, bytes(root_key)))
        listing = save(layout.store, Dir(), bytes(root_key), sync=False)
        commit_id = _sign_and_store(layout, opened, parents=(), listing=listing, sync=False)
        _durable_head(layout, commit_id)
        _accept(layout, commit_id)
        _witness(layout, opened, commit_id)
        return commit_id
    finally:
        wipe_buffer(root_key)
        opened.close()


def put(layout: Layout, password: bytearray, local: Path, vault_path: str) -> None:
    """Stage a file into the cipher directory. HEAD does not move."""
    data = Path(local).read_bytes()
    with _session(layout, password) as (opened, root_key):
        del opened
        directory = _editable(layout, root_key)
        _place(directory, _parts(vault_path), data)
        listing = save(layout.store, directory, bytes(root_key), sync=False)
        layout.store.sync()
        _atomic_write(layout.cipher / "STAGED", (listing + "\n").encode())


def ls(layout: Layout, password: bytearray, vault_path: str = "") -> list[str]:
    """Names in one directory. A trailing slash marks a directory."""
    with _session(layout, password) as (opened, root_key):
        del opened
        directory = _editable(layout, root_key)
        node = _walk(directory, vault_path)
        names = [name + "/" for name in sorted(node.dirs)]
        names.extend(sorted(node.files))
        return names


def read_file(layout: Layout, password: bytearray, vault_path: str) -> bytes:
    """Read one staged or committed file."""
    with _session(layout, password) as (opened, root_key):
        del opened
        directory = _editable(layout, root_key)
        parts = _parts(vault_path)
        node = directory
        for part in parts[:-1]:
            node = _child_dir(node, part)
        name = parts[-1]
        if name not in node.files:
            raise VaultError("path is not a file")
        return bytes(node.files[name])


def commit(layout: Layout, password: bytearray) -> str:
    """Sign the staged listing, then move HEAD. Returns the new commit id."""
    staged_path = layout.cipher / "STAGED"
    if not staged_path.is_file():
        raise VaultError("nothing to commit")
    listing = _hash_line(staged_path, "STAGED")
    with _session(layout, password) as (opened, root_key):
        del root_key
        commit_id = commit_listing(layout, opened, listing)
        staged_path.unlink()
        return commit_id


def status(layout: Layout, password: bytearray, *, allow_unwitnessed: bool = False) -> tuple[int, str]:
    """Classify HEAD. Update remembers the tip. Rewind and split do not."""
    with _session(layout, password) as (opened, root_key):
        del root_key
        code, message, _shown = _judge(layout, opened, allow_unwitnessed=allow_unwitnessed)
        return code, message


def open_committed(
    layout: Layout, password: bytearray, *, allow_unwitnessed: bool = False
) -> tuple[int, str, Dir | None]:
    """Classify HEAD and decrypt the tree a mount may show.

    A rewind returns no tree. An update shows the tip. A split shows the
    accepted head, not the forked tip. File bodies are bytearrays so the
    caller can wipe them.
    """
    with _session(layout, password) as (opened, root_key):
        code, message, shown = _judge(layout, opened, allow_unwitnessed=allow_unwitnessed)
        if shown is None:
            return code, message, None
        listing = load_commit(layout.store, shown).listing.hex()
        directory = load(layout.store, listing, bytes(root_key))
        _own_tree(directory)
        return code, message, directory


def wipe_directory(directory: Dir) -> None:
    """Overwrite file bodies held in a tree returned by open_committed."""
    for name, data in list(directory.files.items()):
        if isinstance(data, bytearray):
            wipe_buffer(data)
        directory.files[name] = b""
    for child in directory.dirs.values():
        wipe_directory(child)


def _judge(layout: Layout, opened, *, allow_unwitnessed: bool) -> tuple[int, str, str | None]:
    """Return the status code, the message, and the commit a mount should show."""
    tips = _read_tips(layout)
    if not tips:
        raise VaultError("HEAD is missing")
    accepted = set(_read_accepted(layout))
    witnessed = set(read_views(layout.witness / "log", required=not allow_unwitnessed))
    parents = _parent_map(layout.store, set(tips) | accepted | witnessed)
    verdict = classify(
        accepted=accepted,
        witnessed=witnessed,
        tips=set(tips),
        parents=parents,
    )
    if verdict.kind == "update":
        _accept(layout, verdict.head)
        _witness(layout, opened, verdict.head)
        return EXIT_OK, f"update {verdict.head}", verdict.head
    if verdict.kind == "rewind":
        stale = verdict.others[0] if verdict.others else tips[0]
        return EXIT_REWIND, f"rewind {verdict.head} {stale}", None
    other = _split_other(verdict.head, tips, verdict.others)
    receipt = layout.state / "receipt"
    write_receipt(receipt, _commit_blob(layout, verdict.head), _commit_blob(layout, other))
    text = f"split {verdict.head} {other}\n{receipt}"
    return EXIT_SPLIT, text, verdict.head


def _own_tree(directory: Dir) -> None:
    for name, data in list(directory.files.items()):
        directory.files[name] = bytearray(data)
    for child in directory.dirs.values():
        _own_tree(child)


def commit_listing(layout: Layout, opened, listing: str) -> str:
    """Sign one listing, sync the new objects once, and rename HEAD."""
    parent = _read_head(layout)
    parents = (parent,) if parent else ()
    commit_id = _sign_and_store(layout, opened, parents=parents, listing=listing, sync=False)
    _durable_head(layout, commit_id)
    _accept(layout, commit_id)
    _witness(layout, opened, commit_id)
    return commit_id


def commit_directory(layout: Layout, opened, root_key: bytearray, directory: Dir) -> str:
    """Seal a tree and publish it as one save."""
    listing = save(layout.store, directory, bytes(root_key), sync=False)
    return commit_listing(layout, opened, listing)


def _sign_and_store(
    layout: Layout, opened, *, parents: tuple[str, ...], listing: str, sync: bool
) -> str:
    seed = opened._copy_signing()
    try:
        blob = create_commit(parents=parents, listing=listing, seed=seed)
    finally:
        wipe_buffer(seed)
    return layout.store.put(blob, kind=Kind.META, sync=sync)


def _session(layout: Layout, password: bytearray):
    return _Unlock(layout, password)


class _Unlock:
    def __init__(self, layout: Layout, password: bytearray) -> None:
        self._layout = layout
        self._password = password
        self._opened = None
        self._root_key = bytearray()

    def __enter__(self):
        blob = (self._layout.cipher / "keybag").read_bytes()
        self._opened = Keybag.unlock(self._password, blob)
        try:
            sealed = (self._layout.cipher / "root.seal").read_bytes()
            self._root_key = bytearray(self._opened.open_sealed(sealed))
        except Exception:
            self._opened.close()
            self._opened = None
            raise
        return self._opened, self._root_key

    def __exit__(self, exc_type, exc, tb) -> None:
        wipe_buffer(self._root_key)
        if self._opened is not None:
            self._opened.close()
            self._opened = None


def _editable(layout: Layout, root_key: bytearray) -> Dir:
    staged = layout.cipher / "STAGED"
    if staged.is_file():
        return load(layout.store, _hash_line(staged, "STAGED"), bytes(root_key))
    head = _read_head(layout)
    if head is None:
        return Dir()
    listing = load_commit(layout.store, head).listing.hex()
    return load(layout.store, listing, bytes(root_key))


def _place(directory: Dir, parts: tuple[str, ...], data: bytes) -> None:
    node = directory
    for part in parts[:-1]:
        if part in node.files:
            raise VaultError("path is not valid")
        child = node.dirs.get(part)
        if child is None:
            child = Dir()
            node.dirs[part] = child
        node = child
    name = parts[-1]
    if name in node.dirs:
        raise VaultError("path is not valid")
    node.files[name] = data


def _walk(directory: Dir, vault_path: str) -> Dir:
    node = directory
    if vault_path:
        for part in _parts(vault_path):
            node = _child_dir(node, part)
    return node


def _child_dir(directory: Dir, name: str) -> Dir:
    child = directory.dirs.get(name)
    if child is None:
        raise VaultError("path is missing")
    return child


def _parts(vault_path: str) -> tuple[str, ...]:
    if not isinstance(vault_path, str) or not vault_path or vault_path.startswith("/"):
        raise VaultError("path is not valid")
    parts = tuple(vault_path.split("/"))
    if any(part in ("", ".", "..", "...") for part in parts):
        raise VaultError("path is not valid")
    return parts


def _read_head(layout: Layout) -> str | None:
    path = layout.cipher / "HEAD"
    if not path.is_file():
        return None
    return _hash_line(path, "HEAD")


def _read_tips(layout: Layout) -> list[str]:
    head = _read_head(layout)
    if head is None:
        return []
    tips = [head]
    for path in sorted(layout.cipher.glob("HEAD.*")):
        if path.is_file():
            tips.append(_hash_line(path, path.name))
    return tips


def _durable_head(layout: Layout, commit_id: str) -> None:
    """One filesystem sync, then rename HEAD onto the new commit."""
    path = layout.cipher / "HEAD"
    fd, tmp_name = tempfile.mkstemp(prefix=".pebble-tmp-", dir=layout.cipher)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write((commit_id + "\n").encode())
            handle.flush()
        layout.store.sync()
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    directory = os.open(layout.cipher, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _accept(layout: Layout, commit_id: str) -> None:
    seen = _read_accepted(layout)
    if commit_id not in seen:
        seen.append(commit_id)
    layout.state.mkdir(parents=True, exist_ok=True)
    body = ("\n".join(seen) + "\n").encode()
    _atomic_write(layout.state / "accepted", body)


def _read_accepted(layout: Layout) -> list[str]:
    path = layout.state / "accepted"
    if not path.is_file():
        return []
    lines = []
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped:
            lines.append(_hash_line_text(stripped, "accepted"))
    return lines


def _witness(layout: Layout, opened, commit_id: str) -> None:
    append_view(
        layout.witness / "log",
        commit_id,
        opened.signing_public,
        opened.sign,
    )


def _parent_map(store: Store, seeds: set[str]) -> dict[str, tuple[str, ...]]:
    parents: dict[str, tuple[str, ...]] = {}
    stack = [item for item in seeds if item]
    while stack:
        node = stack.pop()
        if node in parents:
            continue
        try:
            commit = load_commit(store, node)
        except (FormatError, AuthenticationError):
            continue
        links = tuple(parent.hex() for parent in commit.parents)
        parents[node] = links
        stack.extend(links)
    return parents


def _split_other(head: str, tips: list[str], others: tuple[str, ...]) -> str:
    for tip in tips:
        if tip != head:
            return tip
    for other in others:
        if other != head:
            return other
    raise VaultError("split has no second head")


def _commit_blob(layout: Layout, commit_id: str) -> bytes:
    return layout.store.get(commit_id, kind=Kind.META)


def _hash_line(path: Path, label: str) -> str:
    return _hash_line_text(path.read_text().strip(), label)


def _hash_line_text(text: str, label: str) -> str:
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise FormatError(f"{label} is not valid")
    return text


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".pebble-tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
