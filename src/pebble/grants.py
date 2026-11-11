"""Folder grants and the rule that a removed share cannot come back.

A grant seals one directory key to one member and names the listing that
key opens. The seal and the listing id are inside the signed commit. After
a listing id changes, an older id for that path is refused. After a seal
is dropped, those same bytes are refused if a later commit carries them again.
"""

from __future__ import annotations

from pebble.commit import Grant, load_commit
from pebble.errors import AuthenticationError, FormatError
from pebble.seal import seal
from pebble.store import Store
from pebble.volume import VDir, load_volume, walk


def check_grant_history(store: Store, tip: str) -> None:
    """Refuse a chain that restores a listing id or a seal that already moved on."""
    chain: list = []
    seen: set[str] = set()
    current = tip
    while current:
        if current in seen:
            raise FormatError("commit chain is cyclic")
        seen.add(current)
        commit = load_commit(store, current)
        chain.append(commit)
        if not commit.parents:
            break
        current = commit.parents[0].hex()
    chain.reverse()
    listing_history: dict[bytes, list[bytes]] = {}
    dropped: set[bytes] = set()
    previous: dict[bytes, dict[bytes, bytes]] = {}
    for commit in chain:
        current_seals: dict[bytes, dict[bytes, bytes]] = {}
        listings: dict[bytes, bytes] = {}
        for grant in commit.grants:
            current_seals.setdefault(grant.path, {})[grant.recipient] = grant.sealed
            listings[grant.path] = grant.listing
            if grant.sealed in dropped:
                raise FormatError("grant history is not valid")
        for path, listing in listings.items():
            history = listing_history.setdefault(path, [])
            if listing in history and history[-1] != listing:
                raise FormatError("grant history is not valid")
            if not history or history[-1] != listing:
                history.append(listing)
        for path, recipients in previous.items():
            now = current_seals.get(path, {})
            for sealed in recipients.values():
                if sealed not in now.values():
                    dropped.add(sealed)
        previous = current_seals


def grants_for(
    previous: tuple[Grant, ...],
    root: VDir,
    opened,
    path: str,
    *,
    recipients: set[bytes],
) -> tuple[Grant, ...]:
    """Seals for one folder, plus the grants for every other path.

    recipients is the full set of exchange public keys that should still
    open this folder, including the owner. A new key is sealed again. An
    unchanged key keeps the boxes it already has.
    """
    if not path:
        raise FormatError("grant path is not valid")
    try:
        folder = walk(root, path)
    except KeyError as exc:
        raise FormatError("grant path is not valid") from exc
    if folder.listing_id is None:
        raise FormatError("grant path is not valid")
    path_bytes = path.encode("utf-8")
    listing = bytes.fromhex(folder.listing_id)
    key = bytes(folder.key)
    kept = {
        grant.recipient: grant
        for grant in previous
        if grant.path == path_bytes and grant.recipient in recipients
    }
    owner = opened.exchange_public
    owner_grant = kept.get(owner)
    owner_matches = owner_grant is not None and _opens_to(opened, owner_grant.sealed, key)
    fresh: list[Grant] = [grant for grant in previous if grant.path != path_bytes]
    for recipient in sorted(recipients):
        existing = kept.get(recipient)
        if owner_matches and existing is not None and existing.listing == listing:
            sealed = existing.sealed
        elif owner_matches and existing is not None and recipient != owner:
            sealed = existing.sealed
        else:
            sealed = seal(recipient, key)
        fresh.append(Grant(path_bytes, listing, recipient, sealed))
    return tuple(fresh)


def member_keys(store: Store, tip: str, opened) -> dict[bytes, tuple[bytes, bytes]]:
    """Newest listing each path this member can still decrypt.

    The map is path bytes to (listing id, listing key). A newer commit that
    no longer seals the path to this member leaves the older listing in reach.
    """
    found: dict[bytes, tuple[bytes, bytes]] = {}
    seen: set[str] = set()
    current = tip
    while current:
        if current in seen:
            raise FormatError("commit chain is cyclic")
        seen.add(current)
        commit = load_commit(store, current)
        for grant in commit.grants:
            if grant.path in found or grant.recipient != opened.exchange_public:
                continue
            try:
                key = opened.open_sealed(grant.sealed)
            except AuthenticationError:
                continue
            found[grant.path] = (grant.listing, key)
        if not commit.parents:
            break
        current = commit.parents[0].hex()
    return found


def member_volume(store: Store, tip: str, opened) -> VDir:
    """A tree of only the folders this member can decrypt."""
    root = VDir(b"\x00" * 32)
    for path, (listing, key) in member_keys(store, tip, opened).items():
        node = load_volume(store, listing.hex(), key)
        _graft(root, path.decode("utf-8"), node)
    return root


def _graft(root: VDir, path: str, node: VDir) -> None:
    cursor = root
    parts = path.split("/")
    for part in parts[:-1]:
        child = cursor.dirs.get(part)
        if not isinstance(child, VDir):
            child = VDir(b"\x00" * 32)
            cursor.dirs[part] = child
        cursor = child
    cursor.dirs[parts[-1]] = node


def _opens_to(opened, sealed: bytes, key: bytes) -> bool:
    try:
        opened_key = opened.open_sealed(sealed)
    except AuthenticationError:
        return False
    return opened_key == key
