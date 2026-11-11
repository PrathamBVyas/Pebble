"""Paste an older grant list onto a child of HEAD.

This is the folder provider putting the old share back. A device that
already accepted the removal refuses the result.
"""

import os
import sys
from pathlib import Path

from pebble.commit import create_granted_commit, load_commit
from pebble.keybag import Keybag
from pebble.secret import wipe_buffer
from pebble.store import Kind, Store


def main() -> None:
    cipher = Path(os.environ["PEBBLE_CIPHER"])
    password = bytearray(Path(os.environ["PEBBLE_PASSWORD_FILE"]).read_bytes())
    if password.endswith(b"\n"):
        del password[-1]
    old_id = sys.argv[1]
    store = Store(cipher / "objects")
    old = load_commit(store, old_id)
    head = (cipher / "HEAD").read_text().strip()
    current = load_commit(store, head)
    opened = Keybag.unlock(password, (cipher / "keybag").read_bytes())
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
    (cipher / "HEAD").write_text(forged + "\n")
    print(forged)


if __name__ == "__main__":
    main()
