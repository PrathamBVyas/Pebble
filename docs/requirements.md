# What the problem asks for, and what Pebble does

LLS10, VaultFS, asks for an encrypted folder that stays safe when the attacker controls every byte of the stored copy. The attacker can read, copy, edit, delete, and restore those bytes, and can keep old copies. They do not have the password, and they do not have the running system. A second account on the same machine is outside this problem.

How far each goal is taken is part of the design. This page says what Pebble does for each one.

## Work like a real folder

`pebble mount` serves the committed files through FUSE. `ls`, `cat`, `cp`, and an editor run against that folder with no special library. With `--read-write`, a program writes the way it writes any other folder. A save is published on fsync, and when a rename, unlink, rmdir, or mkdir finishes. The same tree is available from `put`, `ls`, and `commit` when a mount is not wanted.

## Give nothing useful away

File bodies are split into 64 KiB chunks and sealed with XChaCha20-Poly1305 under a per-file key. Directory listings, which hold names and the keys of their children, are sealed the same way. The password never goes to disk. It stretches with Argon2id into a key that wraps the device keys. A search of the cipher directory does not find the plaintext of a file that was stored.

What does stay readable is the shape of the history: commit parents, the listing hash, the author public key, and the fact that a share exists. The problem allows that trade. The bytes of the files stay sealed.

## Catch tampering

A flipped byte fails the authentication tag on a chunk or a listing, or the signature on a commit, before any of those bytes are treated as contents, names, or parent pointers. `status` and the mount take the failure as a refusal. The benchmark flips one byte of a stored object and the following read is refused.

## Notice an old copy

Every open compares the synced folder with the saves this computer has already accepted, and with an append-only log of saves it has seen. That log lives outside the synced folder, so replacing the folder does not erase it.

A later save is taken. An earlier save is refused, and the refusal names the newer save that the log still remembers. Two saves with no line between them are a split: the folder stays on the last accepted save, read-only, and a receipt is written. `verify-proof` checks that receipt with no password and no file keys. Putting yesterday's whole directory back is the rewind case. `tests/demo.sh` and `tests/handcopy.sh` do it by copying the directory.

## Protect the password

A wrong password is the sentence `wrong password`. The same sentence is used when the keybag's tag fails for any other reason, so the refusal does not tell those cases apart. Argon2id uses the OWASP minimum for this version: 19 MiB of memory, 2 iterations, parallelism 1. Costs other than those are refused before Argon2 runs.

`pebble passwd` wraps the same device keys with the new password and records the new keybag hash in the witness directory. On this computer the old password no longer opens the volume, and putting the previous keybag file back is refused.

An old snapshot of the keybag still unwraps with the old password, and those device keys still open data sealed to them. Password change does not re-encrypt file bodies or rotate directory keys. A machine that never recorded the new keybag hash will accept that old snapshot. The KDF is what makes a stolen keybag slow to guess. The witness note is what makes this computer notice that the keybag file moved backwards.

## More than one person

`keygen` makes a keybag and a public key for one person, under their own password. `add-user` copies those into the volume and creates `home/<name>`, sealed to that person and to the owner. `share` seals another folder to them. Files inside a shared folder are readable. A file path on its own is refused; the folder that holds the file is what gets shared.

A member's mount shows only the folders still sealed to them. Another member's home, and any folder that was never shared, does not appear. Reading the stored objects directly does not bypass that: the listing key is inside a seal they cannot open.

The person who created the volume holds the root listing key, so they can read the whole tree, including a member's home. Members do not hold that key.

`revoke` mints a new listing key for one folder and stops sealing it to that person. `remove-user` does this for every folder sealed to them, then deletes their keybag copy and their public key from the cipher directory. Files that were already in the old listing still open. Files written afterwards are in a listing they cannot open. File ciphertext is not rewritten.

If a later save pastes the old seal list back, the history check refuses it. A seal that has been dropped does not become valid again.

## Secrets while the program is running

Passwords and derived keys are `bytearray` values or a private `Secret` mapping. The mapping is locked with `mlock` when the kernel allows it, and marked `MADV_DONTDUMP` so a core dump skips it. A refused `mlock` does not skip the wipe. Close, a wrong password, and a failed command all overwrite the buffer with zeros through `memset` before returning. Commit signing copies the seed out for the signature and wipes that copy. The tests check that the caller's password buffer is zeros when `init` and `unlock` return.

## A crash does not throw away the last save

New objects are written and the filesystem is synced. `HEAD` is then renamed onto the new save. A crash before that rename leaves the previous `HEAD`. A writer killed during `write`, before fsync, does not publish. The mount test covers that case.

## Hostile bytes

The store refuses a chunk larger than 64 KiB plus its tag, and a metadata object larger than 1 MiB, before the body is parsed. Listings are decrypted and the tag is checked before any name or key field is read. Names longer than 255 bytes, names that contain `/` or NUL, the names `.`, `..`, and `...`, and a directory chain deeper than 32 are refused. A truncated object does not come back as file data. The commit signature is checked before parent hashes are followed.

There is no general fuzzer in this repository. The tests are the hostile cases above: truncated objects, flipped bytes, huge lengths, deep chains, and bad names.
