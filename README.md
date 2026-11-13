# Pebble

Pebble is an encrypted folder for Linux. You unlock it with a password and use it with ordinary programs. The copy that gets synced can be read, edited, deleted, and restored by someone who does not have the password. That person learns nothing useful from the stored bytes, and this computer notices when an old copy has been put back.

The problem this implements is LLS10, VaultFS, from the Low-Level Security track. [What each requirement comes to](docs/requirements.md). [How a save, a rewind, and a share actually work](docs/how-it-works.md). [Measured times](docs/benchmarks.md).

## What you need

Tested on Ubuntu 24.04.5 LTS, Linux 6.12.113+, Python 3.12.3, libfuse 3.14.0 (`fusermount3`). The mount uses libfuse 3 and `/dev/fuse`, so the machine has to be Linux. The same packages are what another Debian or Ubuntu release needs in order to build.

```bash
sudo apt install python3 python3-venv python3-dev gcc pkg-config libfuse3-dev fuse3
```

Python packages, installed by the build below: `argon2-cffi`, `cryptography`, `pyfuse3`, `trio`, and `pytest` for the tests.

## Build and test

From the repository root:

```bash
./build.sh
```

`./build.sh` creates `.venv`, installs this package, and runs pytest. It exits 0 when the tests pass. After that, use the `pebble` command from the virtualenv:

```bash
source .venv/bin/activate
```

## Create a volume

The password is read from a file. A trailing newline is stripped. The cipher directory is the folder that gets synced. `state` and `witness` stay on this computer, outside that folder. Copying the cipher directory does not copy them.

```bash
mkdir -p demo
printf 'alice-password' > demo/alice.pw
pebble init demo/cipher --state demo/state --witness demo/witness --password-file demo/alice.pw
```

`init` prints the first save id.

## Use it as a folder

Without `--read-write` the mount refuses writes. With `--read-write`, fsync, rename, unlink, rmdir, and mkdir each publish one save. Closing a file without fsync does not publish. Unmount with `fusermount3 -u`.

```bash
mkdir demo/mnt
pebble mount demo/cipher demo/mnt --read-write --state demo/state --witness demo/witness \
  --password-file demo/alice.pw
# ordinary programs: cp, vim, ls, cat
fusermount3 -u demo/mnt
```

The same files can be written without a mount. `put` stages a file. `commit` publishes it. `HEAD` does not move until `commit`. Put every positional argument before the options. An option between the cipher directory and a later path is rejected by the argument parser.

```bash
printf 'hello' > demo/note.txt
pebble put demo/cipher demo/note.txt notes/note.txt --state demo/state --witness demo/witness \
  --password-file demo/alice.pw
pebble commit demo/cipher --state demo/state --witness demo/witness --password-file demo/alice.pw
pebble ls demo/cipher notes --state demo/state --witness demo/witness --password-file demo/alice.pw
```

`status` exits 0 on an update, 2 on a rewind, 3 on a split, and 4 when an old share list has been pasted back. `verify-proof` checks a fork receipt and takes no password.

```bash
pebble status demo/cipher --state demo/state --witness demo/witness --password-file demo/alice.pw
pebble verify-proof demo/state/receipt
```

## Change the password

The volume password wraps the owner's keybag. The new password opens the current keybag. The old password is refused. This computer remembers the new keybag outside the synced folder, so putting the previous keybag file back is refused here.

```bash
printf 'new-password' > demo/alice-new.pw
pebble passwd demo/cipher --state demo/state --witness demo/witness \
  --password-file demo/alice.pw --new-password-file demo/alice-new.pw
```

A member's own keybag is changed the same way, on the file they keep. That form does not take the cipher directory:

```bash
pebble passwd --keybag demo/bob.keybag \
  --password-file demo/bob.pw --new-password-file demo/bob-new.pw
```

## Add a person, share files, remove them

Each member has their own password and a `home/<name>` folder. They can read that folder. They cannot read another member's home, and they cannot read a folder that was not shared with them. That stays true if they read the stored bytes directly, because those listings are sealed to keys they do not have.

A file is shared by putting it in a folder and sharing the folder. `share` refuses a file path and tells you to share the folder that holds it.

```bash
printf 'bob-password' > demo/bob.pw
pebble keygen --password-file demo/bob.pw --keybag demo/bob.keybag --public demo/bob.pub
pebble add-user demo/cipher --state demo/state --witness demo/witness \
  --password-file demo/alice-new.pw --name bob --keybag demo/bob.keybag --public demo/bob.pub

printf 'report body' > demo/report.txt
pebble put demo/cipher demo/report.txt shared/report.txt --state demo/state --witness demo/witness \
  --password-file demo/alice-new.pw
pebble commit demo/cipher --state demo/state --witness demo/witness --password-file demo/alice-new.pw
pebble share demo/cipher shared bob --state demo/state --witness demo/witness \
  --password-file demo/alice-new.pw
```

Bob mounts with his keybag and sees `home/bob` and `shared`. He does not see the rest of the volume. His mount is read-only.

```bash
mkdir -p demo/bob-state demo/bob-witness demo/bob-mnt
: > demo/bob-witness/log
pebble mount demo/cipher demo/bob-mnt --keybag demo/cipher/keybags/bob \
  --state demo/bob-state --witness demo/bob-witness --password-file demo/bob.pw
fusermount3 -u demo/bob-mnt
```

`revoke` takes Bob off one folder. Files that were already in that folder still open for him. Files written afterwards do not. The file bodies are not re-encrypted.

```bash
pebble revoke demo/cipher shared bob --state demo/state --witness demo/witness \
  --password-file demo/alice-new.pw
```

`remove-user` does that for every folder sealed to Bob, including `home/bob`, and deletes his keybag copy from the cipher directory.

```bash
pebble remove-user demo/cipher --name bob --state demo/state --witness demo/witness \
  --password-file demo/alice-new.pw
```

## The six-beat demo and the benchmarks

`tests/demo.sh` is the short demonstration: ciphertext instead of the file, a second computer taking the new save, an old directory refused, a split with a receipt, a hidden save named from the witness log, and a share that survives an old grant list being pasted back.

```bash
./tests/demo.sh
```

The submission asks for a 5-minute video of the working system. Record that script. The repository does not contain the video itself.

Benchmarks, from the same virtualenv, on a machine with `/dev/fuse`:

```bash
python scripts/bench.py
```

The numbers from one run on the machine above are in [docs/benchmarks.md](docs/benchmarks.md).
