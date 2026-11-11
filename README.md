# Pebble

Run the tests with:

```
./build.sh
```

`./build.sh` creates a virtualenv, installs the package, and runs pytest. It exits 0 when the tests pass.

`pebble` talks to a cipher directory. Accepted heads and the witness log live outside that directory, so copying the cipher directory does not copy them. The password is read from a file.

```
pebble init CIPHER --state STATE --witness WITNESS --password-file FILE
pebble put CIPHER --state STATE --witness WITNESS --password-file FILE LOCAL NAME
pebble ls CIPHER --state STATE --witness WITNESS --password-file FILE
pebble commit CIPHER --state STATE --witness WITNESS --password-file FILE
pebble status CIPHER --state STATE --witness WITNESS --password-file FILE
pebble verify-proof RECEIPT
```

`status` exits 0 on an update, 2 on a rewind, and 3 on a split. `verify-proof` checks a receipt with no password.

A mount shows the committed files. Without `--read-write` it refuses writes. With `--read-write`, fsync, rename, unlink, rmdir, and mkdir each publish one save: the new objects are synced once, then HEAD is renamed. Closing a file without fsync does not publish. Unmount with `fusermount3 -u`.

```
pebble mount CIPHER MOUNTPOINT --state STATE --witness WITNESS --password-file FILE
```

Mounting needs libfuse 3 and `/dev/fuse`. This was tried on Linux 6.12 with libfuse 3.14.

A second person gets a keybag and is granted one folder. `--keybag` mounts only the folders that person can still open. `revoke` mints a new listing key for that folder. A later commit that pastes the old grant list back is refused.

```
pebble keygen --password-file FILE --keybag KEYBAG --public PUBLIC
pebble add-user CIPHER --name NAME --keybag KEYBAG --public PUBLIC --password-file FILE
pebble share CIPHER FOLDER NAME --password-file FILE
pebble revoke CIPHER FOLDER NAME --password-file FILE
pebble mount CIPHER MOUNTPOINT --keybag KEYBAG --password-file FILE
```
