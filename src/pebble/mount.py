"""A FUSE view of one committed tree.

A read-only mount decrypts the files and does not rename HEAD. A
read-write mount keeps the new bytes in memory until fsync, rename,
unlink, rmdir, or mkdir. That save writes the objects, syncs the
filesystem once, and renames HEAD. close without fsync does not publish,
so a writer killed during write leaves the previous save.
"""

from __future__ import annotations

import errno
import os
import stat
import sys
import time
from pathlib import Path

import pyfuse3
import trio

from pebble.commit import load_commit
from pebble.errors import FormatError
from pebble.secret import wipe_buffer
from pebble.tree import Dir, _check_name, load
from pebble.vault import (
    EXIT_OK,
    EXIT_REWIND,
    EXIT_SPLIT,
    Layout,
    _judge,
    _own_tree,
    _session,
    commit_directory,
    wipe_directory,
)


def mount_readonly(
    layout: Layout,
    password: bytearray,
    mountpoint: Path,
    *,
    allow_unwitnessed: bool = False,
    read_write: bool = False,
) -> int:
    """Serve the committed tree until the mount is unmounted."""
    with _session(layout, password) as (opened, root_key):
        code, message, shown = _judge(layout, opened, allow_unwitnessed=allow_unwitnessed)
        print(message)
        if shown is None:
            return EXIT_REWIND
        listing = load_commit(layout.store, shown).listing.hex()
        directory = load(layout.store, listing, bytes(root_key))
        _own_tree(directory)
        writable = read_write and code != EXIT_SPLIT

        def publish() -> None:
            commit_directory(layout, opened, root_key, directory)

        operations = _Operations(directory, publish if writable else None)
        options = set(pyfuse3.default_options)
        if not writable:
            options.add("ro")
        options.add("fsname=pebble")
        pyfuse3.init(operations, str(mountpoint), options)
        try:
            trio.run(pyfuse3.main)
        except Exception:
            pyfuse3.close(unmount=False)
            raise
        else:
            pyfuse3.close()
        finally:
            operations.wipe()
            wipe_directory(directory)
        return EXIT_OK


class _Node:
    def __init__(self, parent: int, is_dir: bool, data: bytearray, tree: Dir | None) -> None:
        self.parent = parent
        self.is_dir = is_dir
        self.data = data
        self.tree = tree
        self.children: dict[str, int] = {}


class _Operations(pyfuse3.Operations):
    def __init__(self, root: Dir, publish) -> None:
        super().__init__()
        self._publish_save = publish
        self._writable = publish is not None
        self._nodes: dict[int, _Node] = {}
        self._next = pyfuse3.ROOT_INODE
        self._add_dir(root, pyfuse3.ROOT_INODE, pyfuse3.ROOT_INODE)

    def wipe(self) -> None:
        for node in self._nodes.values():
            wipe_buffer(node.data)

    def _add_dir(self, directory: Dir, inode: int, parent: int) -> None:
        node = _Node(parent, True, bytearray(), directory)
        self._nodes[inode] = node
        for name in sorted(directory.dirs):
            child_ino = self._alloc()
            node.children[name] = child_ino
            self._add_dir(directory.dirs[name], child_ino, inode)
        for name in sorted(directory.files):
            child_ino = self._alloc()
            node.children[name] = child_ino
            body = directory.files[name]
            if not isinstance(body, bytearray):
                body = bytearray(body)
                directory.files[name] = body
            self._nodes[child_ino] = _Node(inode, False, body, None)

    def _alloc(self) -> int:
        self._next += 1
        return self._next

    def _attr(self, inode: int) -> pyfuse3.EntryAttributes:
        node = self._nodes[inode]
        attr = pyfuse3.EntryAttributes()
        attr.st_ino = inode
        attr.st_uid = os.getuid()
        attr.st_gid = os.getgid()
        attr.st_nlink = 2 if node.is_dir else 1
        if node.is_dir:
            attr.st_mode = stat.S_IFDIR | (0o755 if self._writable else 0o555)
            attr.st_size = 0
        else:
            attr.st_mode = stat.S_IFREG | (0o644 if self._writable else 0o444)
            attr.st_size = len(node.data)
        now = time.time_ns()
        attr.st_atime_ns = now
        attr.st_mtime_ns = now
        attr.st_ctime_ns = now
        attr.entry_timeout = 0
        attr.attr_timeout = 0
        return attr

    def _entries(self, inode: int) -> list[tuple[bytes, int]]:
        node = self._nodes[inode]
        entries = [(b".", inode), (b"..", node.parent)]
        for name in sorted(node.children):
            entries.append((os.fsencode(name), node.children[name]))
        return entries

    def _component(self, name: bytes) -> str:
        try:
            _check_name(name)
            return os.fsdecode(name)
        except (FormatError, UnicodeError):
            raise pyfuse3.FUSEError(errno.EINVAL) from None

    def _require_write(self) -> None:
        if not self._writable:
            raise pyfuse3.FUSEError(errno.EROFS)

    def _publish(self) -> None:
        self._require_write()
        try:
            self._publish_save()
        except pyfuse3.FUSEError:
            raise
        except Exception as exc:
            print(f"save failed: {exc}", file=sys.stderr)
            raise pyfuse3.FUSEError(errno.EIO) from None

    def _drop_file(self, directory: _Node, name: str) -> None:
        body = directory.tree.files.pop(name)
        inode = directory.children.pop(name)
        self._nodes.pop(inode, None)
        if isinstance(body, bytearray):
            wipe_buffer(body)

    def _drop_dir(self, directory: _Node, name: str) -> None:
        child = directory.tree.dirs.pop(name)
        inode = directory.children.pop(name)
        node = self._nodes.pop(inode)
        for filename in list(child.files):
            self._drop_file(node, filename)
        for dirname in list(child.dirs):
            self._drop_dir(node, dirname)
        wipe_buffer(node.data)

    async def getattr(self, inode, ctx=None):
        if inode not in self._nodes:
            raise pyfuse3.FUSEError(errno.ENOENT)
        return self._attr(inode)

    async def lookup(self, parent_inode, name, ctx=None):
        parent = self._nodes.get(parent_inode)
        if parent is None or parent.tree is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        if name in (b".", b".."):
            inode = parent_inode if name == b"." else parent.parent
            return self._attr(inode)
        try:
            inode = parent.children[os.fsdecode(name)]
        except (KeyError, UnicodeError):
            raise pyfuse3.FUSEError(errno.ENOENT) from None
        return self._attr(inode)

    async def opendir(self, inode, ctx):
        node = self._nodes.get(inode)
        if node is None or not node.is_dir:
            raise pyfuse3.FUSEError(errno.ENOTDIR)
        return inode

    async def readdir(self, fh, start_id, token):
        for index, (name, inode) in enumerate(self._entries(fh)):
            if index < start_id:
                continue
            if not pyfuse3.readdir_reply(token, name, self._attr(inode), index + 1):
                return

    async def open(self, inode, flags, ctx):
        node = self._nodes.get(inode)
        if node is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        if node.is_dir:
            raise pyfuse3.FUSEError(errno.EISDIR)
        if not self._writable and flags & (os.O_WRONLY | os.O_RDWR):
            raise pyfuse3.FUSEError(errno.EROFS)
        info = pyfuse3.FileInfo()
        info.fh = inode
        info.direct_io = True
        return info

    async def read(self, fh, off, size):
        data = self._nodes[fh].data
        return bytes(data[off : off + size])

    async def write(self, fh, off, buf):
        self._require_write()
        node = self._nodes.get(fh)
        if node is None or node.is_dir:
            raise pyfuse3.FUSEError(errno.EBADF)
        data = node.data
        end = off + len(buf)
        if end > len(data):
            data.extend(b"\x00" * (end - len(data)))
        data[off:end] = buf
        return len(buf)

    async def flush(self, fh):
        return None

    async def release(self, fh):
        return None

    async def fsync(self, fh, datasync):
        self._publish()

    async def fsyncdir(self, fh, datasync):
        self._publish()

    async def setattr(self, inode, attr, fields, fh, ctx):
        self._require_write()
        node = self._nodes.get(inode)
        if node is None:
            raise pyfuse3.FUSEError(errno.ENOENT)
        if fields.update_size and not node.is_dir:
            size = attr.st_size
            data = node.data
            if size < len(data):
                del data[size:]
            elif size > len(data):
                data.extend(b"\x00" * (size - len(data)))
        return self._attr(inode)

    async def create(self, parent_inode, name, mode, flags, ctx):
        self._require_write()
        parent = self._dir(parent_inode)
        text = self._component(name)
        if text in parent.tree.dirs:
            raise pyfuse3.FUSEError(errno.EEXIST)
        if text not in parent.tree.files:
            parent.tree.files[text] = bytearray()
            inode = self._alloc()
            parent.children[text] = inode
            self._nodes[inode] = _Node(parent_inode, False, parent.tree.files[text], None)
        else:
            inode = parent.children[text]
            del parent.tree.files[text][:]
        info = pyfuse3.FileInfo()
        info.fh = inode
        info.direct_io = True
        return info, self._attr(inode)

    async def mkdir(self, parent_inode, name, mode, ctx):
        self._require_write()
        parent = self._dir(parent_inode)
        text = self._component(name)
        if text in parent.children:
            raise pyfuse3.FUSEError(errno.EEXIST)
        child = Dir()
        parent.tree.dirs[text] = child
        inode = self._alloc()
        parent.children[text] = inode
        self._nodes[inode] = _Node(parent_inode, True, bytearray(), child)
        self._publish()
        return self._attr(inode)

    async def unlink(self, parent_inode, name, ctx):
        self._require_write()
        parent = self._dir(parent_inode)
        text = self._component(name)
        if text in parent.tree.dirs:
            raise pyfuse3.FUSEError(errno.EISDIR)
        if text not in parent.tree.files:
            raise pyfuse3.FUSEError(errno.ENOENT)
        self._drop_file(parent, text)
        self._publish()

    async def rmdir(self, parent_inode, name, ctx):
        self._require_write()
        parent = self._dir(parent_inode)
        text = self._component(name)
        child = parent.tree.dirs.get(text)
        if child is None:
            raise pyfuse3.FUSEError(errno.ENOENT if text not in parent.tree.files else errno.ENOTDIR)
        if child.files or child.dirs:
            raise pyfuse3.FUSEError(errno.ENOTEMPTY)
        self._drop_dir(parent, text)
        self._publish()

    async def rename(self, parent_old, name_old, parent_new, name_new, flags, ctx):
        self._require_write()
        if flags & pyfuse3.RENAME_EXCHANGE:
            raise pyfuse3.FUSEError(errno.ENOTSUP)
        source = self._dir(parent_old)
        dest = self._dir(parent_new)
        old = self._component(name_old)
        new = self._component(name_new)
        noreplace = bool(flags & pyfuse3.RENAME_NOREPLACE)
        if source is dest and old == new:
            return
        if old in source.tree.files:
            self._rename_file(source, parent_old, old, dest, parent_new, new, noreplace)
        elif old in source.tree.dirs:
            self._rename_dir(source, old, dest, parent_new, new, noreplace)
        else:
            raise pyfuse3.FUSEError(errno.ENOENT)
        self._publish()

    async def statfs(self, ctx):
        stats = pyfuse3.StatvfsData()
        stats.f_bsize = 4096
        stats.f_frsize = 4096
        stats.f_namemax = 255
        stats.f_files = len(self._nodes)
        return stats

    def _dir(self, inode: int) -> _Node:
        node = self._nodes.get(inode)
        if node is None or node.tree is None:
            raise pyfuse3.FUSEError(errno.ENOTDIR)
        return node

    def _rename_file(self, source, source_ino, old, dest, dest_ino, new, noreplace) -> None:
        del source_ino
        if new in dest.tree.dirs:
            raise pyfuse3.FUSEError(errno.EISDIR)
        if new in dest.tree.files:
            if noreplace:
                raise pyfuse3.FUSEError(errno.EEXIST)
            self._drop_file(dest, new)
        body = source.tree.files.pop(old)
        inode = source.children.pop(old)
        dest.tree.files[new] = body
        dest.children[new] = inode
        node = self._nodes[inode]
        node.parent = dest_ino
        node.data = body

    def _rename_dir(self, source, old, dest, dest_ino, new, noreplace) -> None:
        if new in dest.tree.files:
            raise pyfuse3.FUSEError(errno.ENOTDIR)
        moving = source.tree.dirs[old]
        if _contains(moving, dest.tree):
            raise pyfuse3.FUSEError(errno.EINVAL)
        existing = dest.tree.dirs.get(new)
        if existing is not None:
            if noreplace:
                raise pyfuse3.FUSEError(errno.EEXIST)
            if existing.files or existing.dirs:
                raise pyfuse3.FUSEError(errno.ENOTEMPTY)
            self._drop_dir(dest, new)
        child = source.tree.dirs.pop(old)
        inode = source.children.pop(old)
        dest.tree.dirs[new] = child
        dest.children[new] = inode
        self._nodes[inode].parent = dest_ino


def _contains(ancestor: Dir, needle: Dir) -> bool:
    if ancestor is needle:
        return True
    return any(_contains(child, needle) for child in ancestor.dirs.values())
