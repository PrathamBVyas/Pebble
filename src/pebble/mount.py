"""A read-only view of one committed tree.

The mount decrypts the files from the cipher directory and serves them
through FUSE. It does not rename HEAD. A rewind is refused before the
mount starts. Writes fail with a read-only error.
"""

from __future__ import annotations

import errno
import os
import stat
import time
from pathlib import Path

import pyfuse3
import trio

from pebble.secret import wipe_buffer
from pebble.tree import Dir
from pebble.vault import (
    EXIT_OK,
    EXIT_REWIND,
    Layout,
    open_committed,
    wipe_directory,
)


def mount_readonly(
    layout: Layout,
    password: bytearray,
    mountpoint: Path,
    *,
    allow_unwitnessed: bool = False,
) -> int:
    """Serve the committed tree until the mount is unmounted."""
    code, message, directory = open_committed(
        layout, password, allow_unwitnessed=allow_unwitnessed
    )
    if code == EXIT_REWIND or directory is None:
        print(message)
        return EXIT_REWIND if directory is None else code
    print(message)
    operations = _Operations(directory)
    options = set(pyfuse3.default_options)
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
    def __init__(self, parent: int, is_dir: bool, data: bytearray) -> None:
        self.parent = parent
        self.is_dir = is_dir
        self.data = data
        self.children: dict[str, int] = {}


class _Operations(pyfuse3.Operations):
    def __init__(self, root: Dir) -> None:
        super().__init__()
        self._nodes: dict[int, _Node] = {}
        self._next = pyfuse3.ROOT_INODE
        self._add_dir(root, pyfuse3.ROOT_INODE, pyfuse3.ROOT_INODE)

    def wipe(self) -> None:
        for node in self._nodes.values():
            wipe_buffer(node.data)

    def _add_dir(self, directory: Dir, inode: int, parent: int) -> None:
        node = _Node(parent, True, bytearray())
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
            self._nodes[child_ino] = _Node(inode, False, body)

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
            attr.st_mode = stat.S_IFDIR | 0o555
            attr.st_size = 0
        else:
            attr.st_mode = stat.S_IFREG | 0o444
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
            entries.append((name.encode("utf-8"), node.children[name]))
        return entries

    async def getattr(self, inode, ctx=None):
        if inode not in self._nodes:
            raise pyfuse3.FUSEError(errno.ENOENT)
        return self._attr(inode)

    async def lookup(self, parent_inode, name, ctx=None):
        if parent_inode not in self._nodes:
            raise pyfuse3.FUSEError(errno.ENOENT)
        if name == b".":
            return self._attr(parent_inode)
        if name == b"..":
            return self._attr(self._nodes[parent_inode].parent)
        try:
            text = os.fsdecode(name)
            inode = self._nodes[parent_inode].children[text]
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
        if flags & (os.O_WRONLY | os.O_RDWR):
            raise pyfuse3.FUSEError(errno.EROFS)
        info = pyfuse3.FileInfo()
        info.fh = inode
        return info

    async def read(self, fh, off, size):
        data = self._nodes[fh].data
        return bytes(data[off : off + size])

    async def write(self, fh, off, buf):
        raise pyfuse3.FUSEError(errno.EROFS)

    async def setattr(self, inode, attr, fields, fh, ctx):
        raise pyfuse3.FUSEError(errno.EROFS)

    async def create(self, parent_inode, name, mode, flags, ctx):
        raise pyfuse3.FUSEError(errno.EROFS)

    async def mkdir(self, parent_inode, name, mode, ctx):
        raise pyfuse3.FUSEError(errno.EROFS)

    async def unlink(self, parent_inode, name, ctx):
        raise pyfuse3.FUSEError(errno.EROFS)

    async def rmdir(self, parent_inode, name, ctx):
        raise pyfuse3.FUSEError(errno.EROFS)

    async def rename(self, parent_inode_old, name_old, parent_inode_new, name_new, flags, ctx):
        raise pyfuse3.FUSEError(errno.EROFS)

    async def statfs(self, ctx):
        stats = pyfuse3.StatvfsData()
        stats.f_bsize = 4096
        stats.f_frsize = 4096
        stats.f_namemax = 255
        stats.f_files = len(self._nodes)
        return stats
