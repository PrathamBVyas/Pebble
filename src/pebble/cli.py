"""The pebble command.

init, put, ls, commit, and status take a cipher directory and a password
file. status also takes the witness log, which is not inside the cipher
directory. verify-proof reads a receipt and takes no password.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from pebble.errors import CryptoError, PasswordError
from pebble.mount import mount_readonly
from pebble.receipt import verify_receipt
from pebble.vault import EXIT_OK, Layout, VaultError, commit, init, ls, put, status


def main(argv: list[str] | None = None) -> None:
    try:
        code = _run(argv)
    except PasswordError as exc:
        print(exc, file=sys.stderr)
        code = 1
    except (VaultError, CryptoError, OSError, ValueError) as exc:
        print(exc, file=sys.stderr)
        code = 1
    raise SystemExit(code)


def _run(argv: list[str] | None) -> int:
    parser = argparse.ArgumentParser(prog="pebble")
    sub = parser.add_subparsers(dest="command", required=True)

    init_cmd = _vault_parser(sub, "init")
    init_cmd.set_defaults(func=_cmd_init)

    put_cmd = _vault_parser(sub, "put")
    put_cmd.add_argument("local")
    put_cmd.add_argument("path")
    put_cmd.set_defaults(func=_cmd_put)

    ls_cmd = _vault_parser(sub, "ls")
    ls_cmd.add_argument("path", nargs="?", default="")
    ls_cmd.set_defaults(func=_cmd_ls)

    commit_cmd = _vault_parser(sub, "commit")
    commit_cmd.set_defaults(func=_cmd_commit)

    status_cmd = _vault_parser(sub, "status")
    status_cmd.add_argument("--allow-unwitnessed", action="store_true")
    status_cmd.set_defaults(func=_cmd_status)

    mount_cmd = _vault_parser(sub, "mount")
    mount_cmd.add_argument("mountpoint")
    mount_cmd.add_argument("--allow-unwitnessed", action="store_true")
    mount_cmd.add_argument("--read-write", action="store_true")
    mount_cmd.set_defaults(func=_cmd_mount)

    proof = sub.add_parser("verify-proof")
    proof.add_argument("receipt")
    proof.set_defaults(func=_cmd_proof)

    args = parser.parse_args(argv)
    return args.func(args)


def _vault_parser(sub: argparse._SubParsersAction, name: str) -> argparse.ArgumentParser:
    parser = sub.add_parser(name)
    parser.add_argument("cipher", nargs="?")
    parser.add_argument("--state")
    parser.add_argument("--witness")
    parser.add_argument("--password-file")
    return parser


def _cmd_init(args: argparse.Namespace) -> int:
    password = _password(args)
    try:
        print(init(_layout(args), password))
    finally:
        _wipe_password(password)
    return EXIT_OK


def _cmd_put(args: argparse.Namespace) -> int:
    password = _password(args)
    try:
        put(_layout(args), password, Path(args.local), args.path)
    finally:
        _wipe_password(password)
    return EXIT_OK


def _cmd_ls(args: argparse.Namespace) -> int:
    password = _password(args)
    try:
        for name in ls(_layout(args), password, args.path):
            print(name)
    finally:
        _wipe_password(password)
    return EXIT_OK


def _cmd_commit(args: argparse.Namespace) -> int:
    password = _password(args)
    try:
        print(commit(_layout(args), password))
    finally:
        _wipe_password(password)
    return EXIT_OK


def _cmd_status(args: argparse.Namespace) -> int:
    password = _password(args)
    try:
        code, text = status(_layout(args), password, allow_unwitnessed=args.allow_unwitnessed)
    finally:
        _wipe_password(password)
    print(text)
    return code


def _cmd_mount(args: argparse.Namespace) -> int:
    password = _password(args)
    try:
        return mount_readonly(
            _layout(args),
            password,
            Path(args.mountpoint),
            allow_unwitnessed=args.allow_unwitnessed,
            read_write=args.read_write,
        )
    finally:
        _wipe_password(password)


def _cmd_proof(args: argparse.Namespace) -> int:
    left, right = verify_receipt(Path(args.receipt))
    print("fork")
    print(left)
    print(right)
    return EXIT_OK


def _layout(args: argparse.Namespace) -> Layout:
    cipher = _need(args.cipher, "PEBBLE_CIPHER", "cipher directory")
    state = _need(args.state, "PEBBLE_STATE", "state directory")
    witness = _need(args.witness, "PEBBLE_WITNESS", "witness directory")
    return Layout(Path(cipher), Path(state), Path(witness))


def _need(value: str | None, env: str, label: str) -> str:
    chosen = value or os.environ.get(env)
    if not chosen:
        raise VaultError(f"missing {label}")
    return chosen


def _password(args: argparse.Namespace) -> bytearray:
    path = args.password_file or os.environ.get("PEBBLE_PASSWORD_FILE")
    if not path:
        raise VaultError("missing password file")
    raw = bytearray(Path(path).read_bytes())
    if raw.endswith(b"\n"):
        del raw[-1]
    if len(raw) == 0:
        raise VaultError("password is empty")
    return raw


def _wipe_password(password: bytearray) -> None:
    from pebble.secret import wipe_buffer

    wipe_buffer(password)
