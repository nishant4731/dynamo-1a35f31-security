#!/usr/bin/env python3
"""Reference solution: validate, stage, apply, and atomically commit a rootfs delta."""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import shutil
import stat
import sys
import tempfile
from pathlib import Path


class Reject(Exception):
    pass


OPS = {"mkdir", "write", "symlink", "hardlink", "rename", "unlink", "whiteout", "opaque"}


def canon(value: object) -> str:
    if not isinstance(value, str) or not value or "\0" in value or value.startswith("/") or value.endswith("/"):
        raise Reject("non-canonical path")
    bits = value.split("/")
    if any(bit in {"", ".", ".."} for bit in bits):
        raise Reject("non-canonical path")
    return value


def decode(value: object) -> bytes:
    if not isinstance(value, str):
        raise Reject("base64 must be text")
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
        raise Reject("bad base64") from exc


def meta(op: dict) -> None:
    for key in ("uid", "gid", "mtime_ns"):
        if key in op and (not isinstance(op[key], int) or isinstance(op[key], bool)):
            raise Reject("bad numeric metadata")
    if "uid" in op and not 0 <= op["uid"] <= 4_000_000_000:
        raise Reject("bad uid")
    if "gid" in op and not 0 <= op["gid"] <= 4_000_000_000:
        raise Reject("bad gid")
    if "mtime_ns" in op and not -(1 << 62) <= op["mtime_ns"] <= (1 << 62):
        raise Reject("bad mtime")
    if "mode" in op:
        mode = op["mode"]
        if not isinstance(mode, int) or isinstance(mode, bool) or mode < 0 or mode & 0o6000 or mode & ~0o1777:
            raise Reject("unsafe mode")
    if "xattrs" in op:
        if not isinstance(op["xattrs"], dict):
            raise Reject("bad xattrs")
        for name, value in op["xattrs"].items():
            if not isinstance(name, str) or not name.startswith("user.") or "\0" in name:
                raise Reject("unsafe xattr")
            decode(value)


def validate(doc: object) -> dict:
    if not isinstance(doc, dict) or doc.get("format") != 1 or not isinstance(doc.get("operations"), list):
        raise Reject("bad bundle")
    for op in doc["operations"]:
        if not isinstance(op, dict) or op.get("op") not in OPS:
            raise Reject("bad operation")
        if op["op"] == "rename":
            canon(op.get("src")); canon(op.get("dst"))
        else:
            canon(op.get("path"))
        if op["op"] == "write":
            decode(op.get("data_b64"))
        if op["op"] == "symlink" and (not isinstance(op.get("target"), str) or "\0" in op["target"]):
            raise Reject("bad symlink")
        if op["op"] == "hardlink":
            canon(op.get("target"))
        meta(op)
    return doc


def audit_initial_tree(root: Path) -> None:
    """Reject privilege-bearing objects and regular inodes linked outside root."""
    counts: dict[tuple[int, int], int] = {}
    declared_links: dict[tuple[int, int], int] = {}

    def check_mode(st: os.stat_result) -> None:
        if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise Reject("set-ID bit in initial target")

    def scan(directory_fd: int) -> None:
        for name in os.listdir(directory_fd):
            st = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            check_mode(st)
            if stat.S_ISDIR(st.st_mode):
                child_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
                try:
                    scan(child_fd)
                finally:
                    os.close(child_fd)
            elif stat.S_ISREG(st.st_mode):
                key = (st.st_dev, st.st_ino)
                counts[key] = counts.get(key, 0) + 1
                previous = declared_links.setdefault(key, st.st_nlink)
                if previous != st.st_nlink:
                    raise Reject("initial hardlink graph changed during audit")
            elif stat.S_ISLNK(st.st_mode):
                if st.st_nlink != 1:
                    raise Reject("hardlinked symlink in initial target")
            else:
                raise Reject("unsupported initial object type")

    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        check_mode(os.fstat(root_fd))
        scan(root_fd)
    finally:
        os.close(root_fd)
    if any(counts[key] != declared_links[key] for key in counts):
        raise Reject("initial regular inode has an alias outside target")


def parent(root: Path, relative: str) -> tuple[Path, Path]:
    parts = relative.split("/")
    current = root
    for bit in parts[:-1]:
        current = current / bit
        try:
            st = os.lstat(current)
        except FileNotFoundError as exc:
            raise Reject("missing parent") from exc
        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
            raise Reject("symlink or non-directory parent")
    return current, current / parts[-1]


def remove_tree(path: Path, missing_ok: bool = False) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        if missing_ok:
            return
        raise Reject("missing object")
    if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
        shutil.rmtree(path)
    else:
        path.unlink()


def copy_tree_preserving_links(source: Path, destination: Path) -> None:
    """Stage the root without silently splitting pre-existing regular-file links."""
    copied: dict[tuple[int, int], Path] = {}

    def copy_file(src: str, dst: str) -> str:
        src_path = Path(src)
        dst_path = Path(dst)
        st = os.stat(src_path, follow_symlinks=False)
        key = (st.st_dev, st.st_ino)
        if stat.S_ISREG(st.st_mode) and key in copied:
            os.link(copied[key], dst_path)
            return str(dst_path)
        result = shutil.copy2(src_path, dst_path, follow_symlinks=False)
        if stat.S_ISREG(st.st_mode):
            copied[key] = dst_path
        return result

    shutil.copytree(source, destination, symlinks=True, copy_function=copy_file)


def apply_meta(path: Path, op: dict) -> None:
    if "uid" in op or "gid" in op:
        st = os.lstat(path)
        os.chown(path, op.get("uid", st.st_uid), op.get("gid", st.st_gid), follow_symlinks=False)
    if "mode" in op:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise Reject("mode on symlink")
        os.chmod(path, op["mode"], follow_symlinks=False)
    if "xattrs" in op:
        if stat.S_ISLNK(os.lstat(path).st_mode):
            raise Reject("xattrs on symlink")
        for name, value in op["xattrs"].items():
            os.setxattr(path, name, decode(value), follow_symlinks=False)
    if "mtime_ns" in op:
        os.utime(path, ns=(op["mtime_ns"], op["mtime_ns"]), follow_symlinks=False)


def apply_op(root: Path, op: dict) -> None:
    kind = op["op"]
    if kind == "rename":
        src_parent, src = parent(root, op["src"])
        dst_parent, dst = parent(root, op["dst"])
        if not os.path.lexists(src) or os.path.lexists(dst):
            raise Reject("invalid rename")
        os.rename(src, dst)
        apply_meta(dst, op)
        return
    p_parent, path = parent(root, op["path"])
    exists = os.path.lexists(path)
    if kind == "mkdir":
        if exists:
            if not path.is_dir() or path.is_symlink():
                raise Reject("mkdir collision")
        else:
            path.mkdir()
        apply_meta(path, op)
    elif kind == "write":
        if exists and path.is_dir() and not path.is_symlink():
            raise Reject("file over directory")
        if exists:
            remove_tree(path)
        path.write_bytes(decode(op["data_b64"]))
        apply_meta(path, op)
    elif kind == "symlink":
        if exists:
            if path.is_dir() and not path.is_symlink():
                raise Reject("symlink over directory")
            remove_tree(path)
        path.symlink_to(op["target"])
        apply_meta(path, op)
    elif kind == "hardlink":
        if exists:
            raise Reject("hardlink collision")
        source = parent(root, op["target"])[1]
        st = os.lstat(source) if os.path.lexists(source) else None
        if st is None or not stat.S_ISREG(st.st_mode):
            raise Reject("hardlink target is not a regular file")
        os.link(source, path)
        apply_meta(path, op)
    elif kind == "rename":
        raise AssertionError("unreachable")
    elif kind == "unlink":
        if exists:
            if path.is_dir() and not path.is_symlink():
                path.rmdir()
            else:
                path.unlink()
    elif kind == "whiteout":
        remove_tree(path, missing_ok=True)
    elif kind == "opaque":
        if not exists or not path.is_dir() or path.is_symlink():
            raise Reject("opaque target is not a directory")
        for child in list(path.iterdir()):
            remove_tree(child)


def apply(root_name: str, bundle_name: str) -> None:
    root = Path(root_name).absolute()
    st = os.lstat(root)
    if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode):
        raise Reject("root is not a real directory")
    audit_initial_tree(root)
    with open(bundle_name, "r", encoding="utf-8") as stream:
        doc = validate(json.load(stream))
    stage = Path(tempfile.mkdtemp(prefix=".rootfs-stage-", dir=str(root.parent)))
    shutil.rmtree(stage)
    backup = root.parent / (".rootfs-old-" + next(tempfile._get_candidate_names()))
    try:
        copy_tree_preserving_links(root, stage)
        for op in doc["operations"]:
            apply_op(stage, op)
        os.rename(root, backup)
        try:
            os.rename(stage, root)
        except Exception:
            os.rename(backup, root)
            raise
        shutil.rmtree(backup)
    finally:
        if os.path.lexists(stage):
            shutil.rmtree(stage, ignore_errors=True)
        if os.path.lexists(backup):
            shutil.rmtree(backup, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--force-fallback", action="store_true")
    args = parser.parse_args(argv)
    try:
        apply(args.root, args.bundle)
        return 0
    except (Reject, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"rootfs-apply rejected bundle: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
