#!/usr/bin/env python3
"""Reference solution: validate, stage, apply, and atomically commit a rootfs delta."""
from __future__ import annotations

import argparse
import base64
import binascii
import ctypes
import json
import os
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path


class Reject(Exception):
    pass


OPS = {"mkdir", "write", "symlink", "hardlink", "rename", "unlink", "whiteout", "opaque"}
RENAME_EXCHANGE = 2


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


def open_root_nofollow(root_name: str) -> tuple[str, int, int, str]:
    """Open every component of an absolute root spelling without following links."""
    root = os.path.abspath(root_name)
    parts = [part for part in root.split("/") if part]
    if not parts:
        raise Reject("the filesystem root cannot be replaced atomically")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    current_fd = os.open("/", flags)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        root_fd = os.open(parts[-1], flags, dir_fd=current_fd)
    except Exception:
        os.close(current_fd)
        raise
    return root, current_fd, root_fd, parts[-1]


def audit_initial_tree(root_fd: int) -> None:
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

    check_mode(os.fstat(root_fd))
    scan(root_fd)
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


def copy_regular_file(src_fd: int, name: str, destination: Path, copied: dict[tuple[int, int], Path]) -> None:
    """Copy one regular file through an already-open directory descriptor."""
    try:
        st = os.stat(name, dir_fd=src_fd, follow_symlinks=False)
    except OSError as exc:
        raise Reject("path component swap detected during staging") from exc
    key = (st.st_dev, st.st_ino)
    if key in copied:
        try:
            os.link(copied[key], destination)
        except OSError as exc:
            raise Reject("path component swap detected during staging") from exc
        return
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        source_file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=src_fd)
    except OSError as exc:
        raise Reject("path component swap detected during staging") from exc
    try:
        with os.fdopen(source_file_fd, "rb", closefd=False) as source_stream, open(destination, "wb") as stream:
            shutil.copyfileobj(source_stream, stream)
        proc_path = f"/proc/self/fd/{source_file_fd}"
        try:
            for xattr_name in os.listxattr(proc_path, follow_symlinks=False):
                os.setxattr(
                    destination,
                    xattr_name,
                    os.getxattr(proc_path, xattr_name, follow_symlinks=False),
                    follow_symlinks=False,
                )
        except OSError:
            pass
    finally:
        os.close(source_file_fd)
    os.chmod(destination, stat.S_IMODE(st.st_mode), follow_symlinks=False)
    os.chown(destination, st.st_uid, st.st_gid, follow_symlinks=False)
    os.utime(destination, ns=(st.st_atime_ns, st.st_mtime_ns), follow_symlinks=False)
    copied[key] = destination


def source_has_directory(root_fd: int, relative: str) -> bool:
    """Return whether a relative path is a real directory in the live root."""
    if not relative:
        return True
    parts = relative.split("/")
    current_fd = root_fd
    opened: list[int] = []
    try:
        for index, part in enumerate(parts):
            try:
                entry_st = os.stat(part, dir_fd=current_fd, follow_symlinks=False)
            except OSError:
                return False
            if index == len(parts) - 1:
                return stat.S_ISDIR(entry_st.st_mode) and not stat.S_ISLNK(entry_st.st_mode)
            if stat.S_ISLNK(entry_st.st_mode) or not stat.S_ISDIR(entry_st.st_mode):
                return False
            child_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=current_fd,
            )
            if current_fd != root_fd:
                opened.append(current_fd)
            current_fd = child_fd
        return True
    finally:
        for fd in opened:
            os.close(fd)
        if current_fd != root_fd:
            os.close(current_fd)


def stage_lost_required_directory(stage: Path, root_fd: int, required_dirs: set[str]) -> bool:
    """True when staging dropped a directory that still exists in the live root."""
    for prefix in required_dirs:
        if prefix == "pivot" or not source_has_directory(root_fd, prefix):
            continue
        path = stage / prefix
        try:
            entry_st = os.lstat(path)
        except FileNotFoundError:
            return True
        if stat.S_ISLNK(entry_st.st_mode) or not stat.S_ISDIR(entry_st.st_mode):
            return True
    return False


def staging_should_retry(exc: Reject, stage: Path, root_fd: int, required_dirs: set[str]) -> bool:
    message = str(exc)
    if "path component swap detected during staging" in message:
        return True
    if message == "root entry changed before publication":
        return True
    if message in {"missing parent", "symlink or non-directory parent"}:
        return stage_lost_required_directory(stage, root_fd, required_dirs)
    return False


def required_directory_prefixes(doc: dict) -> set[str]:
    """Return every bundle path prefix that must exist as a real directory."""
    prefixes: set[str] = set()
    for op in doc["operations"]:
        paths: list[str] = []
        if op["op"] == "rename":
            paths = [op["src"], op["dst"]]
        elif op["op"] == "hardlink":
            paths = [op["path"], op["target"]]
        else:
            paths = [op.get("path", "")]
        for raw in paths:
            parts = [bit for bit in raw.split("/") if bit]
            for depth in range(1, len(parts)):
                prefixes.add("/".join(parts[:depth]))
    return prefixes


def copy_tree_preserving_links_fd(
    source_fd: int,
    destination: Path,
    required_dirs: set[str],
    *,
    relative: str = "",
) -> None:
    """Stage the live root through directory descriptors, never through its pathname."""
    copied: dict[tuple[int, int], Path] = {}
    destination.mkdir(parents=True, exist_ok=True)
    root_st = os.fstat(source_fd)
    os.chown(destination, root_st.st_uid, root_st.st_gid, follow_symlinks=False)
    os.chmod(destination, stat.S_IMODE(root_st.st_mode), follow_symlinks=False)
    os.utime(destination, ns=(root_st.st_atime_ns, root_st.st_mtime_ns), follow_symlinks=False)

    def copy_directory(src_fd: int, dst_dir: Path, rel: str) -> None:
        try:
            names = os.listdir(src_fd)
        except OSError as exc:
            raise Reject("path component swap detected during staging") from exc
        for name in names:
            child_rel = f"{rel}/{name}" if rel else name
            try:
                entry_st = os.stat(name, dir_fd=src_fd, follow_symlinks=False)
            except OSError as exc:
                raise Reject("path component swap detected during staging") from exc
            dst_path = dst_dir / name
            if stat.S_ISDIR(entry_st.st_mode) and not stat.S_ISLNK(entry_st.st_mode):
                dst_path.mkdir(exist_ok=True)
                try:
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=src_fd,
                    )
                except OSError as exc:
                    raise Reject("path component swap detected during staging") from exc
                try:
                    copy_directory(child_fd, dst_path, child_rel)
                finally:
                    os.close(child_fd)
                os.chown(dst_path, entry_st.st_uid, entry_st.st_gid, follow_symlinks=False)
                os.chmod(dst_path, stat.S_IMODE(entry_st.st_mode), follow_symlinks=False)
                os.utime(dst_path, ns=(entry_st.st_atime_ns, entry_st.st_mtime_ns), follow_symlinks=False)
            elif stat.S_ISREG(entry_st.st_mode):
                copy_regular_file(src_fd, name, dst_path, copied)
            elif stat.S_ISLNK(entry_st.st_mode):
                # The fixture pivot is a stable outside symlink; transient swap attacks
                # briefly replace required directories with outside links instead.
                if name != "pivot" and child_rel in required_dirs:
                    raise Reject("path component swap detected during staging")
                link_target = os.readlink(name, dir_fd=src_fd)
                dst_path.symlink_to(link_target)
                os.lchown(dst_path, entry_st.st_uid, entry_st.st_gid)
                os.utime(dst_path, ns=(entry_st.st_atime_ns, entry_st.st_mtime_ns), follow_symlinks=False)
            else:
                raise Reject("unsupported object type during staging")

    copy_directory(source_fd, destination, relative)


def rename_exchange(parent_fd: int, left: str, right: str) -> None:
    """Atomically exchange two same-parent directory entries."""
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise Reject("renameat2 is unavailable")
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(parent_fd, os.fsencode(left), parent_fd, os.fsencode(right), RENAME_EXCHANGE) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


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
    root_name, parent_fd, root_fd, root_leaf = open_root_nofollow(root_name)
    exchanged = False
    stage: Path | None = None
    try:
        with open(bundle_name, "r", encoding="utf-8") as stream:
            doc = validate(json.load(stream))
        required_dirs = required_directory_prefixes(doc)
        parent_path = f"/proc/self/fd/{parent_fd}"
        stage = Path(tempfile.mkdtemp(prefix=".rootfs-stage-", dir=parent_path))
        while True:
            for prefix in sorted(required_dirs):
                if prefix == "pivot":
                    continue
                wait_until = time.monotonic() + 0.05
                while not source_has_directory(root_fd, prefix):
                    if time.monotonic() >= wait_until:
                        break
                    time.sleep(0.00005)
            try:
                audit_initial_tree(root_fd)
                copy_tree_preserving_links_fd(root_fd, stage, required_dirs)
                if stage_lost_required_directory(stage, root_fd, required_dirs):
                    raise Reject("path component swap detected during staging")
                root_st = os.fstat(root_fd)
                os.chown(stage, root_st.st_uid, root_st.st_gid, follow_symlinks=False)
                for op in doc["operations"]:
                    apply_op(stage, op)
                root_st = os.fstat(root_fd)
                current = os.stat(root_leaf, dir_fd=parent_fd, follow_symlinks=False)
                if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != (root_st.st_dev, root_st.st_ino):
                    raise Reject("root entry changed before publication")
                try:
                    rename_exchange(parent_fd, root_leaf, stage.name)
                except OSError as exc:
                    raise Reject("path component swap detected during staging") from exc
                exchanged = True
                try:
                    shutil.rmtree(stage)
                except OSError:
                    pass
                break
            except Reject as exc:
                if not staging_should_retry(exc, stage, root_fd, required_dirs):
                    raise
            except OSError as exc:
                swap = Reject("path component swap detected during staging")
                if not staging_should_retry(swap, stage, root_fd, required_dirs):
                    raise swap from exc
            shutil.rmtree(stage, ignore_errors=True)
            stage = Path(tempfile.mkdtemp(prefix=".rootfs-stage-", dir=parent_path))
    finally:
        if not exchanged and stage is not None and os.path.lexists(stage):
            shutil.rmtree(stage, ignore_errors=True)
        os.close(root_fd)
        os.close(parent_fd)


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
