#!/usr/bin/env python3
"""Intentionally unsafe starter implementation for the hardening task."""
import argparse
import base64
import json
import os
import shutil
import stat
import sys


def target(root, value):
    # This lexical check is deliberately not sufficient for a privileged applier.
    value = os.path.normpath(value)
    if value.startswith("/") or value.startswith("../") or value == "..":
        raise ValueError("path escapes root")
    return os.path.join(root, value)


def metadata(path, op):
    if "uid" in op or "gid" in op:
        st = os.lstat(path)
        os.chown(path, op.get("uid", st.st_uid), op.get("gid", st.st_gid), follow_symlinks=False)
    if "mode" in op:
        os.chmod(path, op["mode"], follow_symlinks=False)
    for name, value in op.get("xattrs", {}).items():
        os.setxattr(path, name, base64.b64decode(value), follow_symlinks=False)
    if "mtime_ns" in op:
        os.utime(path, ns=(op["mtime_ns"], op["mtime_ns"]), follow_symlinks=False)


def apply(root, bundle):
    with open(bundle, "r", encoding="utf-8") as stream:
        doc = json.load(stream)
    if doc.get("format") != 1:
        raise ValueError("unsupported format")
    for op in doc["operations"]:
        kind = op["op"]
        if kind == "rename":
            source = target(root, op["src"])
            destination = target(root, op["dst"])
            os.rename(source, destination)
            metadata(destination, op)
        else:
            path = target(root, op["path"])
            parent = os.path.dirname(path)
            os.makedirs(parent, exist_ok=True)
            if kind == "mkdir":
                os.makedirs(path, exist_ok=True)
            elif kind == "write":
                with open(path, "wb") as stream:
                    stream.write(base64.b64decode(op["data_b64"]))
            elif kind == "symlink":
                if os.path.lexists(path):
                    os.unlink(path)
                os.symlink(op["target"], path)
            elif kind == "hardlink":
                os.link(target(root, op["target"]), path)
            elif kind == "unlink":
                if os.path.isdir(path):
                    os.rmdir(path)
                else:
                    os.unlink(path)
            elif kind == "whiteout":
                if os.path.isdir(path) and not os.path.islink(path):
                    shutil.rmtree(path)
                else:
                    os.unlink(path)
            elif kind == "opaque":
                if not os.path.isdir(path) or os.path.islink(path):
                    raise ValueError("opaque target is not a directory")
                for child in os.listdir(path):
                    child_path = os.path.join(path, child)
                    if os.path.isdir(child_path) and not os.path.islink(child_path):
                        shutil.rmtree(child_path)
                    else:
                        os.unlink(child_path)
            else:
                raise ValueError("unknown operation")
            if kind in {"mkdir", "write", "symlink", "hardlink"}:
                metadata(path, op)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--force-fallback", action="store_true")
    args = parser.parse_args()
    try:
        apply(args.root, args.bundle)
        return 0
    except Exception as exc:
        print(f"rootfs-apply rejected bundle: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
