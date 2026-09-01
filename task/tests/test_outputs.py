"""Black-box tests for the privileged rootfs delta applier."""

from __future__ import annotations

import base64
import json
import os
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest


APP = Path("/app/src/rootfs_apply.py")
TARGET = Path("/app/target")


def enc(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def initial_tree(root: Path, canary: Path | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "seed" / "sub").mkdir(parents=True)
    (root / "seed" / "keep.txt").write_bytes(b"keep-this")
    (root / "seed" / "old.txt").write_bytes(b"old-data")
    (root / "seed" / "sub" / "nested.txt").write_bytes(b"nested")
    os.chmod(root / "seed", 0o755)
    os.chmod(root / "seed" / "keep.txt", 0o640)
    os.utime(root / "seed" / "keep.txt", ns=(1_700_000_010_000_000_000,) * 2)
    (root / "seed" / "link").symlink_to("keep.txt")
    fixed = 1_700_000_000_000_000_000
    for path in (root / "seed", root / "seed" / "sub", root / "seed" / "old.txt", root / "seed" / "link"):
        os.utime(path, ns=(fixed, fixed), follow_symlinks=False)
    if canary is not None:
        (root / "pivot").symlink_to(canary)


def tree_snapshot(root: Path) -> dict[str, tuple]:
    result: dict[str, tuple] = {}
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        dirs[:] = [name for name in dirs if not (current_path / name).is_symlink()]
        for name in dirs + files:
            path = current_path / name
            rel = str(path.relative_to(root))
            st = os.lstat(path)
            mode = stat.S_IMODE(st.st_mode)
            xattrs = []
            try:
                xattrs = [(key, os.getxattr(path, key, follow_symlinks=False)) for key in sorted(os.listxattr(path, follow_symlinks=False)) if key.startswith("user.")]
            except OSError:
                pass
            if stat.S_ISREG(st.st_mode):
                body = path.read_bytes()
                link_key = (st.st_dev, st.st_ino)
            elif stat.S_ISLNK(st.st_mode):
                body = os.readlink(path)
                link_key = None
            else:
                body = None
                link_key = None
            result[rel] = (stat.S_IFMT(st.st_mode), mode, st.st_uid, st.st_gid, st.st_mtime_ns, body, tuple(xattrs), link_key)
    return result


def copy_initial(root: Path) -> None:
    if root.exists() or root.is_symlink():
        shutil.rmtree(root)
    initial_tree(root)


def run_bundle(bundle: dict, *, fallback: bool = False, root: Path = TARGET, timeout: float = 8.0) -> subprocess.CompletedProcess[str]:
    bundle_path = Path(tempfile.mktemp(prefix="bundle-", suffix=".json", dir="/tmp"))
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    command = ["python3", str(APP), "--root", str(root), "--bundle", str(bundle_path)]
    if fallback:
        command.append("--force-fallback")
    try:
        return subprocess.run(command, text=True, capture_output=True, timeout=timeout)
    finally:
        bundle_path.unlink(missing_ok=True)


def model_apply(root: Path, operations: list[dict]) -> None:
    """Independent path-based oracle for valid bundles only."""
    for op in operations:
        kind = op["op"]
        if kind == "mkdir":
            path = root / op["path"]
            if not path.exists():
                path.mkdir()
        elif kind == "write":
            path = root / op["path"]
            path.write_bytes(base64.b64decode(op["data_b64"]))
        elif kind == "symlink":
            path = root / op["path"]
            if os.path.lexists(path):
                path.unlink()
            path.symlink_to(op["target"])
        elif kind == "hardlink":
            os.link(root / op["target"], root / op["path"])
        elif kind == "rename":
            os.rename(root / op["src"], root / op["dst"])
        elif kind == "unlink":
            path = root / op["path"]
            if path.is_dir() and not path.is_symlink():
                path.rmdir()
            else:
                path.unlink(missing_ok=True)
        elif kind == "whiteout":
            path = root / op["path"]
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink(missing_ok=True)
        elif kind == "opaque":
            path = root / op["path"]
            for child in path.iterdir():
                if child.is_dir() and not child.is_symlink():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        else:
            raise AssertionError(kind)
        path = root / (op.get("dst") if kind == "rename" else op.get("path", ""))
        if kind in {"mkdir", "write", "symlink", "hardlink", "rename"}:
            if "uid" in op or "gid" in op:
                st = os.lstat(path)
                os.chown(path, op.get("uid", st.st_uid), op.get("gid", st.st_gid), follow_symlinks=False)
            if "mode" in op:
                os.chmod(path, op["mode"], follow_symlinks=False)
            for name, value in op.get("xattrs", {}).items():
                os.setxattr(path, name, base64.b64decode(value), follow_symlinks=False)
            if "mtime_ns" in op:
                os.utime(path, ns=(op["mtime_ns"], op["mtime_ns"]), follow_symlinks=False)


def valid_bundles() -> list[dict]:
    return [
        {"format": 1, "operations": [
            {"op": "mkdir", "path": "var", "mode": 0o755, "mtime_ns": 1_700_000_100_000_000_000},
            {"op": "mkdir", "path": "var/cache", "mode": 0o1777, "uid": 1000, "gid": 1000, "mtime_ns": 1_700_000_101_000_000_000},
            {"op": "write", "path": "var/cache/blob", "data_b64": enc(b"fresh-cache"), "mode": 0o640, "mtime_ns": 1_700_000_102_000_000_000, "xattrs": {"user.kind": enc(b"cache")}},
            {"op": "hardlink", "path": "var/cache/blob-copy", "target": "var/cache/blob"},
            {"op": "rename", "src": "var/cache/blob-copy", "dst": "var/cache/blob-renamed", "mode": 0o600},
            {"op": "symlink", "path": "var/current", "target": "cache/blob"},
            {"op": "mkdir", "path": "var/cache", "mode": 0o1777, "uid": 1000, "gid": 1000, "mtime_ns": 1_700_000_103_000_000_000},
            {"op": "mkdir", "path": "var", "mode": 0o755, "mtime_ns": 1_700_000_104_000_000_000},
        ]},
        {"format": 1, "operations": [
            {"op": "mkdir", "path": "seed/work", "mode": 0o755},
            {"op": "write", "path": "seed/work/new", "data_b64": enc(b"new")},
            {"op": "opaque", "path": "seed"},
            {"op": "write", "path": "seed/after-opaque", "data_b64": enc(b"after")},
            {"op": "mkdir", "path": "seed/sticky", "mode": 0o1777},
            {"op": "mkdir", "path": "seed", "mode": 0o755, "mtime_ns": 1_700_000_103_000_000_000},
        ]},
        {"format": 1, "operations": [
            {"op": "mkdir", "path": "release", "mode": 0o755},
            {"op": "write", "path": "release/a", "data_b64": enc(b"a")},
            {"op": "write", "path": "release/b", "data_b64": enc(b"b")},
            {"op": "whiteout", "path": "seed/sub"},
            {"op": "whiteout", "path": "seed/old.txt"},
            {"op": "unlink", "path": "seed/does-not-exist"},
            {"op": "mkdir", "path": "seed", "mode": 0o755, "mtime_ns": 1_700_000_103_000_000_000},
        ]},
    ]


def expected_for(bundle: dict, fallback_root: Path) -> dict[str, tuple]:
    initial_tree(fallback_root)
    model_apply(fallback_root, bundle["operations"])
    return tree_snapshot(fallback_root)


def comparable(actual: dict[str, tuple], expected: dict[str, tuple], bundle: dict) -> tuple[dict, dict]:
    """Only compare mtime when it is fixed by the initial tree or explicitly supplied."""
    timed = {"seed", "seed/sub", "seed/keep.txt", "seed/old.txt", "seed/link"}
    for op in bundle["operations"]:
        if "mtime_ns" in op:
            timed.add(op.get("dst", op.get("path")))
    def normalize_links(snapshot: dict[str, tuple]) -> dict[str, tuple]:
        groups: dict[tuple, int] = {}
        next_group = 0
        normalized = {}
        for name in sorted(snapshot):
            item = snapshot[name]
            key = item[-1]
            if key is not None:
                if key not in groups:
                    groups[key] = next_group
                    next_group += 1
                item = (*item[:-1], groups[key])
            normalized[name] = item
        return normalized

    left, right = normalize_links(actual), normalize_links(expected)
    for name in set(left) | set(right):
        if name not in timed and name in left:
            left[name] = (*left[name][:4], None, *left[name][5:])
        if name not in timed and name in right:
            right[name] = (*right[name][:4], None, *right[name][5:])
    return left, right


def test_repaired_program_is_the_declared_artifact():
    """The agent must leave the repaired executable source at /app/src/rootfs_apply.py."""
    assert APP.is_file()


@pytest.mark.parametrize("fallback", [False, True])
def test_valid_bundles_preserve_canonical_semantics(fallback: bool):
    """Valid bundles must reproduce complete tree, metadata, whiteout, opaque, and link semantics in both modes."""
    for index, bundle in enumerate(valid_bundles()):
        copy_initial(TARGET)
        with tempfile.TemporaryDirectory(prefix="expected-") as expected_dir:
            expected_root = Path(expected_dir) / "target"
            expected = expected_for(bundle, expected_root)
        result = run_bundle(bundle, fallback=fallback)
        assert result.returncode == 0, result.stderr
        actual = tree_snapshot(TARGET)
        assert comparable(actual, expected, bundle)[0] == comparable(actual, expected, bundle)[1], (index, actual, expected)
        regular = {key: value[-1] for key, value in actual.items() if value[0] == stat.S_IFREG}
        if index == 0:
            assert regular["var/cache/blob"] == regular["var/cache/blob-renamed"]


@pytest.mark.parametrize("bundle", [
    {"format": 1, "operations": [{"op": "write", "path": "../escape", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "/absolute", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "pivot/out", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "hardlink", "path": "seed/out", "target": "seed/link"}]},
    {"format": 1, "operations": [{"op": "write", "path": "seed/partial", "data_b64": enc(b"x")}, {"op": "unknown", "path": "seed/no"}]},
    {"format": 1, "operations": [{"op": "write", "path": "seed/bad", "data_b64": enc(b"x"), "mode": 0o4755}]},
    {"format": 1, "operations": [{"op": "write", "path": "seed/bad", "data_b64": enc(b"x"), "xattrs": {"security.capability": enc(b"x")}}]},
])
def test_unsafe_bundles_reject_without_partial_writes(bundle: dict):
    """Unsafe paths, links, metadata, and late failures require non-zero rejection with an unchanged target."""
    if TARGET.exists():
        shutil.rmtree(TARGET)
    canary = Path(tempfile.mkdtemp(prefix="outside-canary-"))
    try:
        initial_tree(TARGET, canary)
        before = tree_snapshot(TARGET)
        result = run_bundle(bundle)
        assert result.returncode != 0
        assert tree_snapshot(TARGET) == before
        assert not list(canary.iterdir())
    finally:
        shutil.rmtree(canary, ignore_errors=True)


def test_invalid_json_and_root_symlink_are_rejected():
    """Malformed input and a symlink supplied as the root must fail before any external path is touched."""
    copy_initial(TARGET)
    original = tree_snapshot(TARGET)
    bad = Path(tempfile.mktemp(prefix="invalid-", suffix=".json", dir="/tmp"))
    bad.write_text("{not json", encoding="utf-8")
    try:
        result = subprocess.run(["python3", str(APP), "--root", str(TARGET), "--bundle", str(bad)], text=True, capture_output=True, timeout=8)
        assert result.returncode != 0
        assert tree_snapshot(TARGET) == original
        link_root = TARGET.with_name("target-link")
        link_root.unlink(missing_ok=True)
        link_root.symlink_to(TARGET)
        try:
            result = run_bundle({"format": 1, "operations": []}, root=link_root)
            assert result.returncode != 0
        finally:
            link_root.unlink(missing_ok=True)
    finally:
        bad.unlink(missing_ok=True)


def test_path_swap_race_has_zero_canary_violations_across_64_runs():
    """A deterministic 64-run path-component swap race must never write the outside canary."""
    parent = Path(tempfile.mkdtemp(prefix="race-parent-"))
    canary = Path(tempfile.mkdtemp(prefix="race-canary-"))
    bundle = {"format": 1, "operations": [{"op": "write", "path": "swap/inside/payload", "data_b64": enc(b"must-stay-inside")}]}
    violations: list[str] = []
    try:
        for run in range(64):
            root = parent / "target"
            if root.exists() or root.is_symlink():
                shutil.rmtree(root)
            root.mkdir()
            (root / "swap" / "inside").mkdir(parents=True)
            (root / "swap" / "inside" / "base").write_bytes(b"base")
            marker = canary / "marker"
            marker.write_bytes(f"marker-{run}".encode())
            stop = threading.Event()

            def mutate() -> None:
                while not stop.is_set():
                    moved = root / "swap" / "moved"
                    inside = root / "swap" / "inside"
                    try:
                        if inside.is_dir() and not inside.is_symlink():
                            os.rename(inside, moved)
                            os.symlink(canary, inside)
                            inside.unlink()
                            os.rename(moved, inside)
                    except (FileNotFoundError, NotADirectoryError, OSError):
                        pass

            thread = threading.Thread(target=mutate, daemon=True)
            thread.start()
            result = run_bundle(bundle, fallback=(run % 2 == 1), root=root, timeout=8.0)
            stop.set()
            thread.join(timeout=1.0)
            if marker.read_bytes() != f"marker-{run}".encode() or len(list(canary.iterdir())) != 1:
                violations.append(f"run {run}: canary changed")
            assert result.returncode in (0, 2), result.stderr
        assert not violations, "; ".join(violations)
    finally:
        shutil.rmtree(parent, ignore_errors=True)
        shutil.rmtree(canary, ignore_errors=True)
