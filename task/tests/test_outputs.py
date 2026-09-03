"""Black-box tests for the privileged rootfs delta applier."""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import random
import shutil
import stat
import subprocess
import tempfile
import threading
from pathlib import Path

import pytest


APP = Path("/app/src/rootfs_apply.py")
TARGET = Path("/app/target")
CANARY_TARGET = "__VERIFIER_OUTSIDE_CANARY__"
GENERATOR_SEED = b"rootfs-delta-hardening/submission-cohort/v1"
IMMUTABLE_INPUTS = {
    Path("/app/fixtures/bundle.json"): "144ebe90ebdbaa5fbe6bbd151c5fd72be37658d39399bd728b1c81ffe752b4d0",
    Path("/app/SECURITY_SPEC.md"): "b91d3ef1fecabaf27b1f4e1a8a86c7e5b1984fa157485dadc608b7d2834669d3",
}


@pytest.fixture(scope="session", autouse=True)
def documented_verifier_umask():
    """Pin the inherited creation mask to the documented value for every graded run."""
    previous = os.umask(0o022)
    try:
        yield
    finally:
        os.umask(previous)


def enc(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def nofollow_sha256(path: Path) -> str:
    """Hash an immutable regular file without following any path symlink."""
    current = Path(path.anchor)
    for component in path.parts[1:-1]:
        current /= component
        st = os.lstat(current)
        assert stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode), f"immutable input parent is not a real directory: {current}"
    terminal = os.lstat(path)
    assert stat.S_ISREG(terminal.st_mode), f"immutable input is not a regular file: {path}"
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        assert stat.S_ISREG(os.fstat(fd).st_mode), f"immutable input is not a regular file: {path}"
        digest = hashlib.sha256()
        while chunk := os.read(fd, 1024 * 1024):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


@functools.cache
def submitted_artifact_digest() -> str:
    """Pin the cohort to one no-follow read of the submitted artifact."""
    return nofollow_sha256(APP)


def submission_rng(domain: str) -> random.Random:
    """Return a deterministic, domain-separated RNG for this exact submission."""
    material = b"\0".join((GENERATOR_SEED, domain.encode("ascii"), bytes.fromhex(submitted_artifact_digest())))
    return random.Random(int.from_bytes(hashlib.sha256(material).digest(), "big"))


def initial_tree(root: Path, canary: Path | None = None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "seed" / "sub").mkdir(parents=True)
    (root / "seed" / "keep.txt").write_bytes(b"keep-this")
    (root / "seed" / "old.txt").write_bytes(b"old-data")
    os.link(root / "seed" / "keep.txt", root / "seed" / "keep-alias.txt")
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


def populate_canary(canary: Path) -> None:
    """Create external objects that every path-bearing operation could corrupt."""
    (canary / "outside-source").write_bytes(b"outside-source-must-not-change")
    (canary / "victim-dir" / "nested").mkdir(parents=True)
    (canary / "victim-dir" / "keep.txt").write_bytes(b"keep-outside-tree")
    (canary / "victim-dir" / "nested" / "leaf.txt").write_bytes(b"keep-outside-leaf")
    os.chmod(canary / "outside-source", 0o640)
    os.chmod(canary / "victim-dir", 0o750)
    fixed = 1_700_030_000_000_000_000
    for path in (
        canary / "outside-source",
        canary / "victim-dir" / "keep.txt",
        canary / "victim-dir" / "nested" / "leaf.txt",
        canary / "victim-dir" / "nested",
        canary / "victim-dir",
    ):
        os.utime(path, ns=(fixed, fixed), follow_symlinks=False)


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


def outside_snapshot(root: Path) -> tuple[tuple, dict[str, tuple]]:
    """Snapshot the canary directory itself as well as every descendant."""
    st = os.lstat(root)
    xattrs = []
    try:
        xattrs = [
            (key, os.getxattr(root, key, follow_symlinks=False))
            for key in sorted(os.listxattr(root, follow_symlinks=False))
            if key.startswith("user.")
        ]
    except OSError:
        pass
    metadata = (stat.S_IFMT(st.st_mode), stat.S_IMODE(st.st_mode), st.st_uid, st.st_gid, st.st_mtime_ns, tuple(xattrs))
    return metadata, tree_snapshot(root)


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
    """Independent final-state oracle for valid bundles, using one conforming metadata sequence."""
    for op in operations:
        kind = op["op"]
        if kind == "mkdir":
            path = root / op["path"]
            if not path.exists():
                path.mkdir()
        elif kind == "write":
            path = root / op["path"]
            if os.path.lexists(path):
                if path.is_dir() and not path.is_symlink():
                    raise AssertionError("write over directory")
                path.unlink()
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
        {"format": 1, "operations": [
            {"op": "write", "path": "seed/link", "data_b64": enc(b"terminal-symlink-replaced"), "mode": 0o600, "mtime_ns": 1_700_000_105_000_000_000, "xattrs": {"user.replacement": enc(b"fresh")}},
            {"op": "mkdir", "path": "seed", "mode": 0o755, "mtime_ns": 1_700_000_103_000_000_000},
        ]},
    ]


def generated_valid_bundles() -> list[dict]:
    """Generate fresh-looking valid bundles so behavior cannot be keyed to sample names."""
    names = ["amber", "cobalt", "juniper", "lattice", "quartz", "saffron"]
    random.Random(0xD17A5E).shuffle(names)
    first, second, third = names[:3]
    return [
        {"format": 1, "operations": [
            {"op": "mkdir", "path": first, "mode": 0o755},
            {"op": "mkdir", "path": f"{first}/{second}", "mode": 0o1777, "uid": 1001, "gid": 1002},
            {"op": "write", "path": f"{first}/{second}/{third}", "data_b64": enc(b"generated-a"), "xattrs": {"user.role": enc(b"runtime")}},
            {"op": "hardlink", "path": f"{first}/{second}/{third}-alias", "target": f"{first}/{second}/{third}"},
            {"op": "rename", "src": f"{first}/{second}/{third}-alias", "dst": f"{first}/{second}/moved", "mode": 0o640, "mtime_ns": 1_700_001_002_000_000_000},
            {"op": "symlink", "path": f"{first}/current", "target": f"{second}/{third}"},
            {"op": "unlink", "path": "seed/old.txt"},
            {"op": "mkdir", "path": f"{first}/empty", "mode": 0o755},
            {"op": "opaque", "path": f"{first}/{second}"},
            {"op": "write", "path": f"{first}/{second}/after", "data_b64": enc(b"generated-b"), "mode": 0o600},
            {"op": "mkdir", "path": first, "mode": 0o755, "mtime_ns": 1_700_001_001_000_000_000},
            {"op": "mkdir", "path": "seed", "mode": 0o755, "mtime_ns": 1_700_001_003_000_000_000},
        ]},
        {"format": 1, "operations": [
            {"op": "mkdir", "path": second, "mode": 0o755},
            {"op": "write", "path": f"{second}/old", "data_b64": enc(b"old")},
            {"op": "whiteout", "path": f"{second}/old"},
            {"op": "mkdir", "path": f"{second}/tree", "mode": 0o755},
            {"op": "write", "path": f"{second}/tree/file", "data_b64": enc(b"before")},
            {"op": "whiteout", "path": f"{second}/tree"},
            {"op": "mkdir", "path": f"{second}/tree", "mode": 0o1777},
            {"op": "write", "path": f"{second}/tree/file2", "data_b64": enc(b"after")},
        ]},
        {"format": 1, "operations": [
            {"op": "mkdir", "path": third, "mode": 0o755},
            {"op": "hardlink", "path": f"{third}/linked", "target": "seed/keep.txt", "mode": 0o600, "mtime_ns": 1_700_001_004_000_000_000, "xattrs": {"user.link": enc(b"shared")}},
            {"op": "write", "path": "seed/keep-alias.txt", "data_b64": enc(b"replacement"), "mode": 0o640},
            {"op": "rename", "src": f"{third}/linked", "dst": f"{third}/moved"},
            {"op": "write", "path": f"{third}/new", "data_b64": enc(b"new-object")},
            {"op": "mkdir", "path": "seed", "mode": 0o755, "mtime_ns": 1_700_001_005_000_000_000},
        ]},
    ]


def fresh_generated_valid_bundles() -> list[dict]:
    """Build deterministic but non-literal bundles from several independent seeds."""
    bundles = []
    for seed in (0xA11CE, 0xBADC0DE, 0xC0FFEE, 0xFACEFEED):
        rng = random.Random(seed)
        root = f"pkg-{rng.randrange(1000, 9999)}"
        left = f"left-{rng.randrange(1000, 9999)}"
        right = f"right-{rng.randrange(1000, 9999)}"
        payload = f"payload-{rng.randrange(1000, 9999)}"
        alias = f"alias-{rng.randrange(1000, 9999)}"
        moved = f"moved-{rng.randrange(1000, 9999)}"
        stamp = 1_700_010_000_000_000_000 + seed
        children = [
            {"op": "mkdir", "path": f"{root}/{left}", "mode": rng.choice([0o755, 0o750])},
            {"op": "mkdir", "path": f"{root}/{right}", "mode": rng.choice([0o755, 0o755])},
        ]
        rng.shuffle(children)
        independent_tail = [
            {"op": "symlink", "path": f"{root}/current", "target": f"{left}/{payload}"},
            {"op": "unlink", "path": "seed/old.txt"},
        ]
        rng.shuffle(independent_tail)
        tail = [
            *independent_tail,
            {"op": "mkdir", "path": f"{root}/discard", "mode": 0o755},
            {"op": "write", "path": f"{root}/discard/temporary", "data_b64": enc(b"discard-me")},
            {"op": "whiteout", "path": f"{root}/discard"},
            {"op": "mkdir", "path": "seed", "mode": 0o755, "mtime_ns": stamp},
        ]
        bundles.append({"format": 1, "operations": [
            {"op": "mkdir", "path": root, "mode": 0o755},
            *children,
            {"op": "write", "path": f"{root}/{left}/{payload}", "data_b64": enc(f"payload-{seed}".encode()), "mode": rng.choice([0o600, 0o640]), "mtime_ns": stamp + 1, "xattrs": {"user.seed": enc(str(seed).encode())}},
            {"op": "hardlink", "path": f"{root}/{right}/{alias}", "target": f"{root}/{left}/{payload}", "mode": 0o640, "mtime_ns": stamp + 2},
            {"op": "rename", "src": f"{root}/{right}/{alias}", "dst": f"{root}/{right}/{moved}"},
            {"op": "opaque", "path": f"{root}/{left}"},
            {"op": "write", "path": f"{root}/{left}/after-opaque", "data_b64": enc(b"after-opaque"), "mode": 0o600},
            *tail,
        ]})
    return bundles


def submission_generated_valid_bundles() -> list[dict]:
    """Use a deterministic per-submission namespace while keeping modeled outcomes exact."""
    nonce = f"{submission_rng('valid-v1').getrandbits(64):016x}"
    serial = int(nonce, 16)
    root = f"txn-{nonce}"
    incoming = f"incoming-{nonce}"
    outgoing = f"outgoing-{nonce}"
    payload = f"payload-{nonce}"
    alias = f"alias-{nonce}"
    moved = f"moved-{nonce}"
    stamp = 1_700_020_000_000_000_000 + serial % 1_000_000_000
    uid = 1200 + serial % 97
    gid = 1300 + serial % 89
    return [{"format": 1, "operations": [
        {"op": "mkdir", "path": root, "mode": 0o755},
        {"op": "mkdir", "path": f"{root}/{incoming}", "mode": 0o750},
        {"op": "mkdir", "path": f"{root}/{outgoing}", "mode": 0o1777},
        {"op": "write", "path": f"{root}/{incoming}/{payload}", "data_b64": enc(f"old-{nonce}".encode()), "mode": 0o640, "uid": uid, "gid": gid, "mtime_ns": stamp, "xattrs": {"user.runtime": enc(nonce.encode())}},
        {"op": "hardlink", "path": f"{root}/{outgoing}/{alias}", "target": f"{root}/{incoming}/{payload}"},
        {"op": "rename", "src": f"{root}/{outgoing}/{alias}", "dst": f"{root}/{outgoing}/{moved}", "mode": 0o600, "mtime_ns": stamp + 1},
        {"op": "write", "path": f"{root}/{incoming}/{payload}", "data_b64": enc(f"new-{nonce}".encode()), "mode": 0o644, "mtime_ns": stamp + 2, "xattrs": {"user.replaced": enc(b"fresh-inode")}},
        {"op": "symlink", "path": f"{root}/current", "target": f"{outgoing}/{moved}"},
        {"op": "mkdir", "path": f"{root}/discard", "mode": 0o755},
        {"op": "write", "path": f"{root}/discard/temporary", "data_b64": enc(b"discard")},
        {"op": "whiteout", "path": f"{root}/discard"},
    ]}]


def fresh_unsafe_bundles() -> list[dict]:
    """Generate additional rejection combinations without literal fixture names."""
    bundles = []
    for seed in (0x13579, 0x24680, 0xABCDE):
        rng = random.Random(seed)
        link = f"created-{rng.randrange(1000, 9999)}"
        bundles.append({"format": 1, "operations": [
            {"op": "symlink", "path": f"seed/{link}", "target": "keep.txt"},
            {"op": "write", "path": f"seed/{link}/child", "data_b64": enc(b"x")},
        ]})
    return bundles


def submission_parent_rejection_bundles() -> list[dict]:
    """Exercise every symlink-parent role under a deterministic submission namespace."""
    nonce = f"{submission_rng('unsafe-parent-v1').getrandbits(64):016x}"
    missing = f"missing-{nonce}"
    regular = f"regular-{nonce}"
    link = f"link-{nonce}"
    escape_link = f"escape-{nonce}"
    escaped = f"seed/{escape_link}"
    create_escape = {"op": "symlink", "path": escaped, "target": CANARY_TARGET}

    def through_escape(operation: dict) -> dict:
        return {"format": 1, "operations": [dict(create_escape), operation]}

    return [
        {"format": 1, "operations": [
            {"op": "write", "path": f"{missing}/child", "data_b64": enc(b"x")},
        ]},
        {"format": 1, "operations": [
            {"op": "write", "path": f"seed/{regular}", "data_b64": enc(b"parent-is-file")},
            {"op": "write", "path": f"seed/{regular}/child", "data_b64": enc(b"x")},
        ]},
        {"format": 1, "operations": [
            {"op": "symlink", "path": f"seed/{link}", "target": "keep.txt"},
            {"op": "write", "path": f"seed/{link}/child", "data_b64": enc(b"x")},
        ]},
        through_escape({
            "op": "write", "path": f"{escaped}/outside-write", "data_b64": enc(b"must-not-escape"),
        }),
        through_escape({
            "op": "mkdir", "path": f"{escaped}/outside-directory", "mode": 0o755,
        }),
        through_escape({
            "op": "symlink", "path": f"{escaped}/outside-link", "target": "inert-text",
        }),
        through_escape({
            "op": "hardlink", "path": f"seed/stolen-{nonce}", "target": f"{escaped}/outside-source",
            "mode": 0o600, "mtime_ns": 1_700_030_001_000_000_000,
            "xattrs": {"user.escape": enc(b"must-not-touch-source")},
        }),
        through_escape({
            "op": "hardlink", "path": f"{escaped}/outside-hardlink", "target": "seed/keep.txt",
        }),
        through_escape({"op": "unlink", "path": f"{escaped}/outside-source"}),
        through_escape({"op": "whiteout", "path": f"{escaped}/victim-dir"}),
        through_escape({"op": "opaque", "path": f"{escaped}/victim-dir"}),
        through_escape({
            "op": "rename", "src": f"{escaped}/outside-source", "dst": f"seed/moved-in-{nonce}",
        }),
        through_escape({
            "op": "rename", "src": "seed/old.txt", "dst": f"{escaped}/moved-out-{nonce}",
        }),
    ]


def submission_initial_graph_names() -> dict[str, str]:
    """Return deterministic per-submission names for initial-object-graph attacks."""
    nonce = f"{submission_rng('initial-graph-v1').getrandbits(64):016x}"
    return {
        "subject": f"seed/audit-subject-{nonce}",
        "internal_alias": f"seed/audit-alias-{nonce}",
        "directory": f"seed/audit-directory-{nonce}",
        "fifo": f"seed/audit-pipe-{nonce}",
        "symlink": f"seed/audit-symlink-{nonce}",
        "moved_symlink": f"seed/audit-moved-symlink-{nonce}",
        "probe": f"seed/audit-probe-{nonce}",
    }


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
    current = Path(APP.anchor)
    for component in APP.parts[1:]:
        current /= component
        assert not current.is_symlink(), f"graded artifact path contains symlink: {current}"
    assert APP.resolve(strict=True) == APP.absolute()


def test_immutable_agent_inputs_match_pinned_bytes_without_symlinks():
    """The public fixture and semantics document must remain pristine after the agent run."""
    for path, expected_digest in IMMUTABLE_INPUTS.items():
        assert nofollow_sha256(path) == expected_digest, f"immutable input changed: {path}"


def test_submission_derived_generators_are_reproducible():
    """Identical submitted bytes must always produce an identical graded cohort."""
    assert submission_generated_valid_bundles() == submission_generated_valid_bundles()
    assert submission_parent_rejection_bundles() == submission_parent_rejection_bundles()
    assert submission_initial_graph_names() == submission_initial_graph_names()


@pytest.mark.parametrize("fallback", [False, True])
def test_valid_bundles_preserve_canonical_semantics(fallback: bool):
    """Valid bundles must reproduce complete tree, metadata, whiteout, opaque, and link semantics in both modes."""
    for index, bundle in enumerate(valid_bundles() + generated_valid_bundles() + fresh_generated_valid_bundles() + submission_generated_valid_bundles()):
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
        if index == 1:
            assert actual["seed/after-opaque"][1] == 0o644


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("bundle", [
    {"format": 1, "operations": [{"op": "write", "path": "../escape", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "/absolute", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "pivot/out", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "missing/child", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "a/./b", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "a//b", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "a/", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "write", "path": "a\0b", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "symlink", "path": "seed/created-link", "target": "keep.txt"}, {"op": "write", "path": "seed/created-link/child", "data_b64": enc(b"x")}]},
    {"format": 1, "operations": [{"op": "rename", "src": "seed/old.txt", "dst": "seed/keep.txt"}]},
    {"format": 1, "operations": [{"op": "hardlink", "path": "seed/out", "target": "seed/link"}]},
    {"format": 1, "operations": [{"op": "hardlink", "path": "seed/keep.txt", "target": "seed/old.txt"}]},
    {"format": 1, "operations": [{"op": "write", "path": "seed/sub", "data_b64": enc(b"file-over-directory")}]},
    {"format": 1, "operations": [{"op": "mkdir", "path": "seed/old.txt"}]},
    {"format": 1, "operations": [{"op": "mkdir", "path": "seed/link"}]},
    {"format": 1, "operations": [{"op": "opaque", "path": "seed/old.txt"}]},
    {"format": 1, "operations": [{"op": "symlink", "path": "seed/sub", "target": "elsewhere"}]},
    {"format": 1, "operations": [{"op": "write", "path": "seed/partial", "data_b64": enc(b"x")}, {"op": "unknown", "path": "seed/no"}]},
    {"format": 1, "operations": [{"op": "write", "path": "seed/bad", "data_b64": enc(b"x"), "mode": 0o4755}]},
    {"format": 1, "operations": [{"op": "write", "path": "seed/bad", "data_b64": enc(b"x"), "xattrs": {"security.capability": enc(b"x")}}]},
    {"format": 1, "operations": [{"op": "mkdir", "path": "seed/bad-dir", "mode": 0o2755}]},
    {"format": 1, "operations": [{"op": "symlink", "path": "seed/bad-link", "target": "keep.txt", "mode": 0o4755}]},
    {"format": 1, "operations": [{"op": "hardlink", "path": "seed/bad-link", "target": "seed/keep.txt", "xattrs": {"security.capability": enc(b"x")}}]},
    {"format": 1, "operations": [{"op": "rename", "src": "seed/old.txt", "dst": "seed/bad-move", "mode": 0o4755}]},
    {"format": 1, "operations": [{"op": "hardlink", "path": "seed/transaction-link", "target": "seed/keep.txt", "mode": 0o600}, {"op": "rename", "src": "seed/old.txt", "dst": "seed/transaction-move"}, {"op": "unknown", "path": "seed/late"}]},
] + fresh_unsafe_bundles() + submission_parent_rejection_bundles())
def test_unsafe_bundles_reject_without_partial_writes(bundle: dict, fallback: bool):
    """Unsafe paths reject atomically without changing either root or populated outside canary."""
    if TARGET.exists():
        shutil.rmtree(TARGET)
    canary = Path(tempfile.mkdtemp(prefix=".outside-canary-", dir=TARGET.parent))
    try:
        populate_canary(canary)
        initial_tree(TARGET, canary)
        before = tree_snapshot(TARGET)
        outside_before = outside_snapshot(canary)
        prepared = json.loads(json.dumps(bundle))
        for op in prepared["operations"]:
            if op.get("target") == CANARY_TARGET:
                op["target"] = str(canary)
        result = run_bundle(prepared, fallback=fallback)
        assert result.returncode != 0
        assert tree_snapshot(TARGET) == before
        assert outside_snapshot(canary) == outside_before
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
            result = run_bundle({"format": 1, "operations": [{"op": "write", "path": "probe", "data_b64": enc(b"must-not-write")}]}, root=link_root)
            assert result.returncode != 0
            assert tree_snapshot(TARGET) == original
        finally:
            link_root.unlink(missing_ok=True)
    finally:
        bad.unlink(missing_ok=True)


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("hazard", [
    "external-hardlink-referenced",
    "external-hardlink-unreferenced",
    "external-symlink-hardlink",
    "setuid-file",
    "setgid-directory",
    "setgid-root",
    "fifo",
])
def test_unsafe_initial_object_graph_is_rejected_unchanged(hazard: str, fallback: bool):
    """Initial external inode aliases, set-ID entries, and special objects must fail before mutation."""
    copy_initial(TARGET)
    canary = Path(tempfile.mkdtemp(prefix=".initial-graph-canary-", dir=TARGET.parent))
    try:
        populate_canary(canary)
        names = submission_initial_graph_names()
        operation_target = "seed/keep.txt"
        if hazard in {"external-hardlink-referenced", "external-hardlink-unreferenced"}:
            subject = TARGET / names["subject"]
            subject.write_bytes(b"closed-graph-subject")
            os.link(subject, TARGET / names["internal_alias"])
            os.link(subject, canary / "external-alias")
            if hazard == "external-hardlink-referenced":
                operation_target = names["subject"]
        elif hazard == "external-symlink-hardlink":
            link = TARGET / names["symlink"]
            link.symlink_to("keep.txt")
            os.link(link, canary / "external-symlink-alias", follow_symlinks=False)
        elif hazard == "setuid-file":
            subject = TARGET / names["subject"]
            subject.write_bytes(b"setuid-subject")
            os.chmod(subject, 0o4755)
        elif hazard == "setgid-directory":
            directory = TARGET / names["directory"]
            directory.mkdir()
            os.chmod(directory, 0o2755)
        elif hazard == "setgid-root":
            os.chmod(TARGET, 0o2755)
        elif hazard == "fifo":
            os.mkfifo(TARGET / names["fifo"], 0o600)
        else:
            raise AssertionError(hazard)

        before = tree_snapshot(TARGET)
        outside_before = outside_snapshot(canary)
        if hazard == "external-symlink-hardlink":
            bundle = {"format": 1, "operations": [{
                "op": "rename",
                "src": names["symlink"],
                "dst": names["moved_symlink"],
                "uid": 1234,
                "gid": 1235,
                "mtime_ns": 1_700_040_000_000_000_000,
            }]}
        else:
            bundle = {"format": 1, "operations": [{
                "op": "hardlink",
                "path": names["probe"],
                "target": operation_target,
                "mode": 0o600,
                "mtime_ns": 1_700_040_000_000_000_000,
                "xattrs": {"user.audit": enc(b"must-not-cross-root")},
            }]}
        result = run_bundle(bundle, fallback=fallback)
        assert result.returncode != 0
        assert tree_snapshot(TARGET) == before
        assert outside_snapshot(canary) == outside_before
    finally:
        shutil.rmtree(canary, ignore_errors=True)


@pytest.mark.parametrize("bundle", [
    {"format": 2, "operations": []},
    {"format": 1, "operations": {}},
    {"format": 1, "operations": [{"op": "write", "path": "seed/bad", "data_b64": "%%%"}]},
    {"format": 1, "operations": [{"op": "write", "path": "seed/bad", "data_b64": enc(b"x"), "xattrs": []}]},
])
def test_malformed_bundles_reject_without_writes(bundle: dict):
    """Schema and metadata-shape errors must be rejected atomically."""
    copy_initial(TARGET)
    before = tree_snapshot(TARGET)
    result = run_bundle(bundle)
    assert result.returncode != 0
    assert tree_snapshot(TARGET) == before


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
        assert not violations, "; ".join(violations)
    finally:
        shutil.rmtree(parent, ignore_errors=True)
        shutil.rmtree(canary, ignore_errors=True)
