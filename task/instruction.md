Harden `/app/src/rootfs_apply.py`, a privileged root-filesystem delta applier. The program must keep the existing command-line interface:

`python3 /app/src/rootfs_apply.py --root /app/target --bundle /app/fixtures/bundle.json`

It must also accept `--force-fallback`; the verifier uses that flag to exercise the implementation when an `openat2`-style fast path is unavailable. The flag must not weaken the security guarantees.

The bundle is JSON with `format: 1` and an ordered `operations` array. Paths are canonical slash-separated paths relative to the target root: they may not be empty, absolute, contain NUL, `..`, `.`, or empty components. Operations are applied in order:

- `mkdir` creates or updates a directory.
- `write` creates or replaces a regular file; its `data_b64` value is base64 content.
- `symlink` creates an inert symbolic link. Its `target` is link text and must never be followed while applying the bundle.
- `hardlink` creates `path` as a hardlink to an already-existing regular-file `target` in the root.
- `rename` moves `src` to `dst`; both names must remain in the root.
- `unlink` removes one existing object, and succeeds if the object is already absent.
- `whiteout` removes the named object recursively, including a directory and all descendants.
- `opaque` requires an existing directory and removes its children while preserving the directory itself.

Parent directories must already exist unless created by an earlier operation. A structural operation is completed before its metadata is applied. Metadata fields, when present, are `mode`, `uid`, `gid`, `mtime_ns`, and `xattrs`; xattr values are base64 strings. The canonical order is ownership, mode, xattrs, then mtime. Only ordinary files, directories, symlinks, and hardlinks are supported; device nodes, FIFOs, sockets, setuid/setgid bits, and xattr names outside `user.*` must be rejected.

Treat `/app/fixtures/bundle.json` and `/app/target` as untrusted. A rejected bundle must return a non-zero exit status and leave the target unchanged. A successful bundle must not modify any path outside the target root, must not follow attacker-created symlinks, and must not leave a partially applied target if an operation fails. Preserve the documented benign semantics, including whiteout-over-directory, opaque directories, sticky-bit directory modes, hardlink identity, and per-object metadata.

Do not modify `/app/fixtures/bundle.json`. Your deliverable is the repaired `/app/src/rootfs_apply.py`; it will be executed on fresh verifier-generated bundles with different names, operation order, metadata, and attack combinations.
