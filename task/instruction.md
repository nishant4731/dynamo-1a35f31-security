Harden `/app/src/rootfs_apply.py`, a privileged root-filesystem delta applier. The program must keep the existing command-line interface:

`python3 /app/src/rootfs_apply.py --root /app/target --bundle /app/fixtures/bundle.json`

It must also accept `--force-fallback`, which models an unavailable `openat2`-style fast path without weakening any guarantee.

The bundle is JSON with `format: 1` and an ordered `operations` array. Paths are canonical slash-separated paths relative to the target root: they may not be empty, absolute, contain NUL, `..`, `.`, or empty components. Operations are applied in order:

These rules and `/app/SECURITY_SPEC.md`, not unsafe starter quirks, are normative. On benign valid bundles the starter already demonstrates the intended tree effects; confinement and atomicity are intentionally vulnerable. The verifier independently models expected trees with deterministic submission-namespaced names, order, metadata, and attacks. An identical artifact receives an identical cohort. Both CLI modes enforce every rule.

- `mkdir` creates or updates a directory, rejecting an existing non-directory.
- `write` decodes `data_b64` into a fresh regular file, replacing any non-directory (including a terminal symlink) without following it or changing unrelated hardlink names; an existing directory rejects.
- `symlink` stores inert `target` link text, replacing a non-directory but rejecting a directory.
- `hardlink` links `path` to an existing in-root regular-file `target` and rejects an existing destination. Its metadata affects every inode alias.
- `rename` moves in-root `src` to absent `dst`.
- `unlink` removes one object and succeeds when absent.
- `whiteout` recursively removes the named object or subtree.
- `opaque` requires a directory, removes its children, and preserves it.

Parents must already exist unless created earlier. Complete each structural operation before applying optional `mode`, `uid`, `gid`, `mtime_ns`, and base64-valued `xattrs`. Ownership, mode, xattrs, then mtime is one conforming sequence; only final state is required. Compared fields are type/content, hardlink identity, full special/permission mode, uid/gid, exact `user.*` xattrs, and nanosecond mtime for fixed-time unchanged initial paths or outputs with explicit `mtime_ns`. Unspecified creation mtimes, atime, ctime, and unobservable call order are ignored. Valid modes satisfy `mode & ~0o1777 == 0`; setuid/setgid and non-`user.*` xattrs reject. A modeless `write` uses `0o666` under verifier umask `0o022`, yielding `0o644`.

Only regular files/directories, symlinks, and regular-file hardlinks are supported. Before operations, audit root and descendants without following links. Reject setuid/setgid entries and devices, FIFOs, sockets, or other types. Internal regular hardlinks are valid, but their initial graph must be closed over the target: each regular inode's `st_nlink` must equal its in-target directory-entry count, even when operations do not reference it. Every symlink must have `st_nlink == 1`; hardlinked symlinks are unsupported. This unchanged-tree preflight applies in both modes and prevents alias-visible metadata writes outside the root.

The `--root` spelling is a boundary. From `/`, open every component through root as a real directory without following links. Any symlink component rejects non-zero without changing its referenced tree; one-shot `realpath`/`lstat` is insufficient. Under `--force-fallback`, use descriptor-relative per-component `O_NOFOLLOW` walking. This flag does not disable `renameat2` in this Linux environment. Stage the live root only through the opened root descriptor, never through its pathname. A 64-run path-component swap harness alternates both modes with an 8-second bound per run: PASS requires zero outside-canary violations, exit code zero, and the modeled target tree on every synchronized attack; any canary touch, rejection, or tree mismatch fails; a safe implementation should survive indefinitely.

Publication must survive abrupt death, not merely exceptions. Fully metadata-finalize a private stage beside (not inside) the target, then publish so any observer or `SIGKILL` sees exactly the old or complete new target—never absence, internal staging/backup entries, or mixed generations. One viable mechanism is same-parent `renameat2(RENAME_EXCHANGE)` followed by best-effort retired-generation cleanup. The verifier performs ten deterministic attempts: one post-rename and four live-root mutation cuts in each CLI mode. Any absent/mixed state fails; safe publication should survive indefinitely. After `SIGKILL`, only target and outside canary are graded, so a private adjacent retired directory may remain.

Treat `/app/fixtures/bundle.json` and `/app/target` as untrusted. Rejection is non-zero with unchanged target; stderr is ungraded. Success must not modify outside paths, follow attacker-created links, or expose partial failure. Preserve whiteout-over-directory, opaque, sticky-directory, hardlink, and metadata semantics.

Do not modify `/app/fixtures/bundle.json` or `/app/SECURITY_SPEC.md`. Deliver only repaired `/app/src/rootfs_apply.py`; generated bundles vary names, order, metadata, and attacks.
