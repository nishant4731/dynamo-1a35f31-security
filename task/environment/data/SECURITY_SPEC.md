# Rootfs delta semantics

The visible sample is normative for the benign behavior of the supplied utility. The verifier uses the same semantics on fresh bundles. A path is a canonical relative path: no leading slash, NUL, `..`, `.`, empty component, or trailing slash. Operations are sequential.

`mkdir` creates or updates a directory. `write` replaces a regular file; replacing a non-directory object creates a fresh inode for that directory entry, without following a symlink or changing unrelated hardlink names. `symlink` stores link text without resolving it. `hardlink` requires an existing regular-file target and preserves inode identity, so metadata applied to the new name is visible through every alias. `rename` is an in-root move and rejects an existing destination. `unlink` removes one object and is idempotent. `whiteout` removes a complete subtree. `opaque` clears a directory's children but preserves the directory. The parent must exist at the time of the operation.

After each structural operation, metadata is applied in this exact order: `uid`/`gid`, `mode`, `xattrs`, `mtime_ns`. A write without an explicit mode uses the OS default creation mode `0o666` subject to the process umask; the verifier uses umask `0o022`, so this produces mode `0o644`. Compared fields are permission and sticky-bit mode, uid, gid, nanosecond mtime, and all declared `user.*` xattrs. Device nodes, FIFOs, sockets, setuid/setgid modes, and non-`user.*` xattrs are invalid.

The existing implementation is intentionally unsafe. Preserve the benign semantics while making every operation confined to the target root, race resistant, and failure atomic. Rejection means non-zero exit and no target-tree change; stderr wording is deliberately not prescribed.

The canonical semantics are the rules in this document, not incidental starter quirks. Expected trees are independently generated from this model, and verification includes fresh names, operation orderings, metadata combinations, malformed schemas, and non-empty operations through a symlink root.
