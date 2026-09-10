# Rootfs Delta Hardening

## Overview

This Dynamo task asks an agent to repair a privileged rootfs delta applier. The input format combines ordered filesystem operations, links, whiteouts, opaque directories, metadata, and attacker-controlled paths.

## Approach

The intended repair preserves the visible bundle semantics while making root and operation-path resolution race resistant, auditing the initial target as a closed hardlink graph, rejecting unsafe object types and metadata, and publishing a fully prepared generation atomically. The verifier exercises fresh semantic combinations, symlinked root ancestors, a deterministic concurrent path-swap attack, and deterministic abrupt-termination cuts.

## Environment

The single pinned Python image contains the visible vulnerable source, semantic specification, sample bundle, and pinned pytest/CTR-F dependencies. Hidden fixtures and expected behavior are mounted only when verification runs.

## Verification

Tests use reproducible, submission-namespaced cohorts and compare complete filesystem trees, bytes, types, hardlink identity, full special/permission modes, ownership, exact `user.*` xattr maps, and unchanged fixed-time or explicitly supplied nanosecond mtimes. They intentionally ignore atime, ctime, unspecified creation mtimes, and equivalent metadata syscall ordering. Unsafe bundles—including hardlink-source and destructive-operation traversal through created symlink parents—must return non-zero while preserving exact inside and populated outside-canary snapshots in normal and forced-fallback modes. Separate initial-tree attacks cover set-ID and special objects, regular inodes with outside aliases, and hardlinked symlinks; internal regular-file hardlinks remain valid. A symlink in any `--root` component rejects in both resolver modes. A 64-run path race permits zero canary violations, and ten deterministic publication crash cuts permit zero absent or mixed target generations. The reference solution earns 1.0 and the no-op agent fails.
