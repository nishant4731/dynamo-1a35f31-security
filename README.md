# Rootfs Delta Hardening

## Overview

This Dynamo task asks an agent to repair a privileged rootfs delta applier. The input format combines ordered filesystem operations, links, whiteouts, opaque directories, metadata, and attacker-controlled paths.

## Approach

The intended repair preserves the visible bundle semantics while making path resolution race resistant, rejecting unsafe object types and metadata, and applying updates atomically. The verifier exercises fresh semantic combinations and a deterministic concurrent path-swap attack.

## Environment

The single pinned Python image contains the visible vulnerable source, semantic specification, sample bundle, and pinned pytest/CTR-F dependencies. Hidden fixtures and expected behavior are mounted only when verification runs.

## Verification

Tests use reproducible, submission-namespaced cohorts and compare complete filesystem trees, bytes, types, hardlink identity, modes, ownership, nanosecond timestamps, and `user.*` xattrs. Unsafe bundles—including hardlink-source and destructive-operation traversal through created symlink parents—must return non-zero while preserving exact inside and populated outside-canary snapshots in normal and forced-fallback modes. A 64-run race harness must produce zero canary violations. The reference solution earns 1.0 and the no-op agent fails.
