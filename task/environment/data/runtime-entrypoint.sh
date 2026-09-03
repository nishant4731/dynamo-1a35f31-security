#!/bin/sh
set -eu

# Materialize the image-baked empty fixture in the container's writable layer.
# OverlayFS cannot exchange a lower-layer directory with an upper-layer stage.
if [ ! -e /app/target ]; then
    mkdir -m 0755 /app/target
elif [ -d /app/target ] && rmdir /app/target 2>/dev/null; then
    mkdir -m 0755 /app/target
fi

exec "$@"
