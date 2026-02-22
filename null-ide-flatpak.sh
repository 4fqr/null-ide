#!/bin/bash
export ELECTRON_IS_DEV=0
export ELECTRON_FORCE_IS_PACKAGED=true
export NODE_ENV=production
export ELECTRON_ENABLE_LOGGING=1
export ELECTRON_ENABLE_STACK_DUMPING=1
export TMPDIR="${TMPDIR:-/var/tmp}"

APP_DIR="/app/lib/null-ide"

if [ -x "/app/bin/zypak-wrapper" ]; then
    exec /app/bin/zypak-wrapper /app/lib/framework/electron "$APP_DIR" "$@"
else
    exec /app/lib/framework/electron "$APP_DIR" "$@"
fi
