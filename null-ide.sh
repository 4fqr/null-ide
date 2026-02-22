#!/bin/bash
export ELECTRON_IS_DEV=0
export ELECTRON_FORCE_IS_PACKAGED=true
cd /app/lib/null-ide
exec /app/bin/zypak-wrapper /app/lib/framework/electron /app/lib/null-ide "$@"
