#!/bin/zsh
# Usage: relay-pull-launch.sh — launchd entry: reads the relay home token from the login Keychain and runs relay_pull.py.
set -euo pipefail
cd "${0:A:h}/.."
export PYTHONPATH=$PWD${PYTHONPATH:+:$PYTHONPATH}
export AIFILTER_RELAY_URL=${AIFILTER_RELAY_URL:-https://YOUR-WORKER.workers.dev}
if [[ "$AIFILTER_RELAY_URL" == "https://YOUR-WORKER.workers.dev" || -z "${AIFILTER_RELAY_TOKEN:-}" ]]; then
    exit 0
fi
exec .venv/bin/python scripts/relay_pull.py "$@"
