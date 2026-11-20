#!/bin/bash
# Owner step: start the filter automatically at login and keep it running.
set -euo pipefail
template="$(dirname "$0")/com.example.ai-filter.plist"
agent="$HOME/Library/LaunchAgents/com.example.ai-filter.plist"
mkdir -p "$(dirname "$agent")"
python3 - "$template" "$agent" <<'PY'
import plistlib
import sys
from pathlib import Path

template, agent = map(Path, sys.argv[1:])
root = str(template.resolve().parents[1])
service = plistlib.loads(template.read_bytes())
for key in ("WorkingDirectory", "StandardOutPath", "StandardErrorPath"):
    if key in service:
        service[key] = service[key].replace("__INSTALL_ROOT__", root)
service["ProgramArguments"] = [arg.replace("__INSTALL_ROOT__", root) for arg in service["ProgramArguments"]]
agent.write_bytes(plistlib.dumps(service))
PY
launchctl bootstrap "gui/$(id -u)" "$agent"
echo "ai-filter service installed"
