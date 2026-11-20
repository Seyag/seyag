#!/bin/bash
# Usage: deploy/reload-service.sh  -- reinstall the launchd plist and restart the filter safely (retries bootstrap until the old instance is gone, then waits for port 8118).
set -u
L=gui/$(id -u)/com.example.ai-filter; P=~/Library/LaunchAgents/com.example.ai-filter.plist
cp "$(dirname "$0")/com.example.ai-filter.plist" "$P"
launchctl bootout "$L" 2>/dev/null
for i in $(seq 1 30); do launchctl bootstrap "gui/$(id -u)" "$P" 2>/dev/null && break; sleep 1; done
for i in $(seq 1 30); do nc -z -G1 127.0.0.1 8118 2>/dev/null && { echo "filter up"; exit 0; }; sleep 1; done
echo "FILTER NOT UP: check launchctl print $L" >&2; exit 1
