#!/bin/bash
# Start the filter: the proxy (watched here), and the PAC server, admin page and DNS
# filter (each restarted whenever it exits), plus weekly list refresh, the weekly
# report and daily maintenance. Keeps the Mac awake while the proxy runs.
# Proxy failures (including a CA mismatch) restart only the proxy: PAC stays up
# so strict clients can discover its existing backup proxy.
set -uo pipefail
cd "$(dirname "$0")"
# launchd starts agents with a soft limit of 256 open files. Every proxied connection holds two
# (phone side and site side), so ordinary browsing hit "Too many open files" (2026-11-12, 63 errors
# in one minute) and new connections hung until the phone's VPN was toggled.
mkdir -p data
ulimit -n 16384 2>/dev/null || ulimit -n 8192 2>/dev/null || ulimit -n 4096
echo "$(date "+%F %T") open-files limit: $(ulimit -n)" >> data/run.log
PY=.venv/bin/python
CONFDIR="$HOME/.mitmproxy"
PIDS=()

log() { echo "$(date '+%F %T') run.sh: $*" | tee -a data/supervisor.log >&2; }
cfg() { $PY -c "from aifilter import config; print(config.load().get('$1', '$2', $3))"; }

cleanup() {
  trap - EXIT TERM INT
  [ ${#PIDS[@]} -gt 0 ] && kill "${PIDS[@]}" 2>/dev/null
}
trap cleanup EXIT
trap 'log "stopping"; exit 143' TERM INT

# supervise NAME RETRY_SECONDS CMD...: run CMD, restart it whenever it exits.
# A service that dies within 10 s of starting (port busy, Tailscale not up yet) waits
# RETRY_SECONDS before the next try; one that ran longer comes back after 1 s.
supervise() {
  local name=$1 retry=$2 child="" started rc
  shift 2
  trap '[ -n "$child" ] && kill "$child" 2>/dev/null; exit 0' TERM INT
  while true; do
    started=$SECONDS
    "$@" >> "data/$name.log" 2>&1 &
    child=$!
    rc=0; wait "$child" || rc=$?
    log "$name exited (rc=$rc); restarting"
    if (( SECONDS - started < 10 )); then sleep "$retry" & else sleep 1 & fi
    child=$!; wait "$child"
  done
}

# every SECONDS CMD...: run CMD now and then every SECONDS (stops cleanly on TERM).
every() {
  local period=$1 child=""
  shift
  trap '[ -n "$child" ] && kill "$child" 2>/dev/null; exit 0' TERM INT
  while true; do
    "$@" & child=$!; wait "$child"
    sleep "$period" & child=$!; wait "$child"
  done
}

refresh_lists() {
  if [ -z "$(find data/lists.stamp -mtime -7 2>/dev/null)" ]; then
    $PY -m aifilter.lists >> data/lists.log 2>&1 && touch data/lists.stamp
  fi
}

listen_host() {
  "$PY" -c 'import sys; from aifilter.export_settings import listen_ipv4; print(listen_ipv4(sys.argv[1]))' "$1"
}
PROXY_HOST=$(listen_host proxy) || exit 1
PAC_HOST=$(listen_host pac) || exit 1
DNS_HOST=$(listen_host dns) || exit 1
PORT=$(cfg proxy listen_port 8118)
PAC_PORT=$(cfg pac port 8119)
if [ -z "$PORT" ] || [ -z "$PAC_PORT" ]; then log "cannot read config.toml"; exit 1; fi

# Proxy auto-config for the iPhone first: strict clients have no internet without it.
supervise pac 1 $PY -m http.server "$PAC_PORT" --bind "$PAC_HOST" --directory pac &
PIDS+=($!)
supervise admin 10 $PY admin.py &
PIDS+=($!)
supervise telegram-media 10 $PY -m aifilter.media_verdict &
PIDS+=($!)
supervise dns 10 $PY -m aifilter.dns &
PIDS+=($!)

# Standing social-feed policy (idempotent; restores rows after old temporary approvals).
$PY policy.py >> data/policy.log 2>&1 || log "policy apply failed (data/policy.log)"

# Community blocklists: refreshed when a week old, checked every 6 hours, so a failed
# refresh is retried. lists.update swaps the table atomically and keeps the old lists on error.
every 21600 refresh_lists &
PIDS+=($!)
# Weekly accountability report (checked hourly, sent when due).
every 3600 sh -c "$PY report.py --if-due >> data/report.log 2>&1" &
PIDS+=($!)
# Daily housekeeping: prune old rows, rotate logs.
every 86400 sh -c "$PY -m aifilter.maintenance >> data/maintenance.log 2>&1" &
PIDS+=($!)

# Daily end-to-end proof that blocking, safe search and everyday sites all still hold
# (waits for the proxy on start; alerts only when the set of failing cases changes).
every 86400 sh -c "sleep 90; $PY scripts/selftest.py --notify --proxy-host $PROXY_HOST --proxy-port $PORT --dns-host $DNS_HOST --dns-port $(cfg dns port 53) >> data/selftest.log 2>&1" &
PIDS+=($!)

# Observe only: one incident alert after >5 minutes and one recovery; no repair/VM action.
check_health() {
  "$PY" scripts/healthcheck.py --once --notify --proxy-port "$PORT" --pac-port "$PAC_PORT" --proxy-host "$PROXY_HOST" --pac-host "$PAC_HOST" --dns-host "$DNS_HOST" --dns-port "$(cfg dns port 53)" >> data/healthcheck.log 2>&1
}
every 120 check_health &
PIDS+=($!)

# Re-check before every proxy start. Never start mitmproxy with an untrusted CA,
# and never tear down PAC/DNS/admin merely because this check fails.
start_proxy() {
  if ! AIFILTER_MITM_CONFDIR="$CONFDIR" $PY -m aifilter.cacheck; then
    log "!!! CA check failed: proxy NOT started; PAC and backup remain available (data/proxy.log)"
    return 1
  fi
  exec .venv/bin/mitmdump -q -s addon.py --listen-host "$PROXY_HOST" --listen-port "$PORT" --set confdir="$CONFDIR" \
    --set block_global=true --set connection_strategy=lazy --set http2=true --set upstream_cert=true
}
supervise proxy 10 start_proxy &
PROXY=$!
PIDS+=($PROXY)
caffeinate -is -w "$PROXY" &
PIDS+=($!)
rc=0; wait "$PROXY" || rc=$?
log "proxy supervisor exited (rc=$rc); exiting so launchd restarts everything"
exit $(( rc == 0 ? 1 : rc ))
