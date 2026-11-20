#!/bin/bash
# VM startup script (runs as root on every boot). Installs once, then refreshes lists and starts the proxy.
set -u
D=/opt/filter; mkdir -p $D/lists; cd $D
if [ ! -x /usr/bin/tailscale ]; then curl -fsSL https://tailscale.com/install.sh | sh; fi
if [ ! -x $D/venv/bin/mitmdump ]; then apt-get update -qq && apt-get install -y -qq python3-venv >/dev/null && python3 -m venv $D/venv && $D/venv/bin/pip -q install mitmproxy; fi
curl -fsS -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/addon" -o $D/backup_addon.py
for u in https://nsfw.oisd.nl/domainswild2 \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt \
  https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt; do
  curl -fsS -m 60 "$u" -o "$D/lists/$(echo "$u" | md5sum | cut -c1-8).txt.new" && mv "$D/lists/$(echo "$u" | md5sum | cut -c1-8).txt.new" "$D/lists/$(echo "$u" | md5sum | cut -c1-8).txt"
done
B=$(curl -fsS -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/attributes/bucket")
gcloud storage cp "gs://$B/blocked.txt" $D/lists/own.txt 2>/dev/null || true
# Exit node (2026-11-15): the iPhone sends all traffic home; this VM is the manual fallback exit when the Mac is down.
printf 'net.ipv4.ip_forward = 1\nnet.ipv6.conf.all.forwarding = 1\n' > /etc/sysctl.d/99-tailscale.conf
sysctl -q -p /etc/sysctl.d/99-tailscale.conf
TSIP=""; for i in $(seq 1 60); do TSIP=$(tailscale ip -4 2>/dev/null); [ -n "$TSIP" ] && break; sleep 2; done
tailscale set --advertise-exit-node 2>/dev/null || true
pkill -f mitmdump || true
nohup $D/venv/bin/mitmdump -q -s $D/backup_addon.py --listen-host "${TSIP:-127.0.0.1}" --listen-port 8118 > $D/proxy.log 2>&1 &
