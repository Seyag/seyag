#!/bin/bash
# Usage: scripts/hotspot_probe.sh  -- with the iPhone on the cable and Personal Hotspot on, asks the phone's hotspot DNS (203.0.113.10) a few names over the USB link only. Changes nothing (no routes, no DNS settings).
set -u
src=$(ifconfig | awk '/inet 172\.20\.10\./{print $2; exit}')
if [ -z "$src" ]; then echo "no hotspot link: plug in the iPhone and turn Personal Hotspot on"; exit 2; fi
echo "hotspot link address: $src"
ping -c 2 -t 3 -S "$src" 203.0.113.10 >/dev/null 2>&1 && echo "phone reachable: yes" || echo "phone reachable: no"
fail=0
for name in example.com apple.com wikipedia.org; do
  for proto in "" "+tcp"; do
    out=$(dig -b "$src" @203.0.113.10 "$name" A +time=3 +tries=1 $proto 2>&1)
    status=$(printf '%s\n' "$out" | sed -n 's/.*status: \([A-Z]*\).*/\1/p')
    answers=$(printf '%s\n' "$out" | grep -c "IN[[:space:]]*A[[:space:]]")
    echo "$name ${proto:-udp}: status=${status:-none} answers=$answers"
    [ "${status:-}" = "NOERROR" ] && [ "$answers" -gt 0 ] || fail=1
  done
done
# does plain internet work through the phone without names?
curl -s -o /dev/null -m 6 --interface "$src" -w "direct IP fetch (1.1.1.1): http %{http_code}\n" https://1.1.1.1/ || echo "direct IP fetch: failed"
exit $fail
