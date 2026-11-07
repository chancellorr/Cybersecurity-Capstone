#!/usr/bin/env bash
# Capture kadmin.local output and config files as Kerbo-S test fixtures.
# Usage: sudo bash capture_fixtures.sh clean (or: planted)
set -euo pipefail
NAME="${1:?give a name, for example clean or planted}"
OUT="/home/kerbo/fixtures/$NAME"
mkdir -p "$OUT"
q() { kadmin.local -q "$1" < /dev/null | grep -v '^Authenticating' || true; }

# The snapshot time the age rules measure against (David's loader reads this file).
date -u +%Y-%m-%dT%H:%M:%S > "$OUT/collected_at.txt"

q "listprincs" > "$OUT/listprincs.txt"
while read -r p; do
  [ -z "$p" ] && continue
  q "getprinc $p" > "$OUT/getprinc_${p//\//_}.txt"
done < "$OUT/listprincs.txt"

q "getpols" > "$OUT/getpols.txt"
while read -r pol; do
  [ -z "$pol" ] && continue
  q "getpol $pol" > "$OUT/getpol_${pol}.txt"
done < "$OUT/getpols.txt"

cp /etc/krb5.conf "$OUT/krb5.conf"
cp /etc/krb5kdc/kdc.conf "$OUT/kdc.conf"
chown -R kerbo:kerbo /home/kerbo/fixtures
echo "Saved $(ls "$OUT" | wc -l) files to $OUT"