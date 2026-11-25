#!/usr/bin/env bash
# Run the Suricata rule pack against the attack and benign PCAPs, print hit counts.
# Usage (from project root): bash scripts/run_suricata.sh
set -e
RULES=suricata/ebs-cve-2025-61882.rules
SUDO=""; [ "$(id -u)" -ne 0 ] && SUDO="sudo"
for f in attack benign; do
  rm -rf "out/$f"; mkdir -p "out/$f"
  $SUDO suricata -c /etc/suricata/suricata.yaml -S "$RULES" -r "testdata/$f.pcap" \
       -l "out/$f" -k none --set "vars.address-groups.HOME_NET=[10.0.0.0/8]" >/dev/null 2>&1
  echo "== $f.pcap"
  if [ -s "out/$f/fast.log" ]; then grep -o '\[1:[0-9]*:[0-9]*\] [^[]*' "out/$f/fast.log" | sort | uniq -c; else echo "   (no alerts)"; fi
done
