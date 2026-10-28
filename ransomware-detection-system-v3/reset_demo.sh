#!/usr/bin/env bash
set -euo pipefail

cd /root/ransomware-detection-system-v3

echo "Ensure the dashboard and monitor are stopped before continuing."
read -r -p "Have you stopped them? (yes/no): " answer

if [[ "$answer" != "yes" ]]; then
    echo "Reset cancelled."
    exit 1
fi

timestamp=$(date +%Y%m%d_%H%M%S)
archive="/root/ransomware-demo-history/$timestamp"

mkdir -p "$archive"

# Preserve existing demonstration evidence.
if [[ -f evidence/detection_decisions.jsonl ]]; then
    cp evidence/detection_decisions.jsonl "$archive/"
    : > evidence/detection_decisions.jsonl
fi

# Preserve process-specific evidence without deleting it.
if compgen -G "evidence/process_*.json" > /dev/null; then
    mkdir -p "$archive/process_evidence"
    cp evidence/process_*.json "$archive/process_evidence/"
fi

echo
echo "Active detection history cleared."
echo "Previous evidence saved to: $archive"
echo "Restart the dashboard before the next demonstration."
