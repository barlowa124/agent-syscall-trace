#!/usr/bin/env bash
# Produce the artifacts under results/. Run from the repo root after
# `cargo build --release`. Each artifact is regenerated deterministically
# except timestamps, keys, and pids.
set -uo pipefail

A=${ASTRACE:-./target/release/astrace}
R=results
mkdir -p "$R"

$A keygen --out "$R/demo.key"
chmod 600 "$R/demo.key" 2>/dev/null || true

$A manifest --key "$R/demo.key" --job-id demo \
    --allow-path /usr --allow-path /lib --allow-path /etc \
    --allow-path /tmp --allow-path /proc --allow-path /dev \
    --flag-path /home --allow-connect '10.9.9.2:9999' \
    --allow-flow '10.9.9.2:9999/tcp' --enforce \
    --out "$R/manifest.json" -- \
    /bin/sh -c 'cat /etc/hostname >/dev/null; \
        exec 3<>/dev/tcp/10.9.9.2/9999 && echo hello >&3 && head -1 <&3; \
        (cat /sys/kernel/hostname) 2>/dev/null; \
        (exec 4<>/dev/tcp/10.9.9.2/8888) 2>/dev/null; true'

$A run --netns --manifest "$R/manifest.json" \
    --receipts "$R/receipts.jsonl" --key "$R/demo.key" \
    > "$R/run.stdout" 2> "$R/run.stderr"
echo "run exit: $?"

PUB=$(python3 -c "import json;print(json.load(open('$R/manifest.json'))['pubkey_hex'])")
$A verify --receipts "$R/receipts.jsonl" --pubkey "$PUB" | tee "$R/verify.txt"

cp "$R/receipts.jsonl" "$R/receipts_tampered.jsonl"
sed -i 's|/etc/hostname|/etc/Xostname|' "$R/receipts_tampered.jsonl"
$A verify --receipts "$R/receipts_tampered.jsonl" --pubkey "$PUB" \
    | tee "$R/verify_tampered.txt" || true

$A bench > "$R/bench.txt" 2>&1
echo "--- summary ---"
cat "$R/verify.txt" "$R/verify_tampered.txt" "$R/bench.txt"
