#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${CARGO_HOME:-.}"

# Simple build check
if [ ! -d "$TARGET_DIR/target/debug" ]; then
    echo "Build failed or target/debug directory does not exist."
    exit 1
fi

BINARY="$TARGET_DIR/target/debug/meowping"

# Check if the binary exists and is executable
if [ ! -x "$BINARY" ]; then
    echo "Binary $BINARY does not exist or is not executable."
    exit 1
fi

OUTPUT1=$($BINARY 1.1.1.1 -c 1 -m -p 53)
if ! echo "$OUTPUT1" | grep -q "Cloudflare"; then
    echo "Test failed: Expected output to contain 'Cloudflare'"
    echo "Actual output:"
    echo "$OUTPUT1"
    exit 1
fi

OUTPUT2=$($BINARY https://cloudflare.com -c 1 -m -p 443)
if ! echo "$OUTPUT2" | grep -q "AS13335 Cloudflare, Inc"; then
    echo "Test failed: Expected output to contain 'AS13335 Cloudflare, Inc' for https://cloudflare.com"
    echo "Actual output:"
    echo "$OUTPUT2"
    exit 1
fi

OUTPUT3=$($BINARY https://cloudflare.com -c 1 -m)
if ! echo "$OUTPUT3" | grep -q "Reply from"; then
    echo "Test failed: Expected output to contain 'Reply from' for https://cloudflare.com"
    echo "Actual output:"
    echo "$OUTPUT3"
    exit 1
fi

echo "All feature tests passed."
