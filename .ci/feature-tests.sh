#!/bin/bash
set -euo pipefail

# Simple build check
if [ ! -d "./target/debug" ]; then
    echo "Build failed or target/debug directory does not exist."
    exit 1
fi

BINARY="./target/debug/meowping"

# Check if the binary exists and is executable
if [ ! -x "$BINARY" ]; then
    echo "Binary $BINARY does not exist or is not executable."
    exit 1
fi

OUTPUT1=$($BINARY 1.1.1.1 -c 1 -m -p 53)
echo "$OUTPUT1" | grep -q "Cloudflare"
if [ $? -ne 0 ]; then
    echo "Test failed: Expected output to contain 'Cloudflare'"
    echo "Actual output:"
    echo "$OUTPUT1"
    exit 1
fi

OUTPUT2=$($BINARY https://cloudflare.com -c 1 -m -p 443)
echo "$OUTPUT2" | grep -q "AS13335 Cloudflare, Inc"
if [ $? -ne 0 ]; then
    echo "Test failed: Expected output to contain 'AS13335 Cloudflare, Inc' for https://cloudflare.com"
    echo "Actual output:"
    echo "$OUTPUT2"
    exit 1
fi

echo "All feature tests passed."