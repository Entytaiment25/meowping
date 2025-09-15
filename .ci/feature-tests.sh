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

$BINARY 1.1.1.1 -c 1 -m -p 53 | grep -q "Cloudflare"

# Check if the output contains "Cloudflare"
if [ $? -ne 0 ]; then
    echo "Test failed: Expected output to contain 'Cloudflare'"
    exit 1
fi

$BINARY one.one.one.one.one -c 1 -m -p 53 | grep -q "Cloudflare"
if [ $? -ne 0 ]; then
    echo "Test failed: Expected output to contain 'Cloudflare' for one.one.one.one"
    exit 1
fi
