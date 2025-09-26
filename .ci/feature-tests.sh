#!/usr/bin/env bash
set -euo pipefail

whereis meowping

OUTPUT1=$(meowping 1.1.1.1 -c 1 -m -p 53)
if ! echo "$OUTPUT1" | grep -q "Cloudflare"; then
    echo "Test failed: Expected output to contain 'Cloudflare'"
    echo "Actual output:"
    echo "$OUTPUT1"
    exit 1
fi

OUTPUT2=$(meowping https://cloudflare.com -c 1 -m -p 443)
if ! echo "$OUTPUT2" | grep -q "AS13335 Cloudflare, Inc"; then
    echo "Test failed: Expected output to contain 'AS13335 Cloudflare, Inc' for https://cloudflare.com"
    echo "Actual output:"
    echo "$OUTPUT2"
    exit 1
fi

OUTPUT3=$(meowping https://cloudflare.com -c 1 -m)
if ! echo "$OUTPUT3" | grep -q "Reply from"; then
    echo "Test failed: Expected output to contain 'Reply from' for https://cloudflare.com"
    echo "Actual output:"
    echo "$OUTPUT3"
    exit 1
fi

echo "All feature tests passed."
