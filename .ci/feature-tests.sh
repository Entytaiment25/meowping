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

OUTPUT4=$(meowping -s https://mock.httpstatus.io/200 -c 1 -m)
if ! echo "$OUTPUT4" | grep -q "is online"; then
    echo "Test failed: Expected output to contain 'is online' for HTTP 200"
    echo "Actual output:"
    echo "$OUTPUT4"
    exit 1
fi

OUTPUT5=$(meowping -s https://mock.httpstatus.io/503 -c 1 -m)
if ! echo "$OUTPUT5" | grep -q "is offline (server error)"; then
    echo "Test failed: Expected output to contain 'is offline (server error)' for HTTP 503"
    echo "Actual output:"
    echo "$OUTPUT5"
    exit 1
fi

echo "All feature tests passed."
