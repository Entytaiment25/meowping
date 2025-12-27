#!/usr/bin/env bash
set -euo pipefail



if command -v meowping >/dev/null 2>&1; then
    MEOWPING_PATH="$(command -v meowping)"
else
    MEOWPING_PATH="./target/release/meowping"
    if [ ! -x "$MEOWPING_PATH" ]; then
        echo "meowping not found in PATH and $MEOWPING_PATH does not exist or is not executable"
        exit 1
    fi
fi

# On macOS and Linux, ICMP requires sudo
USE_SUDO_ICMP=""
if [[ "$(uname)" == "Darwin" || "$(uname)" == "Linux" ]]; then
    USE_SUDO_ICMP="sudo $MEOWPING_PATH"
fi

if [[ -n "$USE_SUDO_ICMP" ]]; then
    OUTPUT1=$($USE_SUDO_ICMP 1.1.1.1 -c 1 -m -p 53)
else
    OUTPUT1=$($MEOWPING_PATH 1.1.1.1 -c 1 -m -p 53)
fi
if ! echo "$OUTPUT1" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Cloudflare"; then
    echo "Test failed: Expected output to contain 'Cloudflare'"
    echo "Actual output:"
    echo "$OUTPUT1"
    exit 1
fi

MEOWPING="$MEOWPING_PATH"
OUTPUT2=$($MEOWPING https://cloudflare.com -c 1 -m -p 443)
if ! echo "$OUTPUT2" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "AS13335 Cloudflare, Inc"; then
    echo "Test failed: Expected output to contain 'AS13335 Cloudflare, Inc' for https://cloudflare.com"
    echo "Actual output:"
    echo "$OUTPUT2"
    exit 1
fi

if [[ -n "$USE_SUDO_ICMP" ]]; then
    OUTPUT3=$($USE_SUDO_ICMP https://cloudflare.com -c 1 -m)
else
    OUTPUT3=$($MEOWPING_PATH https://cloudflare.com -c 1 -m)
fi
if ! echo "$OUTPUT3" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Reply from"; then
    echo "Test failed: Expected output to contain 'Reply from' for https://cloudflare.com"
    echo "Actual output:"
    echo "$OUTPUT3"
    exit 1
fi

OUTPUT4=$($MEOWPING -s https://mock.httpstatus.io/200 -c 1 -m)
if ! echo "$OUTPUT4" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "is online"; then
    echo "Test failed: Expected output to contain 'is online' for HTTP 200"
    echo "Actual output:"
    echo "$OUTPUT4"
    exit 1
fi

OUTPUT5=$($MEOWPING -s https://mock.httpstatus.io/503 -c 1 -m)
if ! echo "$OUTPUT5" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "is offline (server error)"; then
    echo "Test failed: Expected output to contain 'is offline (server error)' for HTTP 503"
    echo "Actual output:"
    echo "$OUTPUT5"
    exit 1
fi

# Test multi-host TCP ping in minimal mode
OUTPUT6=$($MEOWPING 1.1.1.1,8.8.8.8 -c 1 -m -p 53)
if ! echo "$OUTPUT6" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Hosts responsive: 2/2"; then
    echo "Test failed: Expected 'Hosts responsive: 2/2' in multi-host TCP minimal output"
    echo "Actual output:"
    echo "$OUTPUT6"
    exit 1
fi
if ! echo "$OUTPUT6" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "1.1.1.1"; then
    echo "Test failed: Expected '1.1.1.1' in multi-host TCP minimal output"
    echo "Actual output:"
    echo "$OUTPUT6"
    exit 1
fi
if ! echo "$OUTPUT6" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "8.8.8.8"; then
    echo "Test failed: Expected '8.8.8.8' in multi-host TCP minimal output"
    echo "Actual output:"
    echo "$OUTPUT6"
    exit 1
fi

# Test multi-host TCP ping in normal mode
OUTPUT7=$($MEOWPING 1.1.1.1,8.8.8.8 -c 1 -p 53)
if ! echo "$OUTPUT7" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Hosts responsive: 2/2"; then
    echo "Test failed: Expected 'Hosts responsive: 2/2' in multi-host TCP normal output"
    echo "Actual output:"
    echo "$OUTPUT7"
    exit 1
fi

# Test multi-host ICMP ping in minimal mode
if [[ -n "$USE_SUDO_ICMP" ]]; then
    OUTPUT8=$($USE_SUDO_ICMP 1.1.1.1,8.8.8.8 -c 1 -m)
else
    OUTPUT8=$($MEOWPING_PATH 1.1.1.1,8.8.8.8 -c 1 -m)
fi
REPLY_COUNT=$(echo "$OUTPUT8" | sed 's/\x1b\[[0-9;]*m//g' | grep -c "Reply from")
if [ "$REPLY_COUNT" -ne 2 ]; then
    echo "Test failed: Expected 2 'Reply from' in multi-host ICMP minimal output, got $REPLY_COUNT"
    echo "Actual output:"
    echo "$OUTPUT8"
    exit 1
fi

# Test multi-host ICMP ping in normal mode
if [[ -n "$USE_SUDO_ICMP" ]]; then
    OUTPUT9=$($USE_SUDO_ICMP 1.1.1.1,8.8.8.8 -c 1)
else
    OUTPUT9=$($MEOWPING_PATH 1.1.1.1,8.8.8.8 -c 1)
fi
if ! echo "$OUTPUT9" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "\[MEOWPING\] Scanning host"; then
    echo "Test failed: Expected '[MEOWPING] Scanning host' in multi-host ICMP normal output"
    echo "Actual output:"
    echo "$OUTPUT9"
    exit 1
fi
REPLY_COUNT9=$(echo "$OUTPUT9" | sed 's/\x1b\[[0-9;]*m//g' | grep -c "Reply from")
if [ "$REPLY_COUNT9" -ne 2 ]; then
    echo "Test failed: Expected 2 'Reply from' in multi-host ICMP normal output, got $REPLY_COUNT9"
    echo "Actual output:"
    echo "$OUTPUT9"
    exit 1
fi

echo "All feature tests passed."
