#!/usr/bin/env bash
set -euo pipefail

# Always use local build for testing to ensure we test the current code
MEOWPING_PATH="./target/release/meowping"
if [ ! -x "$MEOWPING_PATH" ]; then
    echo "$MEOWPING_PATH does not exist or is not executable"
    echo "Please build with: cargo build --release"
    exit 1
fi

# On macOS and Linux, ICMP requires sudo or capabilities
USE_SUDO_ICMP=""
HAVE_ICMP_PERMS=false
if [[ "$(uname)" == "Darwin" || "$(uname)" == "Linux" ]]; then
    # Check if we have raw socket capabilities or can use sudo
    if timeout 2 $MEOWPING_PATH 127.0.0.1 -c 1 -m >/dev/null 2>&1; then
        # Binary has capabilities set or running as root
        HAVE_ICMP_PERMS=true
    elif command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        # Passwordless sudo is available
        USE_SUDO_ICMP="sudo"
        if timeout 2 sudo $MEOWPING_PATH 127.0.0.1 -c 1 -m >/dev/null 2>&1; then
            HAVE_ICMP_PERMS=true
        fi
    fi
fi

OUTPUT1=$($MEOWPING_PATH 1.1.1.1 -c 1 -m -p 53)
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

if [[ "$HAVE_ICMP_PERMS" == "true" ]]; then
    if [[ -n "$USE_SUDO_ICMP" ]]; then
        OUTPUT3=$($USE_SUDO_ICMP $MEOWPING_PATH https://cloudflare.com -c 1 -m)
    else
        OUTPUT3=$($MEOWPING_PATH https://cloudflare.com -c 1 -m)
    fi
    if ! echo "$OUTPUT3" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Reply from"; then
        echo "Test failed: Expected output to contain 'Reply from' for https://cloudflare.com"
        echo "Actual output:"
        echo "$OUTPUT3"
        exit 1
    fi
else
    echo "Skipping ICMP test for cloudflare.com (insufficient permissions)"
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
if [[ "$HAVE_ICMP_PERMS" == "true" ]]; then
    if [[ -n "$USE_SUDO_ICMP" ]]; then
        OUTPUT8=$($USE_SUDO_ICMP $MEOWPING_PATH 1.1.1.1,8.8.8.8 -c 1 -m)
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
        OUTPUT9=$($USE_SUDO_ICMP $MEOWPING_PATH 1.1.1.1,8.8.8.8 -c 1)
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
else
    echo "Skipping multi-host ICMP tests (insufficient permissions)"
fi

# ============================================================================
# IPv6 Tests
# ============================================================================

echo "Running IPv6 tests..."

# Test IPv6 loopback ICMP ping
if [[ "$HAVE_ICMP_PERMS" == "true" ]]; then
    if [[ -n "$USE_SUDO_ICMP" ]]; then
        OUTPUT_IPV6_1=$($USE_SUDO_ICMP $MEOWPING_PATH ::1 -c 1 -m)
    else
        OUTPUT_IPV6_1=$($MEOWPING_PATH ::1 -c 1 -m)
    fi
    if ! echo "$OUTPUT_IPV6_1" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Reply from ::1"; then
        echo "Test failed: Expected 'Reply from ::1' in IPv6 loopback ICMP output"
        echo "Actual output:"
        echo "$OUTPUT_IPV6_1"
        exit 1
    fi
    if ! echo "$OUTPUT_IPV6_1" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Successes = 1"; then
        echo "Test failed: Expected 'Successes = 1' in IPv6 loopback ICMP output"
        echo "Actual output:"
        echo "$OUTPUT_IPV6_1"
        exit 1
    fi
else
    echo "Skipping IPv6 ICMP test (insufficient permissions)"
fi

# Test IPv6 TCP connection (loopback on high port, should timeout - that's expected)
OUTPUT_IPV6_2=$($MEOWPING ::1 -p 9999 -c 1 -m)
if ! echo "$OUTPUT_IPV6_2" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "::1"; then
    echo "Test failed: Expected '::1' in IPv6 TCP output"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_2"
    exit 1
fi
if ! echo "$OUTPUT_IPV6_2" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "protocol=TCP"; then
    echo "Test failed: Expected 'protocol=TCP' in IPv6 TCP output"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_2"
    exit 1
fi

# Test IPv6 subnet scan (/127 = 2 addresses)
if [[ "$HAVE_ICMP_PERMS" == "true" ]]; then
    if [[ -n "$USE_SUDO_ICMP" ]]; then
        OUTPUT_IPV6_3=$($USE_SUDO_ICMP $MEOWPING_PATH ::1/127 -c 1 -m)
    else
        OUTPUT_IPV6_3=$($MEOWPING_PATH ::1/127 -c 1 -m)
    fi
    if ! echo "$OUTPUT_IPV6_3" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Scanning ::/127"; then
        echo "Test failed: Expected 'Scanning ::/127' in IPv6 subnet scan output"
        echo "Actual output:"
        echo "$OUTPUT_IPV6_3"
        exit 1
    fi
    if ! echo "$OUTPUT_IPV6_3" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "2 hosts"; then
        echo "Test failed: Expected '2 hosts' in IPv6 subnet scan output"
        echo "Actual output:"
        echo "$OUTPUT_IPV6_3"
        exit 1
    fi
    if ! echo "$OUTPUT_IPV6_3" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Hosts responsive:"; then
        echo "Test failed: Expected 'Hosts responsive:' in IPv6 subnet scan output"
        echo "Actual output:"
        echo "$OUTPUT_IPV6_3"
        exit 1
    fi
else
    echo "Skipping IPv6 subnet ICMP test (insufficient permissions)"
fi

# Test IPv6 subnet rejection (too large)
OUTPUT_IPV6_4=$($MEOWPING 2001:db8::/64 -m 2>&1 || true)
if ! echo "$OUTPUT_IPV6_4" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "too many addresses to scan"; then
    echo "Test failed: Expected 'too many addresses to scan' for large IPv6 subnet"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_4"
    exit 1
fi

# Test IPv6 subnet TCP scan (/126 = 4 addresses, 2 usable)
OUTPUT_IPV6_5=$($MEOWPING ::1/126 -p 9999 -c 1 -m)
if ! echo "$OUTPUT_IPV6_5" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Scanning"; then
    echo "Test failed: Expected 'Scanning' in IPv6 TCP subnet output"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_5"
    exit 1
fi
if ! echo "$OUTPUT_IPV6_5" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "via TCP"; then
    echo "Test failed: Expected 'via TCP' in IPv6 TCP subnet output"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_5"
    exit 1
fi

# Test mixed IPv4/IPv6 multi-host TCP
OUTPUT_IPV6_6=$($MEOWPING 8.8.8.8,::1 -c 1 -m -p 9999)
if ! echo "$OUTPUT_IPV6_6" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "8.8.8.8"; then
    echo "Test failed: Expected '8.8.8.8' in mixed IPv4/IPv6 TCP output"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_6"
    exit 1
fi
if ! echo "$OUTPUT_IPV6_6" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "::1"; then
    echo "Test failed: Expected '::1' in mixed IPv4/IPv6 TCP output"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_6"
    exit 1
fi

# Test mixed IPv4/IPv6 multi-host ICMP
if [[ "$HAVE_ICMP_PERMS" == "true" ]]; then
    if [[ -n "$USE_SUDO_ICMP" ]]; then
        OUTPUT_IPV6_7=$($USE_SUDO_ICMP $MEOWPING_PATH 8.8.8.8,::1 -c 1 -m)
    else
        OUTPUT_IPV6_7=$($MEOWPING_PATH 8.8.8.8,::1 -c 1 -m)
    fi
    REPLY_COUNT_IPV6=$(echo "$OUTPUT_IPV6_7" | sed 's/\x1b\[[0-9;]*m//g' | grep -c "Reply from")
    if [ "$REPLY_COUNT_IPV6" -ne 2 ]; then
        echo "Test failed: Expected 2 'Reply from' in mixed IPv4/IPv6 ICMP output, got $REPLY_COUNT_IPV6"
        echo "Actual output:"
        echo "$OUTPUT_IPV6_7"
        exit 1
    fi
else
    echo "Skipping mixed IPv4/IPv6 ICMP test (insufficient permissions)"
fi

# Test IPv6 help text
OUTPUT_IPV6_HELP=$($MEOWPING --help)
if ! echo "$OUTPUT_IPV6_HELP" | grep -q "IPv6 Support"; then
    echo "Test failed: Expected 'IPv6 Support' section in help text"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_HELP"
    exit 1
fi

echo "All feature tests passed."
