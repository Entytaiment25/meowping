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
HAVE_EXT_ICMP=false
HAVE_IPV6_ICMP=false
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

    # Check if outbound ICMP to external hosts actually works (may be blocked on CI runners)
    if [[ "$HAVE_ICMP_PERMS" == "true" ]]; then
        if [[ -n "$USE_SUDO_ICMP" ]]; then
            EXT_ICMP_TEST=$($USE_SUDO_ICMP $MEOWPING_PATH 1.1.1.1 -c 1 -m 2>&1 || true)
        else
            EXT_ICMP_TEST=$($MEOWPING_PATH 1.1.1.1 -c 1 -m 2>&1 || true)
        fi
        if echo "$EXT_ICMP_TEST" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Reply from"; then
            HAVE_EXT_ICMP=true
        else
            echo "Note: Outbound ICMP to external hosts appears blocked, skipping external ICMP tests"
        fi

        if [[ -n "$USE_SUDO_ICMP" ]]; then
            IPV6_ICMP_TEST=$($USE_SUDO_ICMP $MEOWPING_PATH ::1 -c 1 -m 2>&1 || true)
        else
            IPV6_ICMP_TEST=$($MEOWPING_PATH ::1 -c 1 -m 2>&1 || true)
        fi
        if echo "$IPV6_ICMP_TEST" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Reply from ::1"; then
            HAVE_IPV6_ICMP=true
        else
            echo "Note: IPv6 ICMP loopback appears unavailable, skipping IPv6 ICMP tests"
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

if [[ "$HAVE_EXT_ICMP" == "true" ]]; then
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
    echo "Skipping ICMP test for cloudflare.com (outbound ICMP unavailable)"
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
if [[ "$HAVE_EXT_ICMP" == "true" ]]; then
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
    echo "Skipping multi-host ICMP tests (outbound ICMP unavailable)"
fi

# ============================================================================
# IPv6 Tests
# ============================================================================

echo "Running IPv6 tests..."

# Test IPv6 loopback ICMP ping
if [[ "$HAVE_ICMP_PERMS" == "true" && "$HAVE_IPV6_ICMP" == "true" ]]; then
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
    echo "Skipping IPv6 ICMP test (insufficient permissions or IPv6 ICMP unavailable)"
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
if [[ "$HAVE_ICMP_PERMS" == "true" && "$HAVE_IPV6_ICMP" == "true" ]]; then
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
    echo "Skipping IPv6 subnet ICMP test (insufficient permissions or IPv6 ICMP unavailable)"
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
if [[ "$HAVE_EXT_ICMP" == "true" && "$HAVE_IPV6_ICMP" == "true" ]]; then
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
    echo "Skipping mixed IPv4/IPv6 ICMP test (outbound ICMP or IPv6 ICMP unavailable)"
fi

# Test IPv6 help text
OUTPUT_IPV6_HELP=$($MEOWPING --help)
if ! echo "$OUTPUT_IPV6_HELP" | grep -q "IPv6 Support"; then
    echo "Test failed: Expected 'IPv6 Support' section in help text"
    echo "Actual output:"
    echo "$OUTPUT_IPV6_HELP"
    exit 1
fi

# ============================================================================
# UDP Probe Tests
# ============================================================================

echo "Running UDP tests..."

# UDP requires a port; running it without one must fail cleanly.
OUTPUT_UDP_NOPORT=$($MEOWPING 1.1.1.1 -u 2>&1 || true)
if ! echo "$OUTPUT_UDP_NOPORT" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "UDP probing requires a port"; then
    echo "Test failed: Expected 'UDP probing requires a port' when --udp is given without -p"
    echo "Actual output:"
    echo "$OUTPUT_UDP_NOPORT"
    exit 1
fi

# UDP help text
OUTPUT_UDP_HELP=$($MEOWPING --help)
if ! echo "$OUTPUT_UDP_HELP" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Probe a UDP port"; then
    echo "Test failed: Expected UDP option in help text"
    echo "Actual output:"
    echo "$OUTPUT_UDP_HELP"
    exit 1
fi

# A closed UDP port on loopback deterministically yields an ICMP Port
# Unreachable, which the connected socket surfaces as "closed". This needs no
# privileges or external network, so it is the reliable UDP verdict test.
OUTPUT_UDP_CLOSED=$($MEOWPING 127.0.0.1 -p 9999 -u -c 1 -m -a)
if ! echo "$OUTPUT_UDP_CLOSED" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "closed (Port Unreachable)"; then
    echo "Test failed: Expected 'closed (Port Unreachable)' for loopback UDP closed port"
    echo "Actual output:"
    echo "$OUTPUT_UDP_CLOSED"
    exit 1
fi
if ! echo "$OUTPUT_UDP_CLOSED" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "protocol=UDP"; then
    echo "Test failed: Expected 'protocol=UDP' in loopback UDP closed output"
    echo "Actual output:"
    echo "$OUTPUT_UDP_CLOSED"
    exit 1
fi

# IPv6 loopback closed port should report the same closed verdict.
OUTPUT_UDP_V6_CLOSED=$($MEOWPING ::1 -p 9999 -u -c 1 -m -a)
if ! echo "$OUTPUT_UDP_V6_CLOSED" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "closed (Port Unreachable)"; then
    echo "Test failed: Expected 'closed (Port Unreachable)' for IPv6 loopback UDP closed port"
    echo "Actual output:"
    echo "$OUTPUT_UDP_V6_CLOSED"
    exit 1
fi

# External UDP: an open DNS resolver answers our query, confirming "open".
# Skipped when outbound UDP appears unavailable (e.g. restricted CI runners).
HAVE_EXT_UDP=false
EXT_UDP_TEST=$($MEOWPING 1.1.1.1 -p 53 -u -c 1 -m -a 2>&1 || true)
if echo "$EXT_UDP_TEST" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "protocol=UDP"; then
    HAVE_EXT_UDP=true
fi

if [[ "$HAVE_EXT_UDP" == "true" ]]; then
    OUTPUT_UDP_OPEN=$($MEOWPING 1.1.1.1 -p 53 -u -c 1 -m -a)
    if ! echo "$OUTPUT_UDP_OPEN" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "protocol=UDP"; then
        echo "Test failed: Expected 'protocol=UDP' in open DNS UDP output"
        echo "Actual output:"
        echo "$OUTPUT_UDP_OPEN"
        exit 1
    fi
    if ! echo "$OUTPUT_UDP_OPEN" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "port=53"; then
        echo "Test failed: Expected 'port=53' in open DNS UDP output"
        echo "Actual output:"
        echo "$OUTPUT_UDP_OPEN"
        exit 1
    fi

    # Multi-host UDP minimal mode should report both resolvers responsive.
    OUTPUT_UDP_MULTI=$($MEOWPING 1.1.1.1,8.8.8.8 -p 53 -u -c 1 -m -a)
    if ! echo "$OUTPUT_UDP_MULTI" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Hosts responsive: 2/2"; then
        echo "Test failed: Expected 'Hosts responsive: 2/2' in multi-host UDP minimal output"
        echo "Actual output:"
        echo "$OUTPUT_UDP_MULTI"
        exit 1
    fi
else
    echo "Skipping external/multi-host UDP tests (outbound UDP to 1.1.1.1:53 unavailable)"
fi

# UDP subnet scan header on loopback (no privileges, no external network).
OUTPUT_UDP_SUBNET=$($MEOWPING 127.0.0.0/30 -p 53 -u -c 1 -m -a)
if ! echo "$OUTPUT_UDP_SUBNET" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "via UDP"; then
    echo "Test failed: Expected 'via UDP' in UDP subnet scan output"
    echo "Actual output:"
    echo "$OUTPUT_UDP_SUBNET"
    exit 1
fi
if ! echo "$OUTPUT_UDP_SUBNET" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Hosts responsive:"; then
    echo "Test failed: Expected 'Hosts responsive:' in UDP subnet scan output"
    echo "Actual output:"
    echo "$OUTPUT_UDP_SUBNET"
    exit 1
fi

# ============================================================================
# Multi-Port Probe Tests
# ============================================================================

echo "Running multi-port tests..."

# Help text documents the unified port flag and its list/range syntax.
OUTPUT_MP_HELP=$($MEOWPING --help)
if ! echo "$OUTPUT_MP_HELP" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "comma list"; then
    echo "Test failed: Expected 'comma list' in -p/--port help text"
    echo "Actual output:"
    echo "$OUTPUT_MP_HELP"
    exit 1
fi

# Reversed range is rejected.
OUTPUT_MP_REVERSED=$($MEOWPING 1.1.1.1 -p 90-80 2>&1 || true)
if ! echo "$OUTPUT_MP_REVERSED" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Port range end before start"; then
    echo "Test failed: Expected 'Port range end before start' for reversed range"
    echo "Actual output:"
    echo "$OUTPUT_MP_REVERSED"
    exit 1
fi

# Out-of-range port is rejected.
OUTPUT_MP_OOR=$($MEOWPING 1.1.1.1 -p 99999 2>&1 || true)
if ! echo "$OUTPUT_MP_OOR" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Port out of range"; then
    echo "Test failed: Expected 'Port out of range' for port 99999"
    echo "Actual output:"
    echo "$OUTPUT_MP_OOR"
    exit 1
fi

# Subnet x ports matrix above the cap is rejected.
OUTPUT_MP_MATRIX=$($MEOWPING 192.168.1.0/24 -p 1-200 2>&1 || true)
if ! echo "$OUTPUT_MP_MATRIX" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "matrix too large"; then
    echo "Test failed: Expected 'matrix too large' for oversized subnet x ports"
    echo "Actual output:"
    echo "$OUTPUT_MP_MATRIX"
    exit 1
fi

# Subnet x ports header on loopback (no privileges, no external network).
OUTPUT_MP_SUBNET=$($MEOWPING 127.0.0.0/30 -p 53,443 -c 1 -m -a)
if ! echo "$OUTPUT_MP_SUBNET" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "x 2 ports via TCP"; then
    echo "Test failed: Expected 'x 2 ports via TCP' in multi-port subnet output"
    echo "Actual output:"
    echo "$OUTPUT_MP_SUBNET"
    exit 1
fi
if ! echo "$OUTPUT_MP_SUBNET" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Ports responsive:"; then
    echo "Test failed: Expected 'Ports responsive:' in multi-port subnet output"
    echo "Actual output:"
    echo "$OUTPUT_MP_SUBNET"
    exit 1
fi

# External multi-port: needs outbound to 1.1.1.1. Skipped otherwise.
HAVE_EXT_MP=false
EXT_MP_TEST=$($MEOWPING 1.1.1.1 -p 53,80,443 -c 1 -m -a 2>&1 || true)
if echo "$EXT_MP_TEST" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "protocol=TCP"; then
    HAVE_EXT_MP=true
fi

if [[ "$HAVE_EXT_MP" == "true" ]]; then
    # Range expansion: 80-82 yields three ports, header reports 3.
    OUTPUT_MP_RANGE=$($MEOWPING 1.1.1.1 -p 80-82 -c 1 -m -a)
    if ! echo "$OUTPUT_MP_RANGE" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "x 3 port(s) via TCP"; then
        echo "Test failed: Expected 'x 3 port(s) via TCP' for range 80-82"
        echo "Actual output:"
        echo "$OUTPUT_MP_RANGE"
        exit 1
    fi
    # Comma list header reports the port count.
    OUTPUT_MP_LIST=$($MEOWPING 1.1.1.1 -p 53,80,443 -c 1 -m -a)
    if ! echo "$OUTPUT_MP_LIST" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "Ports responsive:"; then
        echo "Test failed: Expected 'Ports responsive:' in multi-port list output"
        echo "Actual output:"
        echo "$OUTPUT_MP_LIST"
        exit 1
    fi
    if ! echo "$OUTPUT_MP_LIST" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "1.1.1.1:443"; then
        echo "Test failed: Expected '1.1.1.1:443' line in multi-port output"
        echo "Actual output:"
        echo "$OUTPUT_MP_LIST"
        exit 1
    fi
    # TCP multiport must use 'timed out' for a non-responding port, not the UDP
    # 'open|filtered' wording. Mix an open port (53) with one that times out (23)
    # so the verdict goes through the multiport formatter.
    OUTPUT_MP_TCPTO=$($MEOWPING 1.1.1.1 -p 53,23 -c 1 -t 1000 -m -a)
    if ! echo "$OUTPUT_MP_TCPTO" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "1.1.1.1:23 timed out"; then
        echo "Test failed: Expected '1.1.1.1:23 timed out' for TCP non-responding port"
        echo "Actual output:"
        echo "$OUTPUT_MP_TCPTO"
        exit 1
    fi
    if echo "$OUTPUT_MP_TCPTO" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "open|filtered"; then
        echo "Test failed: TCP multiport output must not use UDP 'open|filtered' wording"
        echo "Actual output:"
        echo "$OUTPUT_MP_TCPTO"
        exit 1
    fi
    # Multi-host x multi-port matrix.
    OUTPUT_MP_MULTIHOST=$($MEOWPING 1.1.1.1,8.8.8.8 -p 53,443 -c 1 -m -a)
    if ! echo "$OUTPUT_MP_MULTIHOST" | sed 's/\x1b\[[0-9;]*m//g' | grep -q "2 host(s) x 2 port(s)"; then
        echo "Test failed: Expected '2 host(s) x 2 port(s)' in multi-host multi-port output"
        echo "Actual output:"
        echo "$OUTPUT_MP_MULTIHOST"
        exit 1
    fi
else
    echo "Skipping external multi-port tests (outbound to 1.1.1.1 unavailable)"
fi

echo "All feature tests passed."
