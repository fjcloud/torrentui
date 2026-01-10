#!/bin/bash
# Test BitTorrent Port Connectivity
# Usage: ./test-bittorrent-port.sh <host> <port>

set -e

HOST="${1:-localhost}"
PORT="${2:-32767}"

echo "🧪 Testing BitTorrent connectivity to ${HOST}:${PORT}"
echo ""

# Test 1: Basic TCP connectivity
echo "📡 Test 1: TCP Connection"
if timeout 3 bash -c "cat < /dev/null > /dev/tcp/${HOST}/${PORT}" 2>/dev/null; then
    echo "   ✅ Port is open and accepting connections"
else
    echo "   ❌ Port is closed or not accessible"
    exit 1
fi
echo ""

# Test 2: Send BitTorrent handshake
echo "📡 Test 2: BitTorrent Protocol Handshake"
echo "   Sending BitTorrent handshake..."

# Create a BitTorrent handshake:
# - 0x13 (19) = protocol name length
# - "BitTorrent protocol" (19 bytes)
# - 8 bytes of zeros (reserved)
# - 20 bytes info_hash (fake, just for testing)
# - 20 bytes peer_id (fake)

RESPONSE=$(timeout 3 bash -c "
    printf '\x13BitTorrent protocol\x00\x00\x00\x00\x00\x00\x00\x00' | \
    cat - <(printf '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') \
        <(printf '\x2d\x54\x45\x53\x54\x2d\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30\x30') | \
    nc -w 3 ${HOST} ${PORT} 2>&1 | xxd -p | head -c 200
" 2>&1 || true)

if [ -n "$RESPONSE" ]; then
    echo "   ✅ Server responded with BitTorrent protocol!"
    echo "   Response (hex): ${RESPONSE:0:80}..."
    
    # Check if response starts with 0x13 (BitTorrent handshake)
    if [[ "$RESPONSE" =~ ^13 ]]; then
        echo "   ✅ Valid BitTorrent handshake detected!"
    else
        echo "   ⚠️  Got response but not a BitTorrent handshake"
    fi
else
    echo "   ⚠️  No response received (might be because we sent fake info_hash)"
    echo "   But the fact we connected means the port IS working!"
fi
echo ""

# Test 3: Check with netcat
echo "📡 Test 3: Quick nc Test"
if echo "test" | timeout 1 nc -w 1 ${HOST} ${PORT} >/dev/null 2>&1; then
    echo "   ✅ Port responds to connections"
else
    echo "   ⚠️  Port might be filtered or application-specific"
fi
echo ""

# Test 4: Port scan
echo "📡 Test 4: Nmap-style Check"
if command -v nmap &> /dev/null; then
    nmap -p ${PORT} ${HOST} 2>/dev/null | grep "${PORT}/tcp"
else
    echo "   ⚠️  nmap not installed, skipping"
fi
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎯 CONCLUSION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "If you got '✅ Port is open' in Test 1:"
echo "  → Your BitTorrent port IS accessible!"
echo ""
echo "The 'Connection reset' with curl is NORMAL because:"
echo "  → BitTorrent protocol ≠ HTTP protocol"
echo "  → The server rejects non-BitTorrent handshakes"
echo ""
echo "To verify seeding is working, check:"
echo "  1. podman logs torrentui | grep 'Upload Stats'"
echo "  2. Look for 'active conns > 0'"
echo "  3. Monitor upload speed in WebUI"
echo ""
echo "If still 0 upload after 5-10 minutes:"
echo "  → Trackers need time to re-announce your IP"
echo "  → Make sure you're seeding popular torrents"
echo "  → Check your tracker's rules (ratio requirements, etc.)"
echo ""
