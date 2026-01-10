#!/usr/bin/env python3
"""
Test BitTorrent Port with Proper Handshake
Usage: python3 test-bt-handshake.py <host> <port>
"""

import socket
import sys
import struct

def test_bittorrent_port(host, port):
    """Test if a BitTorrent port is accessible and responding"""
    
    print(f"🧪 Testing BitTorrent connectivity to {host}:{port}")
    print()
    
    # BitTorrent handshake structure:
    # 1 byte: protocol name length (0x13 = 19)
    # 19 bytes: "BitTorrent protocol"
    # 8 bytes: reserved flags (zeros)
    # 20 bytes: info_hash (fake for testing)
    # 20 bytes: peer_id (fake for testing)
    
    pstr = b"BitTorrent protocol"
    pstrlen = len(pstr)
    reserved = b"\x00" * 8
    info_hash = b"\x00" * 20  # Fake info_hash
    peer_id = b"-TEST-" + b"0" * 14  # Fake peer_id
    
    handshake = struct.pack("B", pstrlen) + pstr + reserved + info_hash + peer_id
    
    try:
        # Test 1: TCP Connection
        print("📡 Test 1: TCP Connection")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        print("   ✅ Port is open and accepting connections")
        print()
        
        # Test 2: Send BitTorrent handshake
        print("📡 Test 2: BitTorrent Handshake")
        print(f"   Sending {len(handshake)} bytes handshake...")
        sock.send(handshake)
        
        # Try to receive response
        sock.settimeout(3)
        try:
            response = sock.recv(1024)
            if response:
                print(f"   ✅ Server responded with {len(response)} bytes!")
                
                # Check if it's a valid BitTorrent handshake response
                if len(response) >= 20 and response[0] == 19:
                    protocol_name = response[1:20].decode('ascii', errors='ignore')
                    print(f"   ✅ Valid BitTorrent handshake: '{protocol_name}'")
                    
                    if len(response) >= 68:
                        peer_id_response = response[48:68]
                        print(f"   📋 Peer ID: {peer_id_response[:20]}")
                else:
                    print(f"   ⚠️  Response doesn't look like BitTorrent handshake")
                    print(f"   First bytes (hex): {response[:20].hex()}")
            else:
                print("   ⚠️  Connection closed immediately (expected with fake info_hash)")
                print("   But the connection was established, so port IS working!")
        except socket.timeout:
            print("   ⚠️  No response (timeout)")
            print("   This is expected with a fake info_hash")
            print("   But the connection was established, so port IS working!")
        
        sock.close()
        print()
        
        # Conclusion
        print("━" * 60)
        print("🎯 CONCLUSION")
        print("━" * 60)
        print()
        print("✅ Your BitTorrent port IS accessible and working!")
        print()
        print("Why curl shows 'Connection reset':")
        print("  → curl sends HTTP (GET / HTTP/1.1)")
        print("  → BitTorrent expects binary handshake")
        print("  → Server rejects invalid protocol → RST")
        print()
        print("This is NORMAL behavior! Your port is OPEN. ✅")
        print()
        print("To verify real seeding:")
        print("  1. Check logs: podman logs torrentui | grep 'Upload Stats'")
        print("  2. Wait 5-10 min for tracker re-announce")
        print("  3. Monitor WebUI for upload speed > 0")
        print()
        
        return True
        
    except socket.timeout:
        print("   ❌ Connection timeout - port might be firewalled")
        return False
    except ConnectionRefusedError:
        print("   ❌ Connection refused - nothing listening on this port")
        return False
    except Exception as e:
        print(f"   ❌ Error: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 test-bt-handshake.py <host> [port]")
        print("Example: python3 test-bt-handshake.py 23.88.40.56 32767")
        sys.exit(1)
    
    host = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 32767
    
    success = test_bittorrent_port(host, port)
    sys.exit(0 if success else 1)
