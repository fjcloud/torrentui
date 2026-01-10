# 🧪 Testing Guide

## Quick Port Test

```bash
# Test your BitTorrent port
python3 test-bt-handshake.py <your-server-ip> <port>

# Example:
python3 test-bt-handshake.py 23.88.40.56 32767
```

**Expected Result:**
```
✅ Port is open and accepting connections
✅ Your BitTorrent port IS accessible and working!
```

## Understanding "Connection Reset" with curl

**❌ WRONG WAY:**
```bash
curl your-server:32767
# Result: Connection reset by peer
```

This does **NOT** mean your port is closed!

**Why it fails:**
- BitTorrent uses a **binary protocol**
- curl sends **HTTP** (`GET / HTTP/1.1`)
- Server rejects non-BitTorrent requests → RST

**✅ If you see "Connected" before "reset" = PORT IS OPEN!**

## Verifying Upload is Working

### 1. Check Application Logs

```bash
podman logs torrentui | grep "Upload Stats"
```

**Good output:**
```
📤 Upload Stats [torrent-name]: 1234567 bytes uploaded, 8 active conns, 25 peers total
```

Key metric: **`active conns > 0`** means peers are downloading from you!

### 2. Monitor WebUI

Look for in the torrent card:
```
⬆ 2.5 MB/s • 1.2 GB total
```

- **Upload speed > 0** = actively seeding
- **Total increases** = ratio improving

### 3. Check Ratio

```
📊 Ratio: 1.25
```

Color coding:
- 🟢 Green (≥ 2.0) = Excellent
- 🟢 Light green (≥ 1.0) = Good
- 🟠 Orange (≥ 0.5) = Fair
- 🔴 Red (< 0.5) = Poor

## Troubleshooting Zero Upload

If after 10+ minutes you still have:
- ⬆ **0 B/s** upload speed
- **0 active conns** in logs
- Ratio not increasing

### Check List:

1. **Port mapping correct?**
   ```bash
   podman inspect torrentui | grep -A5 PortBindings
   # Should show: "32767/tcp": [{"HostPort": "32767"}]
   ```

2. **Firewall open?**
   ```bash
   sudo firewall-cmd --list-ports | grep 32767
   # Should show: 32767/tcp
   ```

3. **Application listening?**
   ```bash
   podman logs torrentui | grep "listening on port"
   # Should show: Torrent client listening on port 32767
   ```

4. **Torrent popular enough?**
   - Try a very popular torrent (100+ seeders)
   - Private trackers may have ratio requirements
   - Some torrents have few/no leechers

5. **Tracker announcing?**
   ```bash
   podman logs torrentui | grep "Tracker:"
   # Should show tracker URLs
   ```

6. **Public IP configured?**
   ```bash
   podman inspect torrentui | grep PUBLIC_IP
   # Should show your real public IP
   ```

## Network Diagnostics

### tcpdump Analysis

```bash
# On server
sudo tcpdump -i any port 32767 -n -c 20
```

**Good pattern (port working):**
```
IP peer > server:32767: Flags [S]       ← Incoming connection
IP server:32767 > peer: Flags [S.]      ← Accepted ✅
IP peer > server:32767: Flags [.]       ← Established
IP server:32767 > peer: Flags [P.]      ← Data sent! 🎉
```

**Bad pattern (port blocked):**
```
IP peer > server:32767: Flags [S]       ← Incoming connection
(no response - timeout)                 ← Firewall blocking ❌
```

**Confusing pattern (but OK!):**
```
IP peer > server:32767: Flags [S]       ← Connection
IP server:32767 > peer: Flags [S.]      ← Accepted
IP server:32767 > peer: Flags [R]       ← Reset after

# This is NORMAL if:
# - Peer sent HTTP instead of BitTorrent protocol
# - Peer has wrong info_hash
# - Peer is testing (like curl)
# The fact it got [S.] means port IS open!
```

## Performance Optimization

For maximum seeding performance, ensure in your run command:

```bash
podman run -d \
  --name torrentui \
  -p 8080:8080 \
  -p 32767:32767 \              # Port mapping
  -e TORRENT_LISTEN_PORT=32767 \ # MUST match port mapping
  -e PUBLIC_IP=$(curl -s ifconfig.me) \  # Your public IP
  -v ./downloads:/app/downloads \
  -v ./data:/app/data \
  ghcr.io/fjcloud/torrentui:latest
```

### Environment Variables

- `TORRENT_LISTEN_PORT`: Port for incoming connections (default: 0 = random)
- `PUBLIC_IP`: Your public IPv4 (helps trackers announce correctly)
- `MAX_UPLOAD_RATE_KBPS`: Limit upload speed (0 = unlimited)
- `MAX_DOWNLOAD_RATE_KBPS`: Limit download speed (0 = unlimited)

## Expected Behavior

### New Torrent Added
```
✅ Added torrent: ubuntu-24.04-live-server.iso (InfoHash: abc123...)
   📡 Tracker: https://tracker.example.com:443/announce
   📤 Upload enabled for: ubuntu-24.04-live-server.iso
```

### During Download
```
⬇ 5.2 MB/s     # Download active
👥 12           # 12 peers connected
```

### After Complete (Seeding)
```
⬆ 2.1 MB/s • 850 MB total   # Upload active
📊 Ratio: 0.85                # Ratio improving
```

### Periodic Upload Stats (every 30s)
```
📤 Upload Stats [ubuntu-24.04-live-server.iso]: 891289600 bytes uploaded, 8 active conns, 25 peers total
```

## When to Worry

**🚨 Red flags:**
- Port test fails completely (connection refused)
- tcpdump shows no [S.] responses
- 0 active conns after 15+ minutes with popular torrent
- Firewall not showing port in allowed list

**✅ False alarms:**
- curl shows "Connection reset" (normal!)
- tcpdump shows some [R] resets (normal for invalid requests)
- No upload on unpopular/fully-seeded torrent (no demand)
- Low upload at night (fewer peers online)

## Getting Help

When asking for help, provide:

1. Port test result:
   ```bash
   python3 test-bt-handshake.py your-ip your-port
   ```

2. Container config:
   ```bash
   podman inspect torrentui | grep -E "(PortBindings|PUBLIC_IP|TORRENT_LISTEN_PORT)"
   ```

3. Recent logs:
   ```bash
   podman logs --tail 50 torrentui
   ```

4. Firewall status:
   ```bash
   sudo firewall-cmd --list-all
   ```

5. Network capture (10-20 packets):
   ```bash
   sudo tcpdump -i any port YOUR_PORT -n -c 20
   ```
