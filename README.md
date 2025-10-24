# TorrentUI

Simple BitTorrent client with web UI.

## Quick Start

```bash
# Local
make build-local
make run-local

# Container
make build
make run
```

Open http://localhost:8080

## Features

- Drag & drop .torrent files
- Download management
- Seeding support
- Modern UI (Inter font)
- Optional authentication

## Commands

```bash
make build-local   # Build binary
make run-local     # Run locally
make build         # Build container
make run           # Run container
make clean-local   # Clean binary
make clean         # Clean container
make test          # Run tests
```

## Config

Environment variables:
- `TORRENTUI_LISTEN_ADDR` (default: :8080) - Web UI listen address
- `DOWNLOAD_DIR` (default: ./downloads) - Downloaded files directory
- `DATA_DIR` (default: ./data) - Metadata, torrents, database directory
- `TORRENTUI_LOG_FILE` (optional) - Log file path
- `TORRENTUI_USERNAME` (optional) - Enables authentication
- `TORRENTUI_PASSWORD` (optional) - Required if username is set
- `TORRENTUI_SECURE_COOKIE` (default: false) - Set to true with HTTPS
- `SESSION_TIMEOUT_HOURS` (default: 24) - Session timeout in hours
- `TORRENT_LISTEN_PORT` (default: 0, random) - Port for incoming torrent connections (seeding)
- `PUBLIC_IP` (optional) - Your public IP address (improves seeding)

## Authentication

To enable authentication, set both username and password:

```bash
# Local (development)
export TORRENTUI_USERNAME=admin
export TORRENTUI_PASSWORD=your-strong-password
make run-local

# Production (with HTTPS)
export TORRENTUI_USERNAME=admin
export TORRENTUI_PASSWORD=your-strong-password
export TORRENTUI_SECURE_COOKIE=true
./torrentui

# Container
podman run -p 8080:8080 \
  -e TORRENTUI_USERNAME=admin \
  -e TORRENTUI_PASSWORD=your-strong-password \
  -e TORRENTUI_SECURE_COOKIE=true \
  quay.io/torrentui:latest
```

If no credentials are configured, the app runs without authentication.

### Security Features

- **Bcrypt password hashing** (cost 12)
- **Rate limiting** (5 login attempts per minute per IP)
- **HttpOnly cookies** (prevents XSS)
- **SameSite=Strict** (prevents CSRF)
- **Secure cookie flag** (when enabled with HTTPS)
- **Session timeout** (configurable)
- **Failed login logging**

⚠️ **Important:** Use strong passwords (12+ characters) and enable `TORRENTUI_SECURE_COOKIE=true` when using HTTPS in production.

## Container Registry

Images are automatically built and published to GitHub Container Registry:

```bash
# Pull latest
docker pull ghcr.io/fjcloud/torrentui:latest

# Run (only mount downloads for data files)
docker run -p 8080:8080 \
  -v ./downloads:/app/downloads \
  -v ./data:/app/data \
  -e TORRENTUI_USERNAME=admin \
  -e TORRENTUI_PASSWORD=your-password \
  ghcr.io/fjcloud/torrentui:latest

# Run with fixed seeding port (optional, for port forwarding)
docker run -p 8080:8080 -p 42069:42069 \
  -v ./downloads:/app/downloads \
  -v ./data:/app/data \
  -e TORRENTUI_USERNAME=admin \
  -e TORRENTUI_PASSWORD=your-password \
  -e TORRENT_LISTEN_PORT=42069 \
  ghcr.io/fjcloud/torrentui:latest
```

## Development

### CI/CD

- **GitHub Actions**: Builds and pushes images on every commit to main
- **Renovate**: Automatically updates dependencies (runs weekly)
- **Multi-arch**: Supports linux/amd64 and linux/arm64

### Workflows

- `.github/workflows/build.yml` - Build and push to GHCR
- `.github/workflows/test.yml` - Run tests and checks

## License

MIT
