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
- Download management with real-time stats
- Seeding support with ratio tracking
- Disk space monitoring
- Persistent torrents across restarts
- Optional authentication with rate limiting
- Modern UI

## Configuration

| Variable | Default | Description |
|---|---|---|
| `TORRENTUI_LISTEN_ADDR` | `:8080` | Web UI listen address |
| `DOWNLOAD_DIR` | `./downloads` | Downloaded files directory |
| `DATA_DIR` | `./data` | Metadata and torrents directory |
| `TORRENTUI_LOG_FILE` | — | Log file path |
| `TORRENTUI_USERNAME` | — | Enables authentication |
| `TORRENTUI_PASSWORD` | — | Required if username is set |
| `TORRENTUI_SECURE_COOKIE` | `false` | Set to `true` with HTTPS |
| `SESSION_TIMEOUT_HOURS` | `24` | Session timeout |
| `TORRENT_LISTEN_PORT` | `0` (random) | Port for incoming torrent connections |
| `PUBLIC_IP` | — | Public IP address (improves seeding) |

## Container

```bash
docker pull ghcr.io/fjcloud/torrentui:latest

docker run -p 8080:8080 \
  -v ./downloads:/app/downloads \
  -v ./data:/app/data \
  -e TORRENTUI_USERNAME=admin \
  -e TORRENTUI_PASSWORD=your-password \
  ghcr.io/fjcloud/torrentui:latest
```

To enable seeding with a fixed port:

```bash
docker run -p 8080:8080 -p 42069:42069 \
  -v ./downloads:/app/downloads \
  -v ./data:/app/data \
  -e TORRENT_LISTEN_PORT=42069 \
  ghcr.io/fjcloud/torrentui:latest
```

## Make Targets

| Target | Description |
|---|---|
| `make build-local` | Build binary |
| `make run-local` | Run locally |
| `make build` | Build container |
| `make run` | Run container |
| `make clean-local` | Clean binary |
| `make clean` | Clean container |
| `make test` | Run tests |

## License

MIT
