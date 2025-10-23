# TorrentUI Containerfile
# Multi-stage build using UBI Red Hat minimal image

# Stage 1: Build stage
FROM registry.access.redhat.com/ubi8/go-toolset:1.21 AS builder

# Set working directory
WORKDIR /workspace

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o /tmp/torrentui server.go

# Stage 2: Runtime stage
FROM registry.access.redhat.com/ubi8/ubi-minimal:8.8

# Install necessary packages
RUN microdnf update -y && \
    microdnf install -y ca-certificates tzdata && \
    microdnf clean all

# Create non-root user
RUN adduser --uid 1001 --gid 0 --home-dir /app --create-home torrentui

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /tmp/torrentui /app/torrentui

# Copy static files
COPY --from=builder /workspace/static /app/static

# Create necessary directories
RUN mkdir -p /app/downloads /app/session /app/logs && \
    chown -R torrentui:0 /app && \
    chmod -R 777 /app

# Set environment variables
ENV TORRENTUI_LISTEN_ADDR=:8080 \
    TORRENTUI_DOWNLOAD_DIR=/app/downloads \
    TORRENTUI_SESSION_DIR=/app/session \
    TORRENTUI_MAX_UPLOAD_RATE_KBPS=0 \
    TORRENTUI_MAX_DOWNLOAD_RATE_KBPS=0

# Expose port
EXPOSE 8080

# Switch to non-root user
USER 1001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/health || exit 1

# Run the application
CMD ["/app/torrentui"]
