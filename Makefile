# TorrentUI Makefile

APP_NAME := torrentui
IMAGE_NAME := quay.io/$(APP_NAME):latest
BINARY := $(APP_NAME)

.PHONY: help build build-local run run-local stop clean clean-local test

help: ## Show help
	@echo "TorrentUI Makefile"
	@echo ""
	@echo "Usage:"
	@echo "  make build-local  - Build binary locally"
	@echo "  make run-local    - Run binary locally"
	@echo "  make build        - Build container image"
	@echo "  make run          - Run container"
	@echo "  make stop         - Stop container"
	@echo "  make clean        - Clean up container"
	@echo "  make clean-local  - Clean up local binary"
	@echo "  make test         - Run tests"

build-local: ## Build binary locally
	@echo "Building $(BINARY) locally..."
	@mkdir -p downloads session logs
	go build -o $(BINARY) server.go
	@echo "✅ Build complete: ./$(BINARY)"
	@echo ""
	@echo "Run with: make run-local"

run-local: ## Run binary locally
	@echo "Starting $(BINARY) locally..."
	@mkdir -p downloads session logs
	@echo "Server running at http://localhost:8080"
	@echo "Press Ctrl+C to stop"
	@echo ""
	./$(BINARY)

build: ## Build container image
	@echo "Building $(IMAGE_NAME)..."
	podman build -t $(IMAGE_NAME) -f Containerfile .
	@echo "Build complete!"

run: ## Run container
	@echo "Starting $(APP_NAME)..."
	podman run --rm -p 8080:8080 \
		-v $(PWD)/downloads:/app/downloads \
		-v $(PWD)/session:/app/session \
		$(IMAGE_NAME)

run-daemon: ## Run in background
	@echo "Starting $(APP_NAME) in background..."
	podman run -d --name $(APP_NAME) -p 8080:8080 \
		-v $(PWD)/downloads:/app/downloads \
		-v $(PWD)/session:/app/session \
		$(IMAGE_NAME)
	@echo "Container started. Use 'make stop' to stop."

stop: ## Stop container
	@echo "Stopping $(APP_NAME)..."
	@podman stop $(APP_NAME) 2>/dev/null || true
	@podman rm $(APP_NAME) 2>/dev/null || true
	@echo "Container stopped."

logs: ## Show logs
	podman logs $(APP_NAME)

clean: ## Clean up container
	@echo "Cleaning up container..."
	@podman rmi $(IMAGE_NAME) 2>/dev/null || true
	@podman stop $(APP_NAME) 2>/dev/null || true
	@podman rm $(APP_NAME) 2>/dev/null || true
	@echo "Container cleanup complete."

clean-local: ## Clean up local binary and data
	@echo "Cleaning up local files..."
	@rm -f $(BINARY)
	@rm -rf downloads session logs
	@echo "Local cleanup complete."

clean-all: clean clean-local ## Clean everything
	@echo "Full cleanup complete."

test: ## Run tests
	@./test.sh

fmt: ## Format code
	go fmt ./...

vet: ## Vet code
	go vet ./...
