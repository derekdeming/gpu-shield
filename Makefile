.PHONY: proto proto-go proto-python clean build test lint help

# Variables
PROTO_DIR := api/proto
PROTO_OUT_GO := pkg/proto
PROTO_OUT_PYTHON := python/gpushield_proto
PROTO_FILES := $(wildcard $(PROTO_DIR)/*.proto)

# Default target
help: ## Show this help message
	@echo "Available targets:"
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

proto: proto-go proto-python ## Generate protobuf stubs for Go and Python

proto-go: ## Generate Go protobuf stubs
	@echo "Generating Go protobuf stubs..."
	@mkdir -p $(PROTO_OUT_GO)/telemetry
	@mkdir -p $(PROTO_OUT_GO)/integrity
	@protoc \
		--go_out=$(PROTO_OUT_GO)/telemetry \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT_GO)/telemetry \
		--go-grpc_opt=paths=source_relative \
		--proto_path=$(PROTO_DIR) \
		$(PROTO_DIR)/telemetry.proto
	@protoc \
		--go_out=$(PROTO_OUT_GO)/integrity \
		--go_opt=paths=source_relative \
		--go-grpc_out=$(PROTO_OUT_GO)/integrity \
		--go-grpc_opt=paths=source_relative \
		--proto_path=$(PROTO_DIR) \
		$(PROTO_DIR)/integrity.proto
	@echo "Go protobuf stubs generated successfully"

proto-python: ## Generate Python protobuf stubs
	@echo "Generating Python protobuf stubs..."
	@mkdir -p $(PROTO_OUT_PYTHON)
	@python -m grpc_tools.protoc \
		--python_out=$(PROTO_OUT_PYTHON) \
		--grpc_python_out=$(PROTO_OUT_PYTHON) \
		--proto_path=$(PROTO_DIR) \
		$(PROTO_FILES)
	@touch $(PROTO_OUT_PYTHON)/__init__.py
	@echo "Python protobuf stubs generated successfully"

##@ Build

build: proto ## Build all binaries
	@echo "Building binaries..."
	@go build -o bin/sensor ./cmd/sensor
	@go build -o bin/collector ./cmd/collector
	@go build -o bin/alert ./cmd/alert
	@echo "Build completed successfully"

build-sensor: proto-go ## Build sensor binary
	@echo "Building sensor..."
	@go build -o bin/sensor ./cmd/sensor
	@echo "Sensor built successfully"

build-collector: proto-go ## Build collector binary
	@echo "Building collector..."
	@go build -o bin/collector ./cmd/collector
	@echo "Collector built successfully"

build-alert: proto-go ## Build alert binary
	@echo "Building alert..."
	@go build -o bin/alert ./cmd/alert
	@echo "Alert built successfully"

build-with-dcgm: proto-go ## Build sensor with native DCGM support
	@echo "Building sensor with DCGM support..."
	@CGO_ENABLED=1 go build -tags dcgm -o bin/sensor-dcgm ./cmd/sensor
	@echo "Sensor with DCGM built successfully"

build-with-rocm: proto-go ## Build sensor with ROCm support
	@echo "Building sensor with ROCm support..."
	@CGO_ENABLED=1 go build -tags rocm -o bin/sensor-rocm ./cmd/sensor
	@echo "Sensor with ROCm built successfully"

build-with-dynolog: proto-go ## Build sensor with Dynolog support
	@echo "Building sensor with Dynolog support..."
	@CGO_ENABLED=1 go build -tags dynolog -o bin/sensor-dynolog ./cmd/sensor
	@echo "Sensor with Dynolog built successfully"

build-all-vendors: build-with-dcgm build-with-rocm build-with-dynolog ## Build sensor with all vendor support

##@ Testing

test: ## Run Go tests
	@echo "Running Go tests..."
	@go test -v ./...

test-python: ## Run Python tests
	@echo "Running Python tests..."
	@python -m pytest python/tests/ -v

##@ Quality

lint: ## Run golangci-lint
	@echo "Running golangci-lint..."
	@golangci-lint run

lint-python: ## Run Python linting
	@echo "Running Python linting..."
	@python -m flake8 python/
	@python -m black --check python/
	@python -m isort --check-only python/

format: ## Format Go code
	@echo "Formatting Go code..."
	@go fmt ./...

format-python: ## Format Python code
	@echo "Formatting Python code..."
	@python -m black python/
	@python -m isort python/

##@ Dependencies

deps: ## Download Go dependencies
	@echo "Downloading Go dependencies..."
	@go mod download
	@go mod tidy

deps-python: ## Install Python dependencies
	@echo "Installing Python dependencies..."
	@pip install -r python/requirements.txt

install-tools: ## Install development tools
	@echo "Installing development tools..."
	@go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	@go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

##@ Docker

docker-build: ## Build Docker images
	@echo "Building Docker images..."
	@docker build -t gpushield/sensor:latest -f docker/Dockerfile.sensor .
	@docker build -t gpushield/collector:latest -f docker/Dockerfile.collector .
	@docker build -t gpushield/alert:latest -f docker/Dockerfile.alert .

##@ Kubernetes

helm-template: ## Generate Helm templates
	@echo "Generating Helm templates..."
	@helm template gpu-runtime-security ./helm/gpu-runtime-security

helm-install: ## Install Helm chart
	@echo "Installing Helm chart..."
	@helm install gpu-runtime-security ./helm/gpu-runtime-security

helm-upgrade: ## Upgrade Helm chart
	@echo "Upgrading Helm chart..."
	@helm upgrade gpu-runtime-security ./helm/gpu-runtime-security

##@ Security

sbom: ## Generate SBOM with syft
	@echo "Generating SBOM..."
	@syft . -o spdx-json=sbom.json
	@echo "SBOM generated: sbom.json"

license-check: ## Check third-party license compliance
	@echo "Checking license compliance..."
	@echo "Verifying third-party licenses exist..."
	@test -f third_party/nvidia-dcgm/LICENSE || { echo "NVIDIA DCGM license missing"; exit 1; }
	@test -f third_party/dynolog/LICENSE || { echo "Dynolog license missing"; exit 1; }
	@test -f third_party/rocprofiler-compute/LICENSE || { echo "ROCProfiler Compute license missing"; exit 1; }
	@echo "✅ All third-party licenses present"
	@echo "Checking license attribution in main LICENSE file..."
	@grep -q "NVIDIA DCGM" LICENSE || { echo "NVIDIA DCGM attribution missing from LICENSE"; exit 1; }
	@grep -q "Meta Dynolog" LICENSE || { echo "Dynolog attribution missing from LICENSE"; exit 1; }
	@grep -q "rocprofiler-compute" LICENSE || { echo "ROCProfiler attribution missing from LICENSE"; exit 1; }
	@echo "✅ License compliance check passed"

security-scan: ## Run security scans
	@echo "Running security scans..."
	@gosec ./...
	@nancy sleuth

##@ Cleanup

clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	@rm -rf bin/
	@rm -rf $(PROTO_OUT_GO)/
	@rm -rf $(PROTO_OUT_PYTHON)/
	@rm -f sbom.json
	@echo "Clean completed"

clean-docker: ## Clean Docker images
	@echo "Cleaning Docker images..."
	@docker rmi gpushield/sensor:latest || true
	@docker rmi gpushield/collector:latest || true
	@docker rmi gpushield/alert:latest || true

##@ Utilities

check-deps: ## Check if required tools are installed
	@echo "Checking dependencies..."
	@command -v protoc >/dev/null 2>&1 || { echo "protoc is required but not installed. Please install Protocol Buffers compiler."; exit 1; }
	@command -v go >/dev/null 2>&1 || { echo "go is required but not installed."; exit 1; }
	@command -v python >/dev/null 2>&1 || { echo "python is required but not installed."; exit 1; }
	@command -v helm >/dev/null 2>&1 || { echo "helm is required but not installed."; exit 1; }
	@echo "All required dependencies are installed" 