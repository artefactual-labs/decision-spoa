APP_SPOA  := decision-spoa
APP_UPD   := decision-geoip-db-updates
APP_CHECK := decision-configcheck

LDFLAGS  := -X main.version=$(shell git describe --tags --always 2>/dev/null || echo dev) \
            -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo none) \
            -X main.date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: all build clean

all: build

build:
	@echo "🔧 Building $(APP_SPOA), $(APP_UPD), and $(APP_CHECK)..."
	@mkdir -p build
	# Force using local Go toolchain (no auto-download)
	env GOTOOLCHAIN=local go build -trimpath -mod=readonly -ldflags "$(LDFLAGS)" -o ./build/$(APP_SPOA) ./cmd/decision-spoa
	env GOTOOLCHAIN=local go build -trimpath -mod=readonly -ldflags "$(LDFLAGS)" -o ./build/$(APP_UPD) ./cmd/decision-geoip-db-updates
	env GOTOOLCHAIN=local go build -trimpath -mod=readonly -ldflags "$(LDFLAGS)" -o ./build/$(APP_CHECK) ./cmd/decision-configcheck
	@echo "✅ Binaries at ./build/$(APP_SPOA), ./build/$(APP_UPD), and ./build/$(APP_CHECK)"

clean:
	rm -rf build
