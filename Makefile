# Plumbline developer commands. Run `make help` for the list.

STATICCHECK_VERSION := v0.8.2
BINARY := bin/plumbline

.PHONY: help run build test lint vet staticcheck e2e screenshots docker clean

help: ## Show this help
	@grep -E '^[a-z0-9-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

run: ## Run locally on :8080 (simulated tenant only unless GITHUB_TOKEN/GITHUB_ORG are set)
	go run ./cmd/plumbline

build: ## Build a static binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BINARY) ./cmd/plumbline

test: ## Run all tests with the race detector
	go test -race -count=1 ./...

lint: vet staticcheck ## go vet + staticcheck

vet:
	go vet ./...

staticcheck:
	go run honnef.co/go/tools/cmd/staticcheck@$(STATICCHECK_VERSION) ./...

e2e: build ## Browser tests (Playwright): needs Node; starts the app on :8099
	cd e2e && npm ci && npx playwright install chromium && npx playwright test

screenshots: build ## Regenerate docs/screenshots/*.png (needs `make e2e` deps installed)
	cd e2e && node screenshots.mjs

docker: ## Build the container image
	docker build -t plumbline:local .

clean:
	rm -rf bin/ plumbline.db plumbline.db-wal plumbline.db-shm
