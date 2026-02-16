# hook-chain — Sequential Hook Executor

default:
    @just --list

# Build the binary
build:
    go build -o bin/hook-chain .

# Install to GOPATH/bin
install:
    go install .

# Run tests in Docker container (MANDATORY - never run tests on host)
test:
    @echo "Running tests in Docker container..."
    docker build -f Dockerfile.test -t hook-chain-test .
    docker run --rm hook-chain-test

# Run tests with verbose output in Docker
test-verbose:
    docker build -f Dockerfile.test -t hook-chain-test .
    docker run --rm hook-chain-test go test ./internal/... -race -count=1 -v

# Run tests and extract coverage report
test-coverage:
    docker build -f Dockerfile.test -t hook-chain-test .
    docker run --rm -v $$(pwd)/coverage:/tmp/coverage hook-chain-test sh -c "go test ./internal/... -race -count=1 -coverprofile=/tmp/coverage/coverage.out && echo 'Coverage written to coverage/coverage.out'"
    go tool cover -func=coverage/coverage.out

# Run linter
lint:
    golangci-lint run ./...

# Run security vulnerability check
vulncheck:
    govulncheck ./...

# Clean build artifacts
clean:
    rm -rf bin/ coverage/

# GoReleaser dry run (snapshot build)
snapshot:
    goreleaser build --snapshot --single-target --clean
