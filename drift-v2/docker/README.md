# Drift Docker Deployment

Multi-arch Docker images for running Drift in containers.

## Quick Start

```bash
# Build the image
docker build -t drift -f docker/Dockerfile .

# Scan a project
docker run -v /path/to/project:/workspace drift scan

# Start MCP server (HTTP transport)
docker run -p 3100:3100 -v /path/to/project:/workspace drift mcp --transport http

# Run quality gate check (CI mode)
docker run -v /path/to/project:/workspace -e CI=true drift check
```

## Docker Compose

```bash
# Start MCP server
docker compose -f docker/docker-compose.yml up drift-mcp

# One-shot CLI scan
docker compose -f docker/docker-compose.yml run drift-cli scan

# CI mode
docker compose -f docker/docker-compose.yml --profile ci up drift-ci
```

## Multi-Arch Build

```bash
# Build for both amd64 and arm64
docker buildx build --platform linux/amd64,linux/arm64 \
  -t drift:latest -f docker/Dockerfile .
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DRIFT_WORKSPACE` | `/workspace` | Path to the project workspace |
| `DRIFT_TRANSPORT` | `stdio` | MCP transport: `stdio` or `http` |
| `DRIFT_PORT` | `3100` | HTTP port for MCP server |
| `DRIFT_LOG_LEVEL` | `info` | Log level: `debug`, `info`, `warn`, `error` |
| `DRIFT_LICENSE_KEY` | | License JWT string |
| `DRIFT_LICENSE_FILE` | | Path to license JWT file |

## Resource Limits

Default compose limits:
- **Memory:** 512MB
- **CPU:** 2 cores

The container uses `tini` as PID 1 for proper signal handling and runs as a non-root `drift` user.

## Connecting MCP Clients

When running in HTTP mode, MCP clients can connect to:

```
http://localhost:3100/mcp
```

The server supports Server-Sent Events (SSE) for streaming responses.
