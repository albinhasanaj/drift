#!/bin/sh
# ============================================================================
# Drift Docker Entrypoint
# ============================================================================
# Handles workspace initialization, transport selection, and command routing.
#
# Environment variables:
#   DRIFT_WORKSPACE     - Path to workspace (default: /workspace)
#   DRIFT_TRANSPORT     - MCP transport: stdio | http (default: stdio)
#   DRIFT_PORT          - HTTP port (default: 3100)
#   DRIFT_LOG_LEVEL     - Log level: debug | info | warn | error (default: info)
#   DRIFT_LICENSE_KEY   - License JWT (optional)
#   DRIFT_LICENSE_FILE  - Path to license JWT file (optional)
# ============================================================================

set -e

WORKSPACE="${DRIFT_WORKSPACE:-/workspace}"
TRANSPORT="${DRIFT_TRANSPORT:-stdio}"
PORT="${DRIFT_PORT:-3100}"

# Ensure workspace directory exists
if [ ! -d "$WORKSPACE" ]; then
    echo "Error: workspace directory $WORKSPACE does not exist" >&2
    echo "Mount your project: docker run -v /path/to/project:/workspace drift" >&2
    exit 1
fi

# Auto-initialize .drift/ if not present
if [ ! -d "$WORKSPACE/.drift" ]; then
    echo "Initializing Drift workspace in $WORKSPACE..." >&2
    mkdir -p "$WORKSPACE/.drift"
    mkdir -p "$WORKSPACE/.drift-backups"
fi

# Route commands
case "${1:-scan}" in
    # MCP server mode
    mcp)
        shift
        if [ "$TRANSPORT" = "http" ] || echo "$@" | grep -q "\-\-transport http"; then
            echo "Starting Drift MCP server (HTTP on port $PORT)..." >&2
            exec node /opt/drift/mcp/dist/index.js --transport http --port "$PORT" --project-root "$WORKSPACE" "$@"
        else
            echo "Starting Drift MCP server (stdio)..." >&2
            exec node /opt/drift/mcp/dist/index.js --project-root "$WORKSPACE" "$@"
        fi
        ;;

    # CLI commands (26 total)
    scan|analyze|check|status|report|patterns|violations|security|contracts|coupling|dna|taint|errors|test-quality|impact|fix|dismiss|suppress|explain|simulate|context|audit|export|gc|setup|doctor)
        echo "Running: drift $*" >&2
        exec node /opt/drift/cli/dist/index.js "$@" --project-root "$WORKSPACE"
        ;;

    # Health check endpoint (used by HEALTHCHECK)
    healthcheck)
        if command -v curl >/dev/null 2>&1; then
            curl -sf "http://localhost:$PORT/health" || exit 1
        else
            node -e "fetch('http://localhost:${PORT}/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))"
        fi
        ;;

    # Shell access for debugging
    sh|bash)
        exec /bin/sh
        ;;

    # Pass through any other command
    *)
        exec "$@"
        ;;
esac
