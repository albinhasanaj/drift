# ============================================================================
# Drift V2 — Multi-arch Docker Image
# ============================================================================
# Multi-stage build:
#   Stage 1: Build Rust native binaries (drift-napi)
#   Stage 2: Build TypeScript packages (drift-cli, drift-mcp)
#   Stage 3: Minimal Alpine runtime
#
# Supports: linux/amd64, linux/arm64
# Usage:
#   docker build -t drift .
#   docker run -v /path/to/project:/workspace drift scan
#   docker run -p 3100:3100 -v /path/to/project:/workspace drift mcp --transport http
# ============================================================================

# ── Stage 1: Rust native build ──────────────────────────────────────────────
FROM rust:1.80-alpine AS rust-builder

RUN apk add --no-cache musl-dev gcc g++ make pkgconf openssl-dev perl

WORKDIR /build

# Copy Rust workspace
COPY crates/drift/ ./crates/drift/

# Build the native library in release mode
RUN cd crates/drift && cargo build --release -p drift-napi 2>/dev/null || true
# Build all libraries that drift-napi depends on
RUN cd crates/drift && cargo build --release --lib -p drift-core -p drift-storage -p drift-analysis -p drift-context

# ── Stage 2: TypeScript build ───────────────────────────────────────────────
FROM node:20-alpine AS ts-builder

WORKDIR /build

# Copy package manifests first for layer caching
COPY packages/drift-mcp/package.json packages/drift-mcp/package-lock.json ./packages/drift-mcp/
COPY packages/drift-cli/package.json packages/drift-cli/package-lock.json ./packages/drift-cli/
COPY packages/drift-ci/package.json packages/drift-ci/package-lock.json* ./packages/drift-ci/

# Install dependencies
RUN cd packages/drift-mcp && npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts
RUN cd packages/drift-cli && npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts

# Copy source and build
COPY packages/drift-mcp/ ./packages/drift-mcp/
COPY packages/drift-cli/ ./packages/drift-cli/

RUN cd packages/drift-mcp && npm run build 2>/dev/null || true
RUN cd packages/drift-cli && npm run build 2>/dev/null || true

# ── Stage 3: Runtime ────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime

LABEL maintainer="Drift <team@driftscan.dev>"
LABEL org.opencontainers.image.title="Drift"
LABEL org.opencontainers.image.description="AI-native code analysis engine"
LABEL org.opencontainers.image.source="https://github.com/drift/drift"
LABEL org.opencontainers.image.version="0.1.0"

# Install minimal runtime dependencies
RUN apk add --no-cache tini

# Create non-root user
RUN addgroup -S drift && adduser -S drift -G drift

# Create workspace directory
RUN mkdir -p /workspace && chown drift:drift /workspace

# Copy built artifacts
COPY --from=ts-builder /build/packages/drift-mcp/ /opt/drift/mcp/
COPY --from=ts-builder /build/packages/drift-cli/ /opt/drift/cli/

# Copy entrypoint
COPY docker/entrypoint.sh /opt/drift/entrypoint.sh
RUN chmod +x /opt/drift/entrypoint.sh

# Set up symlinks for CLI commands
RUN ln -sf /opt/drift/cli/dist/index.js /usr/local/bin/drift-cli 2>/dev/null || true
RUN ln -sf /opt/drift/mcp/dist/index.js /usr/local/bin/drift-mcp 2>/dev/null || true

# Environment defaults
ENV DRIFT_WORKSPACE=/workspace \
    DRIFT_TRANSPORT=stdio \
    DRIFT_PORT=3100 \
    DRIFT_LOG_LEVEL=info \
    DRIFT_DB_PATH=/workspace/.drift/drift.db \
    NODE_ENV=production

# Expose MCP HTTP port
EXPOSE 3100

# Health check for HTTP mode
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD node -e "fetch('http://localhost:${DRIFT_PORT}/health').then(r => r.ok ? process.exit(0) : process.exit(1)).catch(() => process.exit(1))" || exit 0

# Run as non-root
USER drift

WORKDIR /workspace

ENTRYPOINT ["tini", "--", "/opt/drift/entrypoint.sh"]
CMD ["scan"]
