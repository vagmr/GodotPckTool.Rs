# =============================================================================
# GodotPckTool - Rust Edition
# Multi-stage Docker build for minimal image size
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder
# -----------------------------------------------------------------------------
FROM rust:1.75-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

WORKDIR /build

# Copy workspace manifests first (for better layer caching)
COPY Cargo.toml Cargo.lock* ./
COPY pck/Cargo.toml pck/
COPY cli/Cargo.toml cli/

# Create dummy source files to build dependencies
RUN mkdir -p pck/src cli/src \
    && echo "pub fn dummy() {}" > pck/src/lib.rs \
    && echo "fn main() {}" > cli/src/main.rs \
    && cargo build --release \
    && rm -rf pck/src cli/src

# Copy actual source code
COPY pck/src pck/src
COPY cli/src cli/src

# Touch files to invalidate cache and rebuild with real sources
RUN touch pck/src/lib.rs cli/src/main.rs

# Build the release binary
RUN cargo build --release --bin godotpcktool

# -----------------------------------------------------------------------------
# Stage 2: Runtime (minimal image)
# -----------------------------------------------------------------------------
FROM alpine:3.19 AS runtime

# Add non-root user for security
RUN adduser -D -u 1000 pckuser

WORKDIR /app

# Copy the compiled binary
COPY --from=builder /build/target/release/godotpcktool /usr/local/bin/

# Set ownership
RUN chown -R pckuser:pckuser /app

USER pckuser

ENTRYPOINT ["godotpcktool"]
CMD ["--help"]
