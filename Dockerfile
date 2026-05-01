# Build stage
FROM rust:1.90-bookworm AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Copy static files (needed for compile-time include_str! macros)
COPY static ./static

# Build for release
RUN cargo build --release --locked

# Runtime stage
FROM debian:bookworm-slim

# Pull every security update available for the base image, then install
# CA certificates for outbound HTTPS. The upgrade keeps libsystemd0/libudev1,
# zlib1g, and friends current with Debian security patches even though the
# affected APIs are not reachable from the pinchat binary at runtime.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && \
    apt-get install -y --no-install-recommends ca-certificates && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/pinchat /usr/local/bin/pinchat

# Copy static files
COPY static ./static

# Create directory for certificates
RUN mkdir -p /app/certs

# Create non-root user
RUN useradd -m -u 1000 pinchat && \
    chown -R pinchat:pinchat /app

# Switch to non-root user
USER pinchat

# Expose port
EXPOSE 3000

# Set environment variables
ENV RUST_LOG=pinchat=info

# Run the binary
CMD ["pinchat"]
