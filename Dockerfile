# Build stage
FROM rustlang/rust:nightly-bookworm AS builder

WORKDIR /app

# Copy manifests
COPY Cargo.toml ./

# Copy source code
COPY src ./src

# Copy static files (needed for compile-time include_str! macros)
COPY static ./static

# Build for release
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install CA certificates for HTTPS
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/target/release/pinchat /usr/local/bin/pinchat

# Copy static files
COPY static ./static

# Create directory for certificates
RUN mkdir -p /app/certs

# Expose port
EXPOSE 3000

# Set environment variables
ENV RUST_LOG=pinchat=info

# Run the binary
CMD ["pinchat"]