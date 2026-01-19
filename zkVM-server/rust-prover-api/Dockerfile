# --- Build Stage ---
FROM rust:1.75-slim as builder
WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    git \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.risc0/bin:${PATH}"

RUN curl -L https://risc0.com/install | bash

RUN --mount=type=cache,target=/root/.risc0 \
    rzup install rust

COPY Cargo.toml Cargo.lock ./
COPY methods/Cargo.toml methods/Cargo.toml
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release -p host

# --- Run Stage ---
FROM debian:bookworm-slim
WORKDIR /app

# 安裝必要的執行庫 (例如 OpenSSL)
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/host /usr/local/bin/host

EXPOSE 3001
CMD ["host"]