# syntax=docker/dockerfile:1
FROM rust:1.75-slim as builder

WORKDIR /app

# 1. 確保所有工具都在
RUN apt-get update && apt-get install -y \
    curl git pkg-config libssl-dev build-essential unzip xz-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 2. 直接執行安裝腳本並指定安裝路徑，不要依賴環境變數
RUN curl -L https://risc0.com/install | bash

# 3. 使用絕對路徑執行安裝，並加入 --yes 或對應參數 (如果有的話)
# 這裡我們加上 RISC0_HOME 確保快取路徑正確
ENV RISC0_HOME=/root/.risc0
RUN --mount=type=cache,target=/root/.risc0 \
    /root/.risc0/bin/rzup install rust

# 4. 關鍵：在編譯時「手動」把路徑帶進去
COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    PATH="/root/.risc0/bin:${PATH}" cargo build --release -p host

# --- Run Stage ---
FROM debian:bookworm-slim
WORKDIR /app
RUN apt-get update && apt-get install -y libssl3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/host /usr/local/bin/host
EXPOSE 3001
CMD ["host"]