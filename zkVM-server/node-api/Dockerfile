FROM node:20-slim

WORKDIR /app

# 安裝基本依賴（如果 Rust 需要編譯某些 C 套件才需要，否則 slim 即可）
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
RUN npm install

# 複製其餘檔案
COPY . .

# 確保 proofs 目錄存在
RUN mkdir -p proofs

EXPOSE 3000

# 執行 tsx watch (假設你的 package.json 裡有 "dev": "tsx watch src/index.ts")
CMD ["npm", "run", "dev"]