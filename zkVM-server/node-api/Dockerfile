# --- 第一階段：編譯 (Builder Stage) ---
FROM node:20-slim AS builder

# 直接設定為 /app
WORKDIR /app

# 先複製 package 檔案以利用快取 (Cache)
# 因為 context 在根目錄，所以要從 node-api/ 找
COPY node-api/package*.json ./

# 安裝所有依賴（包含開發依賴用來編譯）
RUN npm install

# 複製 node-api 原始碼到 /app
COPY node-api/ .

# 執行編譯 (產出 /app/dist)
RUN npm run build


# --- 第二階段：執行 (Run Stage) ---
FROM node:20-slim

# 執行環境的工作目錄也要是 /app，才能對應 Volume
WORKDIR /app

# 安裝生產環境需要的系統套件
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*

# 1. 從 builder 階段搬運產出
# 此時 builder 的東西都在 /app 下
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/dist ./dist

# 2. 只安裝生產環境依賴
RUN npm install --omit=dev

# 確保 proofs 目錄存在
RUN mkdir -p proofs

EXPOSE 3000

# 執行編譯後的 js
# 結構現在是 /app/dist/index.js
CMD ["node", "dist/index.js"]