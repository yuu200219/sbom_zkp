FROM node:20-bookworm-slim

RUN apt-get update && apt-get install -y \
    curl \
    python3 \
    python3-pip && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    syft --version && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin && \
    grype --version && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY sbom_service/package*.json .
RUN npm install

COPY sbom_service/src/ ./src/
COPY sbom_service/tsconfig.json .

RUN npm run build

ENV NODE_ENV=development
ENV PORT=3002

EXPOSE 3002

CMD ["node", "dist/index.js"]