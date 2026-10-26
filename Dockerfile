# AUTHENTIX / EduVerify-AI (SIH26261)
# Full-Stack Web & API Container (Node.js 22 LTS + Built-in SQLite WAL)
FROM node:22-bookworm-slim AS builder

WORKDIR /app
COPY package.json ./
RUN npm install

COPY index.html tsconfig.json vite.config.ts metadata.json ./
COPY public ./public
COPY src ./src
RUN npm run build

FROM node:22-bookworm-slim AS runtime

ENV NODE_ENV=production \
    PORT=3000 \
    SQLITE_DB_PATH=/app/data/authentix.sqlite \
    UPLOAD_DIR=/app/data/uploads \
    SAMPLE_DOCS_DIR=/app/data/sample_docs \
    OCR_SERVICE_URL=http://ocr-service:8001

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY package.json server.ts tsconfig.json metadata.json ./
COPY db ./db
COPY scripts ./scripts
COPY src ./src

RUN mkdir -p /app/data/uploads /app/data/sample_docs && chown -R node:node /app

USER node
EXPOSE 3000

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=3 \
  CMD curl -fsS http://127.0.0.1:3000/api/health || exit 1

CMD ["./node_modules/.bin/tsx", "server.ts"]
