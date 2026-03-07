# Sovereignly OSS v3.0.1 — MIT License
FROM oven/bun:1-alpine AS builder
WORKDIR /app
COPY package.json bun.lock* ./
COPY packages/ ./packages/
COPY apps/oss/package.json ./apps/oss/
RUN bun install --frozen-lockfile --production
COPY apps/oss/ ./apps/oss/

FROM oven/bun:1-alpine
WORKDIR /app
RUN addgroup -S sovereign && adduser -S sovereign -G sovereign
ENV NODE_ENV=production PORT=8787 DATA_DIR=/data WORKER_POOL_SIZE=2 LOG_LEVEL=minimal
RUN mkdir -p /data/platform && chown -R sovereign:sovereign /data
COPY --from=builder --chown=sovereign:sovereign /app .
USER sovereign
EXPOSE 8787
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD bun -e "fetch('http://localhost:8787/_sovereign/health').then(r=>process.exit(r.ok?0:1))"
CMD ["bun", "apps/oss/src/server.ts"]
