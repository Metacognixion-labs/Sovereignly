# Sovereignly Cloud v4.0 — Business Source License 1.1
FROM oven/bun:1-alpine AS builder
WORKDIR /app
COPY package.json bun.lock* ./
COPY packages/ ./packages/
COPY apps/oss/package.json ./apps/oss/
COPY apps/cloud/package.json ./apps/cloud/
RUN bun install --production
COPY apps/oss/ ./apps/oss/
COPY apps/cloud/ ./apps/cloud/
COPY dashboard/ ./dashboard/
COPY deploy/landing-page.html ./deploy/

FROM oven/bun:1-alpine
WORKDIR /app
COPY --from=litestream/litestream:0.3 /usr/local/bin/litestream /usr/local/bin/litestream
RUN addgroup -S sovereign && adduser -S sovereign -G sovereign
ENV NODE_ENV=production PORT=8787 DATA_DIR=/data WORKER_POOL_SIZE=2 LOG_LEVEL=minimal
RUN mkdir -p /data/platform /data/global /data/tenants && chown -R sovereign:sovereign /data
COPY --from=builder --chown=sovereign:sovereign /app .
COPY --chown=sovereign:sovereign deploy/litestream.yml /etc/litestream.yml
COPY --chown=sovereign:sovereign deploy/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh
USER sovereign
EXPOSE 8787
HEALTHCHECK --interval=10s --timeout=3s --start-period=8s --retries=3 \
  CMD bun -e "fetch('http://localhost:8787/_sovereign/health').then(r=>process.exit(r.ok?0:1))"
ENTRYPOINT ["/app/entrypoint.sh"]
