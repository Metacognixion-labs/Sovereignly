FROM oven/bun:1-alpine AS builder
WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install
COPY . .
ENV SOVEREIGN_API_URL=https://sovereignly.fly.dev
RUN bun run build

FROM oven/bun:1-alpine
WORKDIR /app
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static
COPY --from=builder /app/public ./public
ENV PORT=3000 NODE_ENV=production HOSTNAME=0.0.0.0
EXPOSE 3000
CMD ["bun", "server.js"]
