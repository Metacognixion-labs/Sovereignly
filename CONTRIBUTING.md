# Contributing to Sovereignly

Contributions to MIT-licensed components are welcome.

## What You Can Contribute To

- `packages/core/` — shared types and utilities
- `packages/sdk/` — client SDK
- `apps/oss/` — open-source single-tenant server
- `contracts/` — Solidity smart contracts
- `dashboard/` — admin dashboard UI
- Documentation and tests

## What Requires a License

- `apps/cloud/` is Business Source License 1.1
- You can read, fork, and modify it
- You may NOT offer it as a hosted service without a commercial license

## Development

```bash
bun install
bun run dev          # OSS server on :8787
bun test             # Integration tests
bun run typecheck    # TypeScript strict mode
```

## Pull Request Process

1. Fork the repository
2. Create a feature branch (`git checkout -b feat/my-feature`)
3. Make your changes
4. Run `bun test` and `bun run typecheck`
5. Commit with conventional commits (`feat:`, `fix:`, `docs:`)
6. Open a PR against `main`

## Code Style

- TypeScript strict mode
- No `any` types (use proper generics)
- Business logic in engine modules, not route handlers
- All security events logged to SovereignChain
