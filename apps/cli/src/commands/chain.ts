const c = { bold: "\x1b[1m", green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", dim: "\x1b[2m", reset: "\x1b[0m" };

export async function chain(config: { endpoint: string; token: string }, args: string[]) {
  const sub = args[0] ?? "stats";
  const headers: Record<string, string> = {};
  if (config.token) headers["x-sovereign-token"] = config.token;

  switch (sub) {
    case "stats": {
      const data = await fetch(`${config.endpoint}/_sovereign/chain/stats`, {
        headers, signal: AbortSignal.timeout(5000),
      }).then(r => r.json());

      console.log(`${c.cyan}${c.bold}Chain Statistics${c.reset}`);
      console.log(`  Blocks:    ${data.blocks}`);
      console.log(`  Events:    ${data.events}`);
      console.log(`  Anchored:  ${data.anchored}`);
      console.log(`  Critical:  ${data.critical}`);
      if (data.tip) {
        console.log(`\n${c.bold}Tip Block:${c.reset}`);
        console.log(`  Index:     #${data.tip.index}`);
        console.log(`  Hash:      ${c.dim}${data.tip.blockHash?.slice(0, 16)}...${c.reset}`);
        console.log(`  Merkle:    ${c.dim}${data.tip.merkleRoot?.slice(0, 16)}...${c.reset}`);
        console.log(`  Time:      ${new Date(data.tip.ts).toISOString()}`);
      }
      break;
    }
    case "verify": {
      console.log(`${c.dim}Verifying chain integrity...${c.reset}`);
      const data = await fetch(`${config.endpoint}/_sovereign/chain/verify`, {
        headers, signal: AbortSignal.timeout(30_000),
      }).then(r => r.json());

      if (data.valid) {
        console.log(`${c.green}${c.bold}Chain integrity verified${c.reset}`);
      } else {
        console.error(`${c.red}${c.bold}INTEGRITY FAILURE${c.reset}`);
        console.error(`  Failed at block: ${data.failedAt}`);
        console.error(`  Reason: ${data.reason}`);
        process.exit(1);
      }
      break;
    }
    default:
      console.error(`${c.red}Unknown chain command: ${sub}${c.reset}`);
      console.log("Usage: sovereignly chain [stats|verify]");
      process.exit(1);
  }
}
