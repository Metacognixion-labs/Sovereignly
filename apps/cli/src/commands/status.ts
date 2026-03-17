const c = { bold: "\x1b[1m", dim: "\x1b[2m", green: "\x1b[32m", cyan: "\x1b[36m", red: "\x1b[31m", yellow: "\x1b[33m", reset: "\x1b[0m" };

export async function status(config: { endpoint: string; token: string }) {
  console.log(`${c.dim}Checking ${config.endpoint}...${c.reset}\n`);

  try {
    const health = await fetch(`${config.endpoint}/_sovereign/health`, {
      signal: AbortSignal.timeout(5000),
    }).then(r => r.json());

    const statusColor = health.ok ? c.green : c.red;
    console.log(`${c.bold}Health:${c.reset}    ${statusColor}${health.status}${c.reset}`);
    console.log(`${c.bold}Version:${c.reset}   ${health.version}`);
    console.log(`${c.bold}Runtime:${c.reset}   ${health.runtime} ${health.bunVersion}`);
    console.log(`${c.bold}Node:${c.reset}      ${health.node}`);
    console.log(`${c.bold}Uptime:${c.reset}    ${(health.uptime / 3600).toFixed(1)}h`);
    console.log(`${c.bold}Workers:${c.reset}   ${health.workers?.total ?? 0} (${health.workers?.busy ?? 0} busy)`);
    console.log();

    // Chain stats
    const headers: Record<string, string> = {};
    if (config.token) headers["x-sovereign-token"] = config.token;

    const stats = await fetch(`${config.endpoint}/_sovereign/chain/stats`, {
      headers, signal: AbortSignal.timeout(5000),
    }).then(r => r.json());

    console.log(`${c.cyan}${c.bold}Audit Chain:${c.reset}`);
    console.log(`  Blocks:    ${stats.blocks}`);
    console.log(`  Events:    ${stats.events}`);
    console.log(`  Anchored:  ${stats.anchored}`);
    console.log(`  Critical:  ${stats.critical}`);

    // Compliance
    const comp = await fetch(`${config.endpoint}/_sovereign/compliance/live`, {
      signal: AbortSignal.timeout(5000),
    }).then(r => r.json()).catch(() => null);

    if (comp?.score !== undefined) {
      const scoreColor = comp.score >= 80 ? c.green : comp.score >= 50 ? c.yellow : c.red;
      console.log(`\n${c.bold}Compliance:${c.reset} ${scoreColor}${comp.score}/100${c.reset} (${comp.summary.pass} pass, ${comp.summary.fail} fail, ${comp.summary.warn} warn)`);
    }
  } catch (err: any) {
    console.error(`${c.red}Cannot reach server at ${config.endpoint}${c.reset}`);
    console.error(`${c.dim}${err.message}${c.reset}`);
    process.exit(1);
  }
}
