import { mkdir } from "node:fs/promises";
import { dirname } from "node:path";

const c = { bold: "\x1b[1m", green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", dim: "\x1b[2m", reset: "\x1b[0m" };

export async function login(configPath: string) {
  console.log(`\n${c.cyan}${c.bold}⬡ Sovereignly Login${c.reset}\n`);

  const endpoint = prompt(`Server URL ${c.dim}(http://localhost:8787)${c.reset}: `) || "http://localhost:8787";
  const token = prompt(`Admin token: `) || "";

  if (!token) {
    console.error(`${c.red}Token is required${c.reset}`);
    process.exit(1);
  }

  // Verify connection
  try {
    const res = await fetch(`${endpoint}/_sovereign/health`, {
      headers: { "x-sovereign-token": token },
      signal: AbortSignal.timeout(5000),
    });
    const data = await res.json() as any;

    if (res.ok) {
      console.log(`${c.green}✓${c.reset} Connected to ${endpoint} (${data.status})`);
    } else {
      console.log(`${c.red}✗${c.reset} Server returned ${res.status}`);
    }
  } catch {
    console.log(`${c.red}✗${c.reset} Cannot reach ${endpoint}`);
    const proceed = prompt("Save anyway? (y/n): ");
    if (proceed !== "y") process.exit(1);
  }

  // Save config
  await mkdir(dirname(configPath), { recursive: true });
  await Bun.write(configPath, JSON.stringify({ endpoint, token }, null, 2));
  console.log(`${c.green}✓${c.reset} Credentials saved to ${c.dim}${configPath}${c.reset}\n`);
}
