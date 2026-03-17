const c = { green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", dim: "\x1b[2m", reset: "\x1b[0m" };

export async function emit(config: { endpoint: string; token: string }, args: string[]) {
  const type = args[0];
  if (!type) {
    console.error(`${c.red}Usage: sovereignly emit <EVENT_TYPE> [payload_json]${c.reset}`);
    console.log(`${c.dim}Example: sovereignly emit CONFIG_CHANGE '{"key":"value"}'${c.reset}`);
    process.exit(1);
  }

  const payload = args[1] ? JSON.parse(args[1]) : {};

  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.token) headers["Authorization"] = `Bearer ${config.token}`;

  const res = await fetch(`${config.endpoint}/_sovereign/sdk/events`, {
    method: "POST",
    headers,
    body: JSON.stringify({ events: [{ type, payload, severity: "LOW" }] }),
    signal: AbortSignal.timeout(10_000),
  });

  const data = await res.json();
  if (res.ok) {
    console.log(`${c.green}Event emitted:${c.reset} ${type}`);
    console.log(`${c.dim}ID: ${data.results?.[0]?.eventId}${c.reset}`);
  } else {
    console.error(`${c.red}Failed: ${data.error ?? res.statusText}${c.reset}`);
    process.exit(1);
  }
}
