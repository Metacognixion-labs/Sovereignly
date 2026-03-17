const c = { bold: "\x1b[1m", green: "\x1b[32m", red: "\x1b[31m", yellow: "\x1b[33m", cyan: "\x1b[36m", dim: "\x1b[2m", reset: "\x1b[0m" };

export async function compliance(config: { endpoint: string; token: string }, standard?: string) {
  const data = await fetch(`${config.endpoint}/_sovereign/compliance/live`, {
    signal: AbortSignal.timeout(10_000),
  }).then(r => r.json());

  const scoreColor = data.score >= 80 ? c.green : data.score >= 50 ? c.yellow : c.red;

  console.log(`\n${c.bold}Compliance Report${c.reset}`);
  console.log(`${"─".repeat(50)}`);
  console.log(`  Score:       ${scoreColor}${c.bold}${data.score}/100${c.reset}`);
  console.log(`  Evaluations: ${data.evaluations}`);
  console.log(`  Pass:        ${c.green}${data.summary.pass}${c.reset}`);
  console.log(`  Warn:        ${c.yellow}${data.summary.warn}${c.reset}`);
  console.log(`  Fail:        ${c.red}${data.summary.fail}${c.reset}`);
  console.log(`${"─".repeat(50)}`);

  const controls = standard
    ? data.controls.filter((ctrl: any) => ctrl.framework.toLowerCase() === standard.toLowerCase())
    : data.controls;

  for (const ctrl of controls) {
    const statusIcon = ctrl.status === "pass" ? `${c.green}✓${c.reset}` :
      ctrl.status === "warn" ? `${c.yellow}!${c.reset}` : `${c.red}✗${c.reset}`;
    const scoreCol = ctrl.score >= 80 ? c.green : ctrl.score >= 50 ? c.yellow : c.red;

    console.log(`  ${statusIcon} ${c.bold}${ctrl.name}${c.reset} ${c.dim}(${ctrl.framework} ${ctrl.reference})${c.reset}`);
    console.log(`    Score: ${scoreCol}${ctrl.score}${c.reset}  ${c.dim}${ctrl.evidence}${c.reset}`);
  }
  console.log();
}
