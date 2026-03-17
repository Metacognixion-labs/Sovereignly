const c = { bold: "\x1b[1m", green: "\x1b[32m", red: "\x1b[31m", cyan: "\x1b[36m", magenta: "\x1b[35m", yellow: "\x1b[33m", dim: "\x1b[2m", reset: "\x1b[0m" };

export async function quantum(config: { endpoint: string; token: string }, args: string[]) {
  const sub = args[0] ?? "status";
  const headers: Record<string, string> = {};
  if (config.token) headers["x-sovereign-token"] = config.token;

  switch (sub) {
    case "status": {
      // Try admin endpoint first, fall back to public
      let data: any;
      const adminRes = await fetch(`${config.endpoint}/_sovereign/quantum/status`, {
        headers, signal: AbortSignal.timeout(5000),
      }).then(r => r.json()).catch(() => null);

      if (adminRes?.pqc) {
        data = adminRes;
      } else {
        data = await fetch(`${config.endpoint}/_sovereign/quantum/algorithms`, {
          signal: AbortSignal.timeout(5000),
        }).then(r => r.json()).catch(() => null);
        if (!data) { console.error(`${c.red}Cannot reach quantum endpoints${c.reset}`); process.exit(1); }
      }

      console.log(`\n${c.magenta}${c.bold}⚛  Post-Quantum Security Status${c.reset}\n`);
      console.log(`${"─".repeat(55)}`);

      // PQC Algorithms
      const alg = data.pqc?.algorithms;
      if (alg) {
        console.log(`${c.bold}Signatures:${c.reset}        ${c.magenta}${alg.signatures}${c.reset}`);
        console.log(`${c.bold}Hashing:${c.reset}           ${c.cyan}${alg.hashing}${c.reset}`);
        console.log(`${c.bold}Key Encapsulation:${c.reset} ${c.green}${alg.keyEncapsulation}${c.reset}`);
        console.log(`${c.bold}ZK-Ready:${c.reset}          ${c.yellow}${alg.zkReady}${c.reset}`);
      }

      // NIST
      if (data.pqc?.nistCompliance) {
        console.log(`\n${c.bold}NIST Compliance:${c.reset}   ${data.pqc.nistCompliance}`);
      }

      // Chain dual roots
      const chain = data.chain;
      if (chain) {
        console.log(`\n${c.bold}Dual Merkle Roots:${c.reset} ${chain.dualMerkleRoots ? `${c.green}✓ Active${c.reset}` : `${c.red}✗ Inactive${c.reset}`}`);
        console.log(`${c.bold}Blocks with PQ:${c.reset}    ${chain.blocksWithPQRoot}`);
        if (chain.latestSHA256Root) {
          console.log(`\n${c.bold}Latest SHA-256:${c.reset}    ${c.dim}${chain.latestSHA256Root.slice(0, 32)}...${c.reset}`);
        }
        if (chain.latestPQRoot) {
          console.log(`${c.bold}Latest SHA3-256:${c.reset}   ${c.magenta}${chain.latestPQRoot.slice(0, 32)}...${c.reset}`);
        }
      }

      // Quantum Cloud
      if (data.quantumCloud) {
        const qc = data.quantumCloud;
        console.log(`\n${c.magenta}${c.bold}Origin Quantum Cloud:${c.reset}`);
        console.log(`  Connected:     ${qc.connected ? `${c.green}✓ ${qc.provider}${c.reset}` : `${c.dim}Not connected (local PQC active)${c.reset}`}`);
        if (qc.connected) {
          console.log(`  Entropy Pool:  ${c.green}${qc.entropyPool} bytes${c.reset}`);
          console.log(`  Attestations:  ${c.magenta}${qc.attestations}${c.reset}`);
        }
      }

      // Poseidon
      if (data.poseidon) {
        console.log(`\n${c.bold}ZK Readiness:${c.reset}     ${data.poseidon.available ? `${c.green}✓${c.reset} Poseidon ${data.poseidon.field}` : `${c.red}✗${c.reset}`} ${data.poseidon.zkProvable ? "(zero-knowledge provable)" : ""}`);
      }

      console.log(`${"─".repeat(55)}\n`);
      break;
    }

    case "attest": {
      if (!config.token) { console.error(`${c.red}Admin token required. Run: sovereignly login${c.reset}`); process.exit(1); }

      console.log(`${c.dim}Triggering quantum attestation...${c.reset}`);

      // Get latest chain stats for merkle root
      const stats = await fetch(`${config.endpoint}/_sovereign/chain/stats`, {
        headers, signal: AbortSignal.timeout(5000),
      }).then(r => r.json());

      if (!stats?.tip?.merkleRoot) {
        console.error(`${c.red}No chain tip available${c.reset}`);
        process.exit(1);
      }

      const res = await fetch(`${config.endpoint}/_sovereign/quantum/attest`, {
        method: "POST",
        headers: { ...headers, "Content-Type": "application/json" },
        body: JSON.stringify({
          merkleRoot: stats.tip.merkleRoot,
          blockIndex: stats.tip.index,
          eventCount: stats.events,
        }),
        signal: AbortSignal.timeout(30_000),
      }).then(r => r.json());

      if (res.ok) {
        console.log(`${c.green}${c.bold}Quantum attestation complete${c.reset}`);
        console.log(`  Fingerprint: ${c.magenta}${res.fingerprint}${c.reset}`);
        console.log(`  Chip:        ${res.chip}`);
        console.log(`  Qubits:      ${res.qubits}`);
        console.log(`  Depth:       ${res.depth}`);
      } else {
        console.log(`${c.yellow}Quantum Cloud not available: ${res.error ?? "unknown"}${c.reset}`);
        console.log(`${c.dim}Post-quantum algorithms (ML-DSA-65, SHA3-256) remain active locally.${c.reset}`);
      }
      break;
    }

    default:
      console.error(`${c.red}Unknown quantum command: ${sub}${c.reset}`);
      console.log("Usage: sovereignly quantum [status|attest]");
      process.exit(1);
  }
}
