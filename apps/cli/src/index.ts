#!/usr/bin/env bun
/**
 * Sovereignly CLI
 *
 * Usage:
 *   sovereignly init          Initialize a new project
 *   sovereignly dev           Start the dev server
 *   sovereignly status        Check server health and chain stats
 *   sovereignly emit <type>   Emit an audit event
 *   sovereignly chain stats   Show chain statistics
 *   sovereignly chain verify  Verify chain integrity
 *   sovereignly compliance    Generate compliance report
 *   sovereignly deploy        Deploy to Fly.io
 *   sovereignly login         Authenticate and store token
 *   sovereignly version       Show version
 */

import { status } from "./commands/status.ts";
import { emit } from "./commands/emit.ts";
import { chain } from "./commands/chain.ts";
import { compliance } from "./commands/compliance.ts";
import { init } from "./commands/init.ts";
import { login } from "./commands/login.ts";
import { quantum } from "./commands/quantum.ts";

const VERSION = "4.0.0";
const args = process.argv.slice(2);
const command = args[0];

// Load config
const CONFIG_PATH = `${process.env.HOME ?? process.env.USERPROFILE}/.sovereignly/config.json`;
let config: { endpoint: string; token: string } = { endpoint: "http://localhost:8787", token: "" };
try {
  config = JSON.parse(await Bun.file(CONFIG_PATH).text());
} catch {}

const c = { bold: "\x1b[1m", dim: "\x1b[2m", green: "\x1b[32m", cyan: "\x1b[36m", red: "\x1b[31m", yellow: "\x1b[33m", reset: "\x1b[0m" };

function help() {
  console.log(`
${c.cyan}${c.bold}⬡ Sovereignly CLI${c.reset} ${c.dim}v${VERSION}${c.reset}

${c.bold}Usage:${c.reset}
  sovereignly <command> [options]

${c.bold}Commands:${c.reset}
  ${c.green}init${c.reset}              Initialize project (generate .env, create data dir)
  ${c.green}dev${c.reset}               Start the development server
  ${c.green}status${c.reset}            Check server health and chain stats
  ${c.green}emit${c.reset} <type>       Emit an audit event (e.g. sovereignly emit CONFIG_CHANGE)
  ${c.green}chain${c.reset} stats       Show chain statistics
  ${c.green}chain${c.reset} verify      Verify chain integrity
  ${c.green}compliance${c.reset} [std]  Generate compliance report (soc2, iso27001, nist)
  ${c.green}quantum${c.reset} status     Post-quantum cryptography status
  ${c.green}quantum${c.reset} attest     Trigger quantum attestation of chain
  ${c.green}deploy${c.reset}            Deploy to Fly.io
  ${c.green}login${c.reset}             Authenticate and save credentials
  ${c.green}version${c.reset}           Show version

${c.bold}Config:${c.reset} ${c.dim}~/.sovereignly/config.json${c.reset}
  `);
}

async function run() {
  switch (command) {
    case "init":
      await init();
      break;
    case "dev":
      console.log(`${c.cyan}Starting Sovereignly dev server...${c.reset}`);
      Bun.spawnSync(["bun", "run", "dev"], { stdio: ["inherit", "inherit", "inherit"] });
      break;
    case "status":
      await status(config);
      break;
    case "emit":
      await emit(config, args.slice(1));
      break;
    case "chain":
      await chain(config, args.slice(1));
      break;
    case "compliance":
      await compliance(config, args[1]);
      break;
    case "quantum":
      await quantum(config, args.slice(1));
      break;
    case "deploy":
      console.log(`${c.cyan}Deploying to Fly.io...${c.reset}`);
      Bun.spawnSync(["flyctl", "deploy", "--remote-only"], { stdio: ["inherit", "inherit", "inherit"] });
      break;
    case "login":
      await login(CONFIG_PATH);
      break;
    case "version":
    case "-v":
    case "--version":
      console.log(`sovereignly v${VERSION}`);
      break;
    case "help":
    case "-h":
    case "--help":
    case undefined:
      help();
      break;
    default:
      console.error(`${c.red}Unknown command: ${command}${c.reset}`);
      help();
      process.exit(1);
  }
}

run().catch(err => {
  console.error(`${c.red}Error: ${err.message}${c.reset}`);
  process.exit(1);
});
