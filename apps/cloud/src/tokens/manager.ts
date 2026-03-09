/**
 * Sovereignly Cloud — Token Manager
 * Business Source License 1.1 — MetaCognixion
 *
 * Central orchestrator for the token system.
 * Enforces feature gates, manages config persistence,
 * and bridges the ledger with the audit chain.
 */

import { Database }        from "bun:sqlite";
import { join }            from "node:path";
import type { SovereignChain } from "../../../oss/src/security/chain.ts";

import {
  type TokenSystemConfig,
  type TokenSystemStatus,
  type TokenFeatureGates,
  DEFAULT_TOKEN_CONFIG,
  isValidTransition,
  getFeatureGates,
} from "./config.ts";

import { TokenLedger, type TokenBalance, type LedgerEntry, type TransactionType } from "./ledger.ts";

// ── TokenManager ─────────────────────────────────────────────────────────────

export class TokenManager {
  private configDb: Database;
  private ledger:   TokenLedger;
  private chain:    SovereignChain | null;
  private config:   TokenSystemConfig;

  constructor(opts: {
    dataDir: string;
    chain?:  SovereignChain;
  }) {
    this.chain = opts.chain ?? null;

    // Config persistence
    this.configDb = new Database(join(opts.dataDir, "token-config.db"));
    this.configDb.run("PRAGMA journal_mode = WAL");
    this.configDb.run(`
      CREATE TABLE IF NOT EXISTS token_config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `);

    // Load or initialize config
    this.config = this.loadConfig();

    // Ledger
    this.ledger = new TokenLedger(opts.dataDir);
  }

  // ── Config Management ──────────────────────────────────────────────────

  getConfig(): TokenSystemConfig {
    return { ...this.config };
  }

  getFeatureGates(): TokenFeatureGates {
    return getFeatureGates(this.config);
  }

  getStatus(): TokenSystemStatus {
    return this.config.status;
  }

  /**
   * Transition the token system status (CLOSED → PRE_PUBLIC → PUBLIC, or rollback).
   * Only valid transitions are allowed.
   */
  async setStatus(newStatus: TokenSystemStatus, adminId: string): Promise<{
    ok: boolean;
    from: TokenSystemStatus;
    to: TokenSystemStatus;
    error?: string;
  }> {
    const from = this.config.status;

    if (from === newStatus) {
      return { ok: false, from, to: newStatus, error: `Already in ${newStatus} status` };
    }

    if (!isValidTransition(from, newStatus)) {
      return {
        ok: false, from, to: newStatus,
        error: `Invalid transition: ${from} → ${newStatus}. Valid: ${from} → [${getValidNextStates(from).join(", ")}]`,
      };
    }

    this.config.status    = newStatus;
    this.config.updatedAt = Date.now();
    this.config.updatedBy = adminId;
    this.saveConfig();

    // Audit log
    await this.chain?.emit("CONFIG_CHANGE", {
      event:      "token_system_status_changed",
      from,
      to:         newStatus,
      adminId,
      gates:      getFeatureGates(this.config),
    }, "HIGH");

    console.log(`[TokenManager] Status transition: ${from} → ${newStatus} by ${adminId}`);

    return { ok: true, from, to: newStatus };
  }

  /**
   * Update token system configuration parameters.
   */
  async updateConfig(
    updates: Partial<Omit<TokenSystemConfig, "status" | "updatedAt" | "updatedBy">>,
    adminId: string,
  ): Promise<TokenSystemConfig> {
    const prev = { ...this.config };

    // Apply updates (whitelist of mutable fields)
    const mutableKeys: (keyof typeof updates)[] = [
      "isFrozen", "pointsToTokenRate", "autoConvert",
      "stakingEnabled", "minStakeDays", "baseStakingApy",
      "dailyWithdrawLimit", "weeklyWithdrawLimit", "withdrawalFeePercent",
      "minWithdrawal", "maxWithdrawal", "transferFeePercent",
      "governanceEnabled", "governanceThreshold",
      "tokenName", "tokenSymbol", "tokenDecimals",
    ];

    for (const key of mutableKeys) {
      if (updates[key] !== undefined) {
        (this.config as any)[key] = updates[key];
      }
    }

    this.config.updatedAt = Date.now();
    this.config.updatedBy = adminId;
    this.saveConfig();

    // Audit log
    await this.chain?.emit("CONFIG_CHANGE", {
      event:   "token_system_config_updated",
      changes: Object.fromEntries(
        mutableKeys
          .filter(k => updates[k] !== undefined && updates[k] !== (prev as any)[k])
          .map(k => [k, { from: (prev as any)[k], to: updates[k] }])
      ),
      adminId,
    }, "MEDIUM");

    return this.getConfig();
  }

  /**
   * Emergency freeze/unfreeze — halts ALL token operations instantly.
   */
  async setFrozen(frozen: boolean, adminId: string, reason: string): Promise<void> {
    this.config.isFrozen  = frozen;
    this.config.updatedAt = Date.now();
    this.config.updatedBy = adminId;
    this.saveConfig();

    await this.chain?.emit("CONFIG_CHANGE", {
      event:  frozen ? "token_system_frozen" : "token_system_unfrozen",
      reason,
      adminId,
      gates:  getFeatureGates(this.config),
    }, "CRITICAL");

    console.log(`[TokenManager] ${frozen ? "FROZEN" : "UNFROZEN"} by ${adminId}: ${reason}`);
  }

  // ── Token Operations (Gate-Enforced) ───────────────────────────────────

  /**
   * Award tokens to a user (admin action).
   * Allowed in: CLOSED, PRE_PUBLIC, PUBLIC (unless frozen).
   */
  async award(userId: string, amount: number, memo: string, adminId: string): Promise<LedgerEntry> {
    const gates = this.getFeatureGates();
    if (!gates.canAward) throw new Error("Token awards are currently disabled");

    const entry = this.ledger.award(userId, amount, memo, adminId);

    await this.chain?.emit("CONFIG_CHANGE", {
      event: "token_awarded", userId, amount, memo, adminId,
    }, "LOW");

    return entry;
  }

  /**
   * Transfer tokens between users.
   * Allowed in: PRE_PUBLIC, PUBLIC (unless frozen).
   */
  async transfer(fromUser: string, toUser: string, amount: number): Promise<{ transfer: LedgerEntry; fee?: LedgerEntry }> {
    const gates = this.getFeatureGates();
    if (!gates.canTransfer) {
      throw new Error(
        this.config.status === "CLOSED"
          ? "Transfers are disabled in CLOSED mode. Admin must advance to PRE_PUBLIC or PUBLIC."
          : "Transfers are currently frozen"
      );
    }

    return this.ledger.transfer(fromUser, toUser, amount, this.config.transferFeePercent);
  }

  /**
   * Stake tokens.
   * Allowed in: CLOSED, PRE_PUBLIC, PUBLIC (if staking enabled and not frozen).
   */
  async stake(userId: string, amount: number): Promise<LedgerEntry> {
    const gates = this.getFeatureGates();
    if (!gates.canStake) throw new Error("Staking is currently disabled");

    return this.ledger.stakeLock(userId, amount);
  }

  /**
   * Unstake tokens.
   */
  async unstake(userId: string, amount: number): Promise<LedgerEntry> {
    const gates = this.getFeatureGates();
    if (!gates.canStake) throw new Error("Staking operations are currently disabled");

    return this.ledger.stakeUnlock(userId, amount);
  }

  /**
   * Initiate withdrawal to external wallet.
   * ONLY allowed in PUBLIC mode (unless frozen).
   */
  async withdraw(userId: string, amount: number, walletAddress: string): Promise<{ withdrawal: LedgerEntry; fee: LedgerEntry }> {
    const gates = this.getFeatureGates();
    if (!gates.canWithdraw) {
      throw new Error(
        this.config.status !== "PUBLIC"
          ? `Withdrawals are only available when the token system is in PUBLIC mode (current: ${this.config.status})`
          : "Withdrawals are currently frozen"
      );
    }

    // Enforce withdrawal limits
    if (amount < this.config.minWithdrawal) {
      throw new Error(`Minimum withdrawal: ${this.config.minWithdrawal} ${this.config.tokenSymbol}`);
    }
    if (amount > this.config.maxWithdrawal) {
      throw new Error(`Maximum withdrawal: ${this.config.maxWithdrawal} ${this.config.tokenSymbol}`);
    }

    // Check daily/weekly limits
    const recent = this.ledger.getTransactions(userId, { type: "WITHDRAWAL", limit: 500 });
    const now    = Date.now();
    const dayAgo = now - 86_400_000;
    const weekAgo = now - 604_800_000;

    const dailyTotal  = recent.filter(e => e.createdAt > dayAgo).reduce((s, e) => s + e.amount, 0);
    const weeklyTotal = recent.filter(e => e.createdAt > weekAgo).reduce((s, e) => s + e.amount, 0);

    if (dailyTotal + amount > this.config.dailyWithdrawLimit) {
      throw new Error(`Daily withdrawal limit exceeded (${dailyTotal + amount} > ${this.config.dailyWithdrawLimit})`);
    }
    if (weeklyTotal + amount > this.config.weeklyWithdrawLimit) {
      throw new Error(`Weekly withdrawal limit exceeded (${weeklyTotal + amount} > ${this.config.weeklyWithdrawLimit})`);
    }

    const result = this.ledger.initiateWithdrawal(userId, amount, this.config.withdrawalFeePercent, walletAddress);

    await this.chain?.emit("CONFIG_CHANGE", {
      event: "token_withdrawal_initiated",
      userId, amount, walletAddress, fee: result.fee.amount,
    }, "HIGH");

    return result;
  }

  // ── Query ──────────────────────────────────────────────────────────────

  getBalance(userId: string): TokenBalance {
    return this.ledger.getOrCreateUserAccount(userId);
  }

  getTransactions(accountId: string, opts?: { limit?: number; offset?: number; type?: TransactionType }): LedgerEntry[] {
    return this.ledger.getTransactions(accountId, opts);
  }

  getSupplyStats() {
    return this.ledger.getSupplyStats();
  }

  // ── Config Persistence ─────────────────────────────────────────────────

  private loadConfig(): TokenSystemConfig {
    const row = this.configDb.prepare("SELECT value FROM token_config WHERE key = 'config'").get() as any;
    if (row) {
      try {
        return { ...DEFAULT_TOKEN_CONFIG, ...JSON.parse(row.value) };
      } catch {
        return { ...DEFAULT_TOKEN_CONFIG };
      }
    }
    // First run — save defaults
    this.configDb.prepare(
      "INSERT INTO token_config (key, value) VALUES ('config', ?)"
    ).run(JSON.stringify(DEFAULT_TOKEN_CONFIG));
    return { ...DEFAULT_TOKEN_CONFIG };
  }

  private saveConfig() {
    this.configDb.prepare(
      "INSERT OR REPLACE INTO token_config (key, value) VALUES ('config', ?)"
    ).run(JSON.stringify(this.config));
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────

  close() {
    this.ledger.close();
    this.configDb.close();
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function getValidNextStates(from: TokenSystemStatus): TokenSystemStatus[] {
  const { VALID_TRANSITIONS } = require("./config.ts");
  return VALID_TRANSITIONS[from] ?? [];
}
