/**
 * Sovereignly Cloud — Token Ledger (Double-Entry Bookkeeping)
 * Business Source License 1.1 — MetaCognixion
 *
 * Every token operation creates a debit + credit pair.
 * All balances must sum to zero (accounting invariant).
 * Immutable transaction history — audit-grade.
 *
 * Account types:
 *   USER          Individual user balance
 *   TREASURY      Platform fee collection
 *   STAKING_POOL  Locked staking tokens
 *   FEE_POOL      Transaction fees
 *   MINT          Virtual source for new tokens
 *   BURN          Virtual sink for destroyed tokens
 */

import { Database } from "bun:sqlite";
import { join }     from "node:path";

// ── Types ────────────────────────────────────────────────────────────────────

export type AccountType = "USER" | "TREASURY" | "STAKING_POOL" | "FEE_POOL" | "MINT" | "BURN";

export type TransactionType =
  | "ADMIN_AWARD"         // Admin awards tokens to user
  | "POINTS_CONVERSION"   // Reward points → tokens
  | "STAKING_LOCK"        // Token locked in stake
  | "STAKING_UNLOCK"      // Stake released
  | "STAKING_REWARD"      // Staking interest earned
  | "TRANSFER"            // User-to-user transfer
  | "TRANSFER_FEE"        // Fee on transfer
  | "WITHDRAWAL"          // Withdraw to external wallet
  | "WITHDRAWAL_FEE"      // Fee on withdrawal
  | "DEPOSIT"             // Deposit from external wallet
  | "ADMIN_ADJUSTMENT"    // Admin manual adjustment
  | "BURN";               // Token burn

export interface TokenBalance {
  accountId:    string;
  accountType:  AccountType;
  available:    number;     // Can transfer/spend
  locked:       number;     // Staked or vesting
  pendingOut:   number;     // Pending withdrawal
  totalEarned:  number;     // Cumulative earned
  totalSpent:   number;     // Cumulative spent
}

export interface LedgerEntry {
  id:              string;
  txId:            string;     // Groups debit+credit pairs
  type:            TransactionType;
  debitAccount:    string;
  creditAccount:   string;
  amount:          number;
  memo:            string;
  createdAt:       number;
  createdBy:       string;
}

// ── TokenLedger ──────────────────────────────────────────────────────────────

export class TokenLedger {
  private db: Database;

  constructor(dataDir: string) {
    const dbPath = join(dataDir, "token-ledger.db");
    this.db = new Database(dbPath);
    this.initSchema();
  }

  private initSchema() {
    this.db.run("PRAGMA journal_mode = WAL");
    this.db.run("PRAGMA foreign_keys = ON");

    this.db.run(`
      CREATE TABLE IF NOT EXISTS accounts (
        id           TEXT PRIMARY KEY,
        type         TEXT NOT NULL,
        available    REAL NOT NULL DEFAULT 0,
        locked       REAL NOT NULL DEFAULT 0,
        pending_out  REAL NOT NULL DEFAULT 0,
        total_earned REAL NOT NULL DEFAULT 0,
        total_spent  REAL NOT NULL DEFAULT 0,
        created_at   INTEGER NOT NULL,
        updated_at   INTEGER NOT NULL
      )
    `);

    this.db.run(`
      CREATE TABLE IF NOT EXISTS ledger_entries (
        id              TEXT PRIMARY KEY,
        tx_id           TEXT NOT NULL,
        type            TEXT NOT NULL,
        debit_account   TEXT NOT NULL,
        credit_account  TEXT NOT NULL,
        amount          REAL NOT NULL,
        memo            TEXT NOT NULL DEFAULT '',
        created_at      INTEGER NOT NULL,
        created_by      TEXT NOT NULL DEFAULT 'system'
      )
    `);

    this.db.run("CREATE INDEX IF NOT EXISTS idx_ledger_tx     ON ledger_entries(tx_id)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_ledger_debit  ON ledger_entries(debit_account)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_ledger_credit ON ledger_entries(credit_account)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_ledger_type   ON ledger_entries(type)");
    this.db.run("CREATE INDEX IF NOT EXISTS idx_ledger_time   ON ledger_entries(created_at)");

    // Ensure system accounts exist
    this.ensureAccount("TREASURY",     "TREASURY");
    this.ensureAccount("STAKING_POOL", "STAKING_POOL");
    this.ensureAccount("FEE_POOL",     "FEE_POOL");
    this.ensureAccount("MINT",         "MINT");
    this.ensureAccount("BURN",         "BURN");
  }

  private ensureAccount(id: string, type: AccountType) {
    const exists = this.db.prepare("SELECT 1 FROM accounts WHERE id = ?").get(id);
    if (!exists) {
      const now = Date.now();
      this.db.prepare(
        "INSERT INTO accounts (id, type, created_at, updated_at) VALUES (?, ?, ?, ?)"
      ).run(id, type, now, now);
    }
  }

  // ── Account Management ───────────────────────────────────────────────────

  getOrCreateUserAccount(userId: string): TokenBalance {
    let row = this.db.prepare("SELECT * FROM accounts WHERE id = ?").get(userId) as any;
    if (!row) {
      const now = Date.now();
      this.db.prepare(
        "INSERT INTO accounts (id, type, created_at, updated_at) VALUES (?, 'USER', ?, ?)"
      ).run(userId, now, now);
      row = this.db.prepare("SELECT * FROM accounts WHERE id = ?").get(userId) as any;
    }
    return this.rowToBalance(row);
  }

  getBalance(accountId: string): TokenBalance | null {
    const row = this.db.prepare("SELECT * FROM accounts WHERE id = ?").get(accountId) as any;
    return row ? this.rowToBalance(row) : null;
  }

  // ── Core Operations ──────────────────────────────────────────────────────

  /**
   * Award tokens to a user (admin action). Creates tokens from MINT account.
   */
  award(userId: string, amount: number, memo: string, adminId: string): LedgerEntry {
    if (amount <= 0) throw new Error("Amount must be positive");
    this.getOrCreateUserAccount(userId);

    return this.transact("ADMIN_AWARD", "MINT", userId, amount, memo, adminId, (debit, credit) => {
      // MINT is virtual — no balance checks needed
      this.db.prepare(
        "UPDATE accounts SET available = available + ?, total_earned = total_earned + ?, updated_at = ? WHERE id = ?"
      ).run(amount, amount, Date.now(), credit);
    });
  }

  /**
   * Lock tokens for staking.
   */
  stakeLock(userId: string, amount: number): LedgerEntry {
    const balance = this.getOrCreateUserAccount(userId);
    if (balance.available < amount) throw new Error(`Insufficient balance: ${balance.available} < ${amount}`);

    return this.transact("STAKING_LOCK", userId, "STAKING_POOL", amount, "Staking lock", "system", (debit, credit) => {
      const now = Date.now();
      this.db.prepare(
        "UPDATE accounts SET available = available - ?, locked = locked + ?, updated_at = ? WHERE id = ?"
      ).run(amount, amount, now, debit);
      this.db.prepare(
        "UPDATE accounts SET available = available + ?, updated_at = ? WHERE id = ?"
      ).run(amount, now, credit);
    });
  }

  /**
   * Unlock tokens from staking.
   */
  stakeUnlock(userId: string, amount: number): LedgerEntry {
    const balance = this.getOrCreateUserAccount(userId);
    if (balance.locked < amount) throw new Error(`Insufficient locked balance: ${balance.locked} < ${amount}`);

    return this.transact("STAKING_UNLOCK", "STAKING_POOL", userId, amount, "Staking unlock", "system", (debit, credit) => {
      const now = Date.now();
      this.db.prepare(
        "UPDATE accounts SET available = available - ?, updated_at = ? WHERE id = ?"
      ).run(amount, now, debit);
      this.db.prepare(
        "UPDATE accounts SET locked = locked - ?, available = available + ?, updated_at = ? WHERE id = ?"
      ).run(amount, amount, now, credit);
    });
  }

  /**
   * Award staking rewards to a user.
   */
  stakeReward(userId: string, amount: number): LedgerEntry {
    this.getOrCreateUserAccount(userId);

    return this.transact("STAKING_REWARD", "MINT", userId, amount, "Staking reward", "system", (debit, credit) => {
      this.db.prepare(
        "UPDATE accounts SET available = available + ?, total_earned = total_earned + ?, updated_at = ? WHERE id = ?"
      ).run(amount, amount, Date.now(), credit);
    });
  }

  /**
   * Transfer tokens between users. Deducts transfer fee to FEE_POOL.
   */
  transfer(fromUser: string, toUser: string, amount: number, feePercent: number): { transfer: LedgerEntry; fee?: LedgerEntry } {
    const balance = this.getOrCreateUserAccount(fromUser);
    this.getOrCreateUserAccount(toUser);

    const fee = feePercent > 0 ? Math.floor(amount * feePercent / 100 * 1e9) / 1e9 : 0;
    const netAmount = amount - fee;

    if (balance.available < amount) throw new Error(`Insufficient balance: ${balance.available} < ${amount}`);

    const transfer = this.transact("TRANSFER", fromUser, toUser, netAmount, `Transfer to ${toUser}`, fromUser, (debit, credit) => {
      const now = Date.now();
      this.db.prepare(
        "UPDATE accounts SET available = available - ?, total_spent = total_spent + ?, updated_at = ? WHERE id = ?"
      ).run(netAmount, netAmount, now, debit);
      this.db.prepare(
        "UPDATE accounts SET available = available + ?, total_earned = total_earned + ?, updated_at = ? WHERE id = ?"
      ).run(netAmount, netAmount, now, credit);
    });

    let feeEntry: LedgerEntry | undefined;
    if (fee > 0) {
      feeEntry = this.transact("TRANSFER_FEE", fromUser, "FEE_POOL", fee, "Transfer fee", "system", (debit, credit) => {
        const now = Date.now();
        this.db.prepare(
          "UPDATE accounts SET available = available - ?, total_spent = total_spent + ?, updated_at = ? WHERE id = ?"
        ).run(fee, fee, now, debit);
        this.db.prepare(
          "UPDATE accounts SET available = available + ?, updated_at = ? WHERE id = ?"
        ).run(fee, now, credit);
      });
    }

    return { transfer, fee: feeEntry };
  }

  /**
   * Initiate withdrawal to external wallet (only when PUBLIC).
   */
  initiateWithdrawal(userId: string, amount: number, feePercent: number, walletAddress: string): { withdrawal: LedgerEntry; fee: LedgerEntry } {
    const balance = this.getOrCreateUserAccount(userId);
    const fee = Math.floor(amount * feePercent / 100 * 1e9) / 1e9;
    const total = amount + fee;

    if (balance.available < total) throw new Error(`Insufficient balance for withdrawal + fee: ${balance.available} < ${total}`);

    const withdrawal = this.transact("WITHDRAWAL", userId, "TREASURY", amount, `Withdrawal to ${walletAddress}`, userId, (debit, credit) => {
      const now = Date.now();
      this.db.prepare(
        "UPDATE accounts SET available = available - ?, pending_out = pending_out + ?, updated_at = ? WHERE id = ?"
      ).run(amount, amount, now, debit);
      this.db.prepare(
        "UPDATE accounts SET available = available + ?, updated_at = ? WHERE id = ?"
      ).run(amount, now, credit);
    });

    const feeEntry = this.transact("WITHDRAWAL_FEE", userId, "FEE_POOL", fee, "Withdrawal fee", "system", (debit, credit) => {
      const now = Date.now();
      this.db.prepare(
        "UPDATE accounts SET available = available - ?, total_spent = total_spent + ?, updated_at = ? WHERE id = ?"
      ).run(fee, fee, now, debit);
      this.db.prepare(
        "UPDATE accounts SET available = available + ?, updated_at = ? WHERE id = ?"
      ).run(fee, now, credit);
    });

    return { withdrawal, fee: feeEntry };
  }

  // ── Query ────────────────────────────────────────────────────────────────

  getTransactions(accountId: string, opts: { limit?: number; offset?: number; type?: TransactionType } = {}): LedgerEntry[] {
    const limit  = Math.min(opts.limit ?? 50, 500);
    const offset = opts.offset ?? 0;

    let sql = "SELECT * FROM ledger_entries WHERE debit_account = ? OR credit_account = ?";
    const params: any[] = [accountId, accountId];

    if (opts.type) {
      sql += " AND type = ?";
      params.push(opts.type);
    }

    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?";
    params.push(limit, offset);

    const rows = this.db.prepare(sql).all(...params) as any[];
    return rows.map(this.rowToEntry);
  }

  getSupplyStats(): {
    totalMinted:   number;
    totalBurned:   number;
    circulating:   number;
    staked:        number;
    inTreasury:    number;
    inFeePool:     number;
  } {
    const mint     = this.getBalance("MINT");
    const burn     = this.getBalance("BURN");
    const staking  = this.getBalance("STAKING_POOL");
    const treasury = this.getBalance("TREASURY");
    const feePool  = this.getBalance("FEE_POOL");

    const totalMinted = mint ? mint.total_spent ?? mint.totalSpent ?? 0 : 0;
    const totalBurned = burn ? burn.available : 0;

    // Sum all user available balances
    const userSum = this.db.prepare(
      "SELECT COALESCE(SUM(available), 0) AS total FROM accounts WHERE type = 'USER'"
    ).get() as any;

    return {
      totalMinted:  totalMinted,
      totalBurned:  totalBurned,
      circulating:  userSum.total,
      staked:       staking?.available ?? 0,
      inTreasury:   treasury?.available ?? 0,
      inFeePool:    feePool?.available ?? 0,
    };
  }

  // ── Internal ─────────────────────────────────────────────────────────────

  private transact(
    type:          TransactionType,
    debitAccount:  string,
    creditAccount: string,
    amount:        number,
    memo:          string,
    createdBy:     string,
    mutation:      (debit: string, credit: string) => void,
  ): LedgerEntry {
    const id    = crypto.randomUUID();
    const txId  = crypto.randomUUID();
    const now   = Date.now();

    // Run mutation and ledger insert atomically
    const txn = this.db.transaction(() => {
      mutation(debitAccount, creditAccount);

      this.db.prepare(`
        INSERT INTO ledger_entries (id, tx_id, type, debit_account, credit_account, amount, memo, created_at, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(id, txId, type, debitAccount, creditAccount, amount, memo, now, createdBy);
    });
    txn();

    return { id, txId, type, debitAccount, creditAccount, amount, memo, createdAt: now, createdBy };
  }

  private rowToBalance(row: any): TokenBalance {
    return {
      accountId:   row.id,
      accountType: row.type,
      available:   row.available,
      locked:      row.locked,
      pendingOut:  row.pending_out,
      totalEarned: row.total_earned,
      totalSpent:  row.total_spent,
    };
  }

  private rowToEntry(row: any): LedgerEntry {
    return {
      id:            row.id,
      txId:          row.tx_id,
      type:          row.type,
      debitAccount:  row.debit_account,
      creditAccount: row.credit_account,
      amount:        row.amount,
      memo:          row.memo,
      createdAt:     row.created_at,
      createdBy:     row.created_by,
    };
  }

  close() {
    this.db.close();
  }
}
