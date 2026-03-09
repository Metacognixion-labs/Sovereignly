/**
 * Sovereignly Cloud — Token System Configuration
 * Business Source License 1.1 — MetaCognixion
 *
 * Three-state visibility system for platform tokens:
 *   CLOSED      → Internal only. Tokens awarded/staked, no withdrawals.
 *   PRE_PUBLIC  → Limited external access. Controlled testing phase.
 *   PUBLIC      → Full external access. Withdrawals & transfers enabled.
 *
 * Admin controls all transitions from the dashboard.
 * Modeled after Académie Studio's proven $ACAD token architecture.
 */

// ── Types ────────────────────────────────────────────────────────────────────

export type TokenSystemStatus = "CLOSED" | "PRE_PUBLIC" | "PUBLIC";

export interface TokenSystemConfig {
  status:                TokenSystemStatus;
  isFrozen:              boolean;     // Emergency freeze — halts ALL token operations

  // Conversion
  pointsToTokenRate:     number;      // e.g. 100 points = 1 token
  autoConvert:           boolean;     // Auto-convert points to tokens on earning

  // Staking
  stakingEnabled:        boolean;
  minStakeDays:          number;
  baseStakingApy:        number;      // percentage

  // Withdrawal (only available when PUBLIC)
  dailyWithdrawLimit:    number;
  weeklyWithdrawLimit:   number;
  withdrawalFeePercent:  number;
  minWithdrawal:         number;
  maxWithdrawal:         number;

  // Transfer fees
  transferFeePercent:    number;      // e.g. 1.0 = 1%

  // Governance
  governanceEnabled:     boolean;
  governanceThreshold:   number;      // min tokens to vote

  // Metadata
  tokenName:             string;
  tokenSymbol:           string;
  tokenDecimals:         number;
  updatedAt:             number;
  updatedBy:             string;
}

// ── Defaults ─────────────────────────────────────────────────────────────────

export const DEFAULT_TOKEN_CONFIG: TokenSystemConfig = {
  status:                "CLOSED",
  isFrozen:              false,

  pointsToTokenRate:     100,
  autoConvert:           false,

  stakingEnabled:        true,
  minStakeDays:          30,
  baseStakingApy:        5.0,

  dailyWithdrawLimit:    1_000,
  weeklyWithdrawLimit:   5_000,
  withdrawalFeePercent:  2.5,
  minWithdrawal:         10,
  maxWithdrawal:         50_000,

  transferFeePercent:    1.0,

  governanceEnabled:     false,
  governanceThreshold:   1_000,

  tokenName:             "Sovereignly Token",
  tokenSymbol:           "SVRN",
  tokenDecimals:         9,
  updatedAt:             Date.now(),
  updatedBy:             "system",
};

// ── State Machine ────────────────────────────────────────────────────────────

/**
 * Valid status transitions. Admin can advance step by step or rollback.
 *
 *   CLOSED ──► PRE_PUBLIC ──► PUBLIC
 *      ◄──────────────────────┘ (rollback)
 *      ◄────────┘               (rollback)
 */
export const VALID_TRANSITIONS: Record<TokenSystemStatus, TokenSystemStatus[]> = {
  CLOSED:     ["PRE_PUBLIC"],
  PRE_PUBLIC: ["PUBLIC", "CLOSED"],
  PUBLIC:     ["CLOSED"],
};

export function isValidTransition(from: TokenSystemStatus, to: TokenSystemStatus): boolean {
  return VALID_TRANSITIONS[from]?.includes(to) ?? false;
}

// ── Feature Gates ────────────────────────────────────────────────────────────

export interface TokenFeatureGates {
  canAward:          boolean;   // Admin can award tokens internally
  canStake:          boolean;   // Users can stake tokens
  canTransfer:       boolean;   // Internal user-to-user transfers
  canWithdraw:       boolean;   // Withdraw to external wallet
  canDeposit:        boolean;   // Deposit from external wallet
  canConvertPoints:  boolean;   // Convert reward points to tokens
}

/**
 * Compute feature gates based on current config.
 * This is the single source of truth for what's allowed.
 */
export function getFeatureGates(config: TokenSystemConfig): TokenFeatureGates {
  if (config.isFrozen) {
    return {
      canAward:         false,
      canStake:         false,
      canTransfer:      false,
      canWithdraw:      false,
      canDeposit:       false,
      canConvertPoints: false,
    };
  }

  switch (config.status) {
    case "CLOSED":
      return {
        canAward:         true,
        canStake:         config.stakingEnabled,
        canTransfer:      false,
        canWithdraw:      false,
        canDeposit:       false,
        canConvertPoints: true,
      };

    case "PRE_PUBLIC":
      return {
        canAward:         true,
        canStake:         config.stakingEnabled,
        canTransfer:      true,    // Internal transfers enabled for testing
        canWithdraw:      false,   // Not yet
        canDeposit:       false,
        canConvertPoints: true,
      };

    case "PUBLIC":
      return {
        canAward:         true,
        canStake:         config.stakingEnabled,
        canTransfer:      true,
        canWithdraw:      true,
        canDeposit:       true,
        canConvertPoints: true,
      };
  }
}
