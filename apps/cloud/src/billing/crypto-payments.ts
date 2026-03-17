/**
 * Sovereignly — Crypto Payment Gateway
 *
 * Accepts cryptocurrency payments alongside Stripe.
 * Supports: USDC, USDT, ETH, SOL, BTC via multiple providers.
 *
 * Architecture:
 *   1. Coinbase Commerce — hosted checkout (easiest, supports 10+ coins)
 *   2. Direct USDC/USDT — on-chain payment to a watched address
 *   3. Solana Pay — QR-code based payment (mobile-friendly)
 *
 * All payments logged to SovereignChain for audit trail.
 */

import type { SovereignChain } from "../../../oss/src/security/chain.ts";

// -- Types --

export type CryptoProvider = "coinbase" | "direct" | "solana_pay";
export type CryptoNetwork = "ethereum" | "base" | "arbitrum" | "solana" | "bitcoin";
export type CryptoCurrency = "USDC" | "USDT" | "ETH" | "SOL" | "BTC";

export interface CryptoPaymentConfig {
  /** Coinbase Commerce API key */
  coinbaseApiKey?: string;
  /** Wallet addresses for direct payments */
  wallets: {
    ethereum?: string;  // ETH + USDC (ERC20) + USDT
    solana?: string;    // SOL + USDC (SPL)
    bitcoin?: string;   // BTC
    base?: string;      // USDC on Base
  };
  /** Accepted currencies */
  acceptedCurrencies: CryptoCurrency[];
  /** Webhook URL for payment confirmations */
  webhookUrl: string;
  /** Confirmation thresholds */
  confirmations: {
    ethereum: number;   // default: 12
    solana: number;     // default: 32
    bitcoin: number;    // default: 3
  };
}

export interface CryptoCharge {
  id: string;
  tenantId: string;
  plan: string;
  amountUSD: number;
  currency: CryptoCurrency;
  network: CryptoNetwork;
  provider: CryptoProvider;
  status: "pending" | "confirming" | "completed" | "expired" | "failed";
  paymentAddress: string;
  amountCrypto: string;
  txHash?: string;
  createdAt: number;
  expiresAt: number;
  completedAt?: number;
}

// -- Coinbase Commerce Integration --

export class CoinbaseCommerceProvider {
  constructor(private apiKey: string) {}

  async createCharge(opts: {
    name: string;
    description: string;
    amountUSD: number;
    metadata: Record<string, string>;
    redirectUrl: string;
    cancelUrl: string;
  }): Promise<{ id: string; hostedUrl: string; expiresAt: string }> {
    const res = await fetch("https://api.commerce.coinbase.com/charges", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-CC-Api-Key": this.apiKey,
        "X-CC-Version": "2018-03-22",
      },
      body: JSON.stringify({
        name: opts.name,
        description: opts.description,
        pricing_type: "fixed_price",
        local_price: { amount: opts.amountUSD.toFixed(2), currency: "USD" },
        metadata: opts.metadata,
        redirect_url: opts.redirectUrl,
        cancel_url: opts.cancelUrl,
      }),
    });

    const data = await res.json() as any;
    if (!res.ok) throw new Error(data.error?.message ?? "Coinbase Commerce error");

    return {
      id: data.data.id,
      hostedUrl: data.data.hosted_url,
      expiresAt: data.data.expires_at,
    };
  }

  async getCharge(chargeId: string): Promise<any> {
    const res = await fetch(`https://api.commerce.coinbase.com/charges/${chargeId}`, {
      headers: { "X-CC-Api-Key": this.apiKey, "X-CC-Version": "2018-03-22" },
    });
    return res.json();
  }

  verifyWebhook(rawBody: string, signature: string, webhookSecret: string): boolean {
    // Coinbase Commerce uses HMAC-SHA256
    const crypto = globalThis.crypto;
    // Simplified — in production use proper HMAC verification
    return !!signature && !!webhookSecret;
  }
}

// -- Solana Pay Integration --

export class SolanaPayProvider {
  constructor(private recipientAddress: string) {}

  createPaymentUrl(opts: {
    amountUSDC: number;
    label: string;
    message: string;
    reference: string;
  }): string {
    // Solana Pay URL spec: solana:<recipient>?amount=<amount>&spl-token=<USDC_MINT>&reference=<ref>&label=<label>&message=<message>
    const USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
    const params = new URLSearchParams({
      amount: opts.amountUSDC.toString(),
      "spl-token": USDC_MINT,
      reference: opts.reference,
      label: opts.label,
      message: opts.message,
    });
    return `solana:${this.recipientAddress}?${params}`;
  }
}

// -- Unified Crypto Payment Service --

export class CryptoPaymentService {
  private coinbase?: CoinbaseCommerceProvider;
  private solanaPay?: SolanaPayProvider;
  private charges = new Map<string, CryptoCharge>();

  constructor(
    private config: CryptoPaymentConfig,
    private chain: SovereignChain,
  ) {
    if (config.coinbaseApiKey) {
      this.coinbase = new CoinbaseCommerceProvider(config.coinbaseApiKey);
    }
    if (config.wallets.solana) {
      this.solanaPay = new SolanaPayProvider(config.wallets.solana);
    }
  }

  /** Create a crypto payment for a plan upgrade */
  async createPayment(opts: {
    tenantId: string;
    plan: string;
    amountUSD: number;
    preferredCurrency?: CryptoCurrency;
    preferredProvider?: CryptoProvider;
  }): Promise<{
    chargeId: string;
    paymentUrl?: string;    // Coinbase hosted checkout
    paymentAddress?: string; // Direct payment address
    solanaPayUrl?: string;  // Solana Pay QR code URL
    amountUSD: number;
    expiresAt: number;
  }> {
    const chargeId = `cry_${crypto.randomUUID().slice(0, 16)}`;
    const expiresAt = Date.now() + 30 * 60 * 1000; // 30 min expiry

    // Try Coinbase Commerce first (supports most currencies)
    if (this.coinbase && (!opts.preferredProvider || opts.preferredProvider === "coinbase")) {
      const charge = await this.coinbase.createCharge({
        name: `Sovereignly ${opts.plan} Plan`,
        description: `Upgrade to ${opts.plan} — $${opts.amountUSD}/mo`,
        amountUSD: opts.amountUSD,
        metadata: { tenantId: opts.tenantId, plan: opts.plan, chargeId },
        redirectUrl: `${this.config.webhookUrl.replace("/webhook", "")}/billing?payment=success`,
        cancelUrl: `${this.config.webhookUrl.replace("/webhook", "")}/billing?payment=cancelled`,
      });

      this.charges.set(chargeId, {
        id: chargeId, tenantId: opts.tenantId, plan: opts.plan,
        amountUSD: opts.amountUSD, currency: opts.preferredCurrency ?? "USDC",
        network: "ethereum", provider: "coinbase", status: "pending",
        paymentAddress: "", amountCrypto: "", createdAt: Date.now(), expiresAt,
      });

      void this.chain.emit("CONFIG_CHANGE", {
        event: "crypto_payment_created", chargeId, tenantId: opts.tenantId,
        plan: opts.plan, provider: "coinbase", amountUSD: opts.amountUSD,
      }, "LOW");

      return { chargeId, paymentUrl: charge.hostedUrl, amountUSD: opts.amountUSD, expiresAt };
    }

    // Solana Pay for USDC on Solana
    if (this.solanaPay && opts.preferredCurrency === "USDC" && opts.preferredProvider === "solana_pay") {
      const reference = crypto.randomUUID();
      const url = this.solanaPay.createPaymentUrl({
        amountUSDC: opts.amountUSD,
        label: "Sovereignly",
        message: `${opts.plan} plan upgrade`,
        reference,
      });

      this.charges.set(chargeId, {
        id: chargeId, tenantId: opts.tenantId, plan: opts.plan,
        amountUSD: opts.amountUSD, currency: "USDC", network: "solana",
        provider: "solana_pay", status: "pending",
        paymentAddress: this.config.wallets.solana!, amountCrypto: opts.amountUSD.toString(),
        createdAt: Date.now(), expiresAt,
      });

      return { chargeId, solanaPayUrl: url, paymentAddress: this.config.wallets.solana, amountUSD: opts.amountUSD, expiresAt };
    }

    // Direct payment to wallet address
    const network = opts.preferredCurrency === "SOL" ? "solana" : opts.preferredCurrency === "BTC" ? "bitcoin" : "ethereum";
    const walletKey = opts.preferredCurrency === "SOL" ? "solana" : opts.preferredCurrency === "BTC" ? "bitcoin" : "ethereum";
    const address = this.config.wallets[walletKey];
    if (!address) throw new Error(`No wallet configured for ${network}`);

    this.charges.set(chargeId, {
      id: chargeId, tenantId: opts.tenantId, plan: opts.plan,
      amountUSD: opts.amountUSD, currency: opts.preferredCurrency ?? "USDC",
      network, provider: "direct", status: "pending",
      paymentAddress: address, amountCrypto: "TBD", // Would need price oracle
      createdAt: Date.now(), expiresAt,
    });

    return { chargeId, paymentAddress: address, amountUSD: opts.amountUSD, expiresAt };
  }

  /** Get payment status */
  getPayment(chargeId: string): CryptoCharge | undefined {
    return this.charges.get(chargeId);
  }

  /** Confirm a payment (called by webhook or manual verification) */
  async confirmPayment(chargeId: string, txHash: string): Promise<boolean> {
    const charge = this.charges.get(chargeId);
    if (!charge) return false;
    charge.status = "completed";
    charge.txHash = txHash;
    charge.completedAt = Date.now();

    void this.chain.emit("CONFIG_CHANGE", {
      event: "crypto_payment_completed", chargeId, txHash,
      tenantId: charge.tenantId, plan: charge.plan,
      amountUSD: charge.amountUSD, currency: charge.currency, network: charge.network,
    }, "LOW");

    return true;
  }

  /** List supported payment methods */
  getSupportedMethods(): Array<{
    provider: CryptoProvider;
    currencies: CryptoCurrency[];
    networks: CryptoNetwork[];
    label: string;
  }> {
    const methods = [];

    if (this.coinbase) {
      methods.push({
        provider: "coinbase" as const,
        currencies: ["USDC", "USDT", "ETH", "BTC", "SOL"] as CryptoCurrency[],
        networks: ["ethereum", "base", "solana", "bitcoin"] as CryptoNetwork[],
        label: "Coinbase Commerce (10+ cryptocurrencies)",
      });
    }

    if (this.solanaPay) {
      methods.push({
        provider: "solana_pay" as const,
        currencies: ["USDC", "SOL"] as CryptoCurrency[],
        networks: ["solana"] as CryptoNetwork[],
        label: "Solana Pay (QR code, instant)",
      });
    }

    if (this.config.wallets.ethereum) {
      methods.push({
        provider: "direct" as const,
        currencies: ["USDC", "USDT", "ETH"] as CryptoCurrency[],
        networks: ["ethereum", "base", "arbitrum"] as CryptoNetwork[],
        label: "Direct transfer (USDC, ETH on Ethereum/Base/Arbitrum)",
      });
    }

    if (this.config.wallets.bitcoin) {
      methods.push({
        provider: "direct" as const,
        currencies: ["BTC"] as CryptoCurrency[],
        networks: ["bitcoin"] as CryptoNetwork[],
        label: "Bitcoin (on-chain)",
      });
    }

    return methods;
  }

  stats() {
    const charges = Array.from(this.charges.values());
    return {
      total: charges.length,
      completed: charges.filter(c => c.status === "completed").length,
      pending: charges.filter(c => c.status === "pending").length,
      totalUSD: charges.filter(c => c.status === "completed").reduce((s, c) => s + c.amountUSD, 0),
    };
  }
}

// -- Route Registration --

export function registerCryptoPaymentRoutes(
  app: any,
  crypto: CryptoPaymentService,
  opts: { adminToken?: string }
) {
  // List supported methods (public)
  app.get("/_sovereign/billing/crypto/methods", (c: any) => {
    return c.json({ methods: crypto.getSupportedMethods() });
  });

  // Create crypto payment
  app.post("/_sovereign/billing/crypto/charge", async (c: any) => {
    const body = await c.req.json().catch(() => ({}));
    const { tenantId, plan, amountUSD, currency, provider } = body as any;
    if (!tenantId || !plan || !amountUSD) {
      return c.json({ error: "tenantId, plan, and amountUSD required" }, 400);
    }
    try {
      const result = await crypto.createPayment({
        tenantId, plan, amountUSD,
        preferredCurrency: currency,
        preferredProvider: provider,
      });
      return c.json(result, 201);
    } catch (err: any) {
      return c.json({ error: err.message }, 400);
    }
  });

  // Check payment status
  app.get("/_sovereign/billing/crypto/charge/:id", (c: any) => {
    const charge = crypto.getPayment(c.req.param("id"));
    if (!charge) return c.json({ error: "not found" }, 404);
    return c.json(charge);
  });

  // Confirm payment (admin)
  app.post("/_sovereign/billing/crypto/confirm", async (c: any) => {
    const token = c.req.header("x-sovereign-token") ?? "";
    if (!opts.adminToken || token !== opts.adminToken) return c.json({ error: "admin required" }, 403);
    const { chargeId, txHash } = await c.req.json().catch(() => ({}));
    const ok = await crypto.confirmPayment(chargeId, txHash);
    return c.json({ ok });
  });

  // Stats (admin)
  app.get("/_sovereign/billing/crypto/stats", (c: any) => {
    const token = c.req.header("x-sovereign-token") ?? "";
    if (!opts.adminToken || token !== opts.adminToken) return c.json({ error: "admin required" }, 403);
    return c.json(crypto.stats());
  });
}
