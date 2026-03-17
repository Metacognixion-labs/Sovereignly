"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {
  Globe, Shield, Link2, Atom, ShieldCheck, Zap, Lock, Eye,
  ArrowRight, Check, ChevronDown, Terminal, Blocks, Database,
  GitBranch, Cpu, Leaf, Code2, ExternalLink,
} from "lucide-react";

// Animated counter
function Counter({ end, suffix = "" }: { end: number; suffix?: string }) {
  const [val, setVal] = useState(0);
  useEffect(() => {
    const start = performance.now();
    const dur = 1500;
    function tick(now: number) {
      const p = Math.min((now - start) / dur, 1);
      setVal(Math.round(end * (1 - Math.pow(1 - p, 3))));
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }, [end]);
  return <>{val}{suffix}</>;
}

// Pricing
const PLANS = [
  { name: "Free", price: { mo: 0, yr: 0 }, desc: "Get started", cta: "Start Free", featured: false,
    features: ["10K events/mo", "3 functions", "0.5 GB storage", "EAS/Base anchoring", "Community support"] },
  { name: "Starter", price: { mo: 49, yr: 39 }, desc: "For growing teams", cta: "Start Trial", featured: false,
    features: ["1M events/mo", "20 functions", "20 GB storage", "EAS + Arbitrum anchoring", "SOC2 reports", "3 team seats", "Email support"] },
  { name: "Growth", price: { mo: 149, yr: 119 }, desc: "Scale with confidence", cta: "Start Trial", featured: true,
    features: ["10M events/mo", "100 functions", "100 GB storage", "Full omnichain (5 chains)", "SOC2 + ISO27001", "Quantum attestation", "10 team seats", "Priority support"] },
  { name: "Enterprise", price: { mo: -1, yr: -1 }, desc: "Custom everything", cta: "Contact Sales", featured: false,
    features: ["Unlimited events", "Unlimited functions", "Unlimited storage", "All chains + Bitcoin", "Custom compliance", "Confidential compute (TEE)", "Dedicated infrastructure", "24/7 SLA"] },
];

const FEATURES = [
  { icon: Link2, title: "Cryptographic Audit Chain", desc: "Every execution Ed25519-signed, Merkle-batched, and immutable. Full non-repudiation for every API call, deploy, and config change.", color: "#42A5F5" },
  { icon: Globe, title: "Omnichain Attestation", desc: "Merkle roots sealed to EAS/Base, Arbitrum, Solana, Irys, and Bitcoin. Independent verification on 5+ public blockchains for $0.63/yr.", color: "#4CAF50" },
  { icon: Atom, title: "Post-Quantum Security", desc: "Hybrid Ed25519 + ML-DSA-65 signatures. SHA-256 + SHA3-256 dual Merkle roots. ML-KEM-768 encryption. NIST FIPS 203/204 compliant.", color: "#AB47BC" },
  { icon: ShieldCheck, title: "Compliance as Code", desc: "SOC2, ISO 27001, HIPAA, GDPR reports auto-generated from chain evidence. Live compliance scoring. Verifiable Credentials (W3C).", color: "#4CAF50" },
  { icon: Zap, title: "Quantum Cloud", desc: "Origin Wukong 72-qubit quantum processor integration. Quantum random numbers. Quantum-attested Merkle roots. Hardware entropy.", color: "#AB47BC" },
  { icon: Lock, title: "Zero-Trust by Default", desc: "Anomaly detection, RBAC, secret scanning, input shielding, SSRF guard, intent guard. Every security event logged to chain.", color: "#EF5350" },
];

const FAQS = [
  { q: "How is this different from Vercel or Railway?", a: "Vercel and Railway deploy your code. Sovereignly deploys your code AND cryptographically proves every execution happened correctly, anchors proof to 5 public blockchains, and auto-generates compliance reports. Same deploy experience, fundamentally more trust." },
  { q: "What does 'omnichain attestation' mean?", a: "Every 100 blocks, the Merkle root of your audit chain is attested to EAS on Base, Arbitrum, Solana, Irys, and Bitcoin. Anyone can independently verify your audit trail without trusting Sovereignly. Total cost: $0.63/year." },
  { q: "Is the post-quantum cryptography real?", a: "Yes. We use hybrid Ed25519 + ML-DSA-65 (NIST FIPS 204 Level 3) signatures and SHA3-256 dual Merkle roots. When quantum computers break SHA-256, your chain remains verifiable via the post-quantum layer." },
  { q: "Can I self-host?", a: "Yes. The core engine (apps/oss/) is MIT-licensed. Clone the repo, run `bun install && bun run dev`, and you have a full sovereign cloud instance. The multi-tenant SaaS layer (apps/cloud/) uses BSL 1.1." },
  { q: "What's the Quantum Cloud integration?", a: "We integrate with Origin Quantum's 72-qubit Wukong processor for quantum random number generation (QRNG) and quantum Merkle root attestation. This creates physically unreproducible fingerprints of your audit data." },
];

export default function LandingPage() {
  const [annual, setAnnual] = useState(false);
  const [openFaq, setOpenFaq] = useState<number | null>(null);

  return (
    <div className="min-h-screen bg-background">
      {/* Nav */}
      <nav className="fixed top-0 w-full z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <img src="/logo.svg" alt="Sovereignly" className="w-7 h-7 drop-shadow-[0_0_6px_rgba(76,175,80,0.3)]" />
            <span className="font-semibold text-sm tracking-wide">Sovereignly</span>
          </div>
          <div className="hidden md:flex items-center gap-6 text-sm text-text-secondary">
            <a href="#features" className="hover:text-text-primary transition-colors">Features</a>
            <a href="#pricing" className="hover:text-text-primary transition-colors">Pricing</a>
            <a href="https://github.com/Metacognixion-labs/Sovereignly" target="_blank" className="hover:text-text-primary transition-colors">GitHub</a>
          </div>
          <div className="flex items-center gap-3">
            <Link href="/login" className="text-sm text-text-secondary hover:text-text-primary transition-colors">Sign in</Link>
            <Link href="/signup" className="px-4 py-1.5 rounded-lg bg-brand text-background text-sm font-medium hover:bg-brand-bright transition-colors">
              Start Free
            </Link>
          </div>
        </div>
      </nav>

      {/* Hero */}
      <section className="pt-32 pb-20 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-brand/20 bg-brand/5 text-brand text-xs font-mono mb-6">
            <span className="w-1.5 h-1.5 rounded-full bg-brand animate-pulse" />
            Post-Quantum Ready · NIST FIPS 203/204
          </div>
          <h1 className="text-4xl sm:text-5xl lg:text-7xl font-bold tracking-tight leading-[1.1] mb-6">
            Every execution<br />
            <span className="bg-gradient-to-r from-[#4CAF50] via-[#42A5F5] to-[#AB47BC] bg-clip-text text-transparent">
              cryptographically proven.
            </span>
          </h1>
          <p className="text-lg text-text-secondary max-w-2xl mx-auto mb-10 leading-relaxed">
            Deploy serverless functions with immutable audit trails, omnichain attestation
            to 5 public blockchains, and auto-generated compliance reports.
            Open-core. Post-quantum. Self-hostable.
          </p>
          <div className="flex items-center justify-center gap-4 mb-12">
            <Link href="/signup" className="px-6 py-3 rounded-xl bg-brand text-background font-medium hover:bg-brand-bright transition-all hover:shadow-[0_0_30px_rgba(76,175,80,0.4)]">
              Start Free <ArrowRight className="w-4 h-4 inline ml-1" />
            </Link>
            <a href="https://github.com/Metacognixion-labs/Sovereignly" target="_blank"
              className="px-6 py-3 rounded-xl border border-border text-text-secondary font-medium hover:border-brand/40 hover:text-text-primary transition-all">
              <GitBranch className="w-4 h-4 inline mr-1.5" /> View on GitHub
            </a>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-2xl mx-auto">
            {[
              { label: "Anchor Chains", value: 6, suffix: "" },
              { label: "COGS / tenant / yr", value: 0, suffix: "", display: "$0.63" },
              { label: "Runtime Deps", value: 3, suffix: "" },
              { label: "Compliance Score", value: 84, suffix: "/100" },
            ].map(s => (
              <div key={s.label} className="rounded-xl border border-border bg-panel/50 p-4">
                <div className="text-2xl font-bold text-brand">
                  {s.display ?? <Counter end={s.value} suffix={s.suffix} />}
                </div>
                <div className="text-[10px] font-mono text-text-muted uppercase tracking-widest mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Terminal Demo */}
      <section className="pb-20 px-6">
        <div className="max-w-3xl mx-auto">
          <div className="rounded-xl border border-border bg-[#0a0e14] overflow-hidden shadow-2xl">
            <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
              <span className="w-3 h-3 rounded-full bg-red/60" />
              <span className="w-3 h-3 rounded-full bg-amber/60" />
              <span className="w-3 h-3 rounded-full bg-green/60" />
              <span className="text-xs font-mono text-text-muted ml-2">Terminal</span>
            </div>
            <div className="p-5 font-mono text-[13px] leading-[1.8] text-text-secondary">
              <div><span className="text-text-muted">$</span> <span className="text-cyan">sovereignly</span> init</div>
              <div className="text-green">✓ Generated .env with secure random secrets</div>
              <div className="text-green">✓ Created data/platform/</div>
              <div>&nbsp;</div>
              <div><span className="text-text-muted">$</span> <span className="text-cyan">sovereignly</span> dev</div>
              <div className="text-text-muted">⬡ SOVEREIGNLY OSS v4.0.0</div>
              <div className="text-green">✓ Chain ready — tip block #0</div>
              <div className="text-green">✓ Workers: 4 pre-warmed</div>
              <div className="text-green">✓ Ready at http://localhost:8787</div>
              <div>&nbsp;</div>
              <div><span className="text-text-muted">$</span> <span className="text-cyan">sovereignly</span> quantum status</div>
              <div><span style={{color:"#a78bfa"}}>⚛ Signatures:</span> Ed25519 + ML-DSA-65 (FIPS 204)</div>
              <div><span style={{color:"#a78bfa"}}>⚛ Hashing:</span> SHA-256 + SHA3-256 dual roots</div>
              <div><span style={{color:"#a78bfa"}}>⚛ ZK-Ready:</span> Poseidon BN254</div>
              <div className="text-green">✓ Compliance: 84/100 (7 pass, 0 fail)</div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">Infrastructure you can verify</h2>
            <p className="text-text-secondary max-w-xl mx-auto">Every feature built for auditability, sovereignty, and post-quantum resilience.</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
            {FEATURES.map(f => (
              <div key={f.title} className="rounded-xl border border-border bg-panel p-6 hover:border-border-bright transition-all group relative overflow-hidden">
                <div className="absolute top-0 left-0 right-0 h-0.5 opacity-0 group-hover:opacity-60 transition-opacity" style={{ background: f.color }} />
                <div className="w-10 h-10 rounded-lg flex items-center justify-center mb-4" style={{ background: `${f.color}15`, border: `1px solid ${f.color}30` }}>
                  <f.icon className="w-5 h-5" style={{ color: f.color }} />
                </div>
                <h3 className="font-semibold mb-2">{f.title}</h3>
                <p className="text-sm text-text-muted leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Pricing */}
      <section id="pricing" className="py-20 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">Simple, transparent pricing</h2>
            <div className="inline-flex items-center gap-3 mt-4 bg-surface rounded-full p-1 border border-border">
              <button onClick={() => setAnnual(false)}
                className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all ${!annual ? "bg-brand text-background" : "text-text-muted hover:text-text-primary"}`}>
                Monthly
              </button>
              <button onClick={() => setAnnual(true)}
                className={`px-4 py-1.5 rounded-full text-sm font-medium transition-all ${annual ? "bg-brand text-background" : "text-text-muted hover:text-text-primary"}`}>
                Annual <span className="text-[10px] ml-1 opacity-70">Save 20%</span>
              </button>
            </div>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
            {PLANS.map(plan => (
              <div key={plan.name}
                className={`rounded-xl border p-6 flex flex-col ${plan.featured ? "border-brand/40 bg-brand/5 ring-1 ring-brand/20" : "border-border bg-panel"}`}>
                {plan.featured && <div className="text-[9px] font-mono uppercase tracking-widest text-brand mb-3">Most Popular</div>}
                <h3 className="text-lg font-semibold">{plan.name}</h3>
                <p className="text-xs text-text-muted mt-1 mb-4">{plan.desc}</p>
                <div className="mb-6">
                  {plan.price.mo === -1 ? (
                    <span className="text-3xl font-bold">Custom</span>
                  ) : (
                    <>
                      <span className="text-3xl font-bold">${annual ? plan.price.yr : plan.price.mo}</span>
                      {plan.price.mo > 0 && <span className="text-text-muted text-sm">/mo</span>}
                    </>
                  )}
                </div>
                <ul className="space-y-2.5 mb-6 flex-1">
                  {plan.features.map(f => (
                    <li key={f} className="flex items-start gap-2 text-sm text-text-secondary">
                      <Check className="w-4 h-4 text-brand shrink-0 mt-0.5" /> {f}
                    </li>
                  ))}
                </ul>
                <Link href="/signup"
                  className={`w-full py-2.5 rounded-lg text-sm font-medium text-center transition-all ${
                    plan.featured
                      ? "bg-brand text-background hover:bg-brand-bright"
                      : "border border-border hover:border-brand/40 hover:text-brand"
                  }`}>
                  {plan.cta}
                </Link>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="py-20 px-6">
        <div className="max-w-2xl mx-auto">
          <h2 className="text-3xl font-bold tracking-tight mb-10 text-center">FAQ</h2>
          <div className="space-y-3">
            {FAQS.map((faq, i) => (
              <div key={i} className="rounded-xl border border-border bg-panel overflow-hidden">
                <button onClick={() => setOpenFaq(openFaq === i ? null : i)}
                  className="w-full flex items-center justify-between px-5 py-4 text-left text-sm font-medium hover:bg-surface/50 transition-colors">
                  {faq.q}
                  <ChevronDown className={`w-4 h-4 text-text-muted shrink-0 transition-transform ${openFaq === i ? "rotate-180" : ""}`} />
                </button>
                {openFaq === i && (
                  <div className="px-5 pb-4 text-sm text-text-muted leading-relaxed">{faq.a}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className="py-20 px-6">
        <div className="max-w-3xl mx-auto text-center">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">Ready to prove it?</h2>
          <p className="text-text-secondary mb-8">Deploy your first function with cryptographic proof in under 2 minutes.</p>
          <div className="inline-flex items-center gap-2 px-5 py-3 rounded-xl bg-surface border border-border font-mono text-sm mb-8">
            <span className="text-text-muted">$</span>
            <span>npx create-sovereignly@latest</span>
          </div>
          <div className="flex items-center justify-center gap-4">
            <Link href="/signup" className="px-8 py-3 rounded-xl bg-brand text-background font-medium hover:bg-brand-bright transition-all hover:shadow-[0_0_30px_rgba(76,175,80,0.4)]">
              Start Free <ArrowRight className="w-4 h-4 inline ml-1" />
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border py-10 px-6">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <img src="/logo.svg" alt="" className="w-5 h-5" />
            <span className="text-sm font-medium">Sovereignly</span>
            <span className="text-xs text-text-muted">by MetaCognixion</span>
          </div>
          <div className="flex items-center gap-6 text-xs text-text-muted">
            <a href="https://github.com/Metacognixion-labs/Sovereignly" target="_blank" className="hover:text-text-primary transition-colors">GitHub</a>
            <a href="https://twitter.com/Jepetocrypto" target="_blank" className="hover:text-text-primary transition-colors">Twitter</a>
            <span>MIT + BSL 1.1</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
