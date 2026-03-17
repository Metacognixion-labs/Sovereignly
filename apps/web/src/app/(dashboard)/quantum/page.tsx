"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { Atom, ShieldCheck, Fingerprint, Zap, Lock, Hash, Cpu, Waves } from "lucide-react";

interface QuantumStatus {
  pqc: {
    enabled: boolean;
    algorithms: { signatures: string; hashing: string; keyEncapsulation: string; zkReady: string };
    nistCompliance: string;
  };
  chain: {
    dualMerkleRoots: boolean;
    blocksWithPQRoot: number;
    latestPQRoot: string | null;
    latestSHA256Root: string | null;
  };
  quantumCloud: {
    connected: boolean;
    provider: string;
    entropyPool: number;
    attestations: number;
  };
  poseidon: { available: boolean; field: string; zkProvable: boolean };
}

function StatusBadge({ active, label }: { active: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-mono ${
      active
        ? "bg-green/10 text-green border border-green/20"
        : "bg-text-muted/10 text-text-muted border border-border"
    }`}>
      <span className={`w-1.5 h-1.5 rounded-full ${active ? "bg-green shadow-[0_0_4px] shadow-green" : "bg-text-muted"}`} />
      {label}
    </span>
  );
}

function AlgorithmCard({ icon: Icon, name, detail, status, color }: {
  icon: typeof Atom; name: string; detail: string; status: string; color: string;
}) {
  return (
    <div className="rounded-xl border border-border bg-panel p-5 hover:border-border-bright transition-colors">
      <div className="flex items-start justify-between mb-3">
        <div className="w-10 h-10 rounded-lg flex items-center justify-center" style={{ background: `${color}15`, border: `1px solid ${color}30` }}>
          <Icon className="w-5 h-5" style={{ color }} />
        </div>
        <StatusBadge active label={status} />
      </div>
      <div className="font-medium text-sm mb-1">{name}</div>
      <div className="text-xs text-text-muted font-mono leading-relaxed">{detail}</div>
    </div>
  );
}

export default function QuantumPage() {
  const [status, setStatus] = useState<QuantumStatus | null>(null);
  const [publicInfo, setPublicInfo] = useState<any>(null);

  useEffect(() => {
    api<QuantumStatus>("/_sovereign/quantum/status").then(r => r.ok && setStatus(r.data));
    api("/_sovereign/quantum/algorithms").then(r => r.ok && setPublicInfo(r.data));
  }, []);

  const data = status ?? {
    pqc: { enabled: true, algorithms: publicInfo?.pqc?.algorithms ?? { signatures: "Loading...", hashing: "Loading...", keyEncapsulation: "Loading...", zkReady: "Loading..." }, nistCompliance: "" },
    chain: publicInfo?.chain ?? { dualMerkleRoots: true, blocksWithPQRoot: 0, latestPQRoot: null, latestSHA256Root: null },
    quantumCloud: { connected: false, provider: "Checking...", entropyPool: 0, attestations: 0 },
    poseidon: publicInfo?.poseidon ?? { available: true, field: "BN254", zkProvable: true },
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Post-Quantum Security</h1>
          <p className="text-sm text-text-muted mt-0.5">NIST FIPS 203/204 compliant cryptography</p>
        </div>
        <StatusBadge active={data.pqc.enabled} label={data.pqc.enabled ? "PQC ACTIVE" : "PQC INACTIVE"} />
      </div>

      {/* Algorithm Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <AlgorithmCard
          icon={Fingerprint}
          name="Hybrid Signatures"
          detail={data.pqc.algorithms.signatures}
          status="FIPS 204"
          color="#a78bfa"
        />
        <AlgorithmCard
          icon={Hash}
          name="Dual Merkle Roots"
          detail={data.pqc.algorithms.hashing}
          status="Active"
          color="#00d4ff"
        />
        <AlgorithmCard
          icon={Lock}
          name="Key Encapsulation"
          detail={data.pqc.algorithms.keyEncapsulation}
          status="FIPS 203"
          color="#0df23b"
        />
        <AlgorithmCard
          icon={Zap}
          name="ZK-Ready Hash"
          detail={data.pqc.algorithms.zkReady}
          status="Ready"
          color="#ffcc00"
        />
      </div>

      {/* Chain + Quantum Cloud */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Dual Merkle Roots */}
        <div className="rounded-xl border border-border bg-panel">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2">
            <Hash className="w-4 h-4 text-cyan" />
            <span className="text-[10px] font-mono uppercase tracking-widest text-cyan">Dual Merkle Roots</span>
            <StatusBadge active={data.chain.dualMerkleRoots} label="Every Block" />
          </div>
          <div className="p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-text-muted">Blocks with PQ root</span>
              <span className="font-mono text-sm font-semibold text-cyan">{data.chain.blocksWithPQRoot}</span>
            </div>
            {data.chain.latestSHA256Root && (
              <div>
                <div className="text-[9px] font-mono text-text-muted uppercase tracking-widest mb-1">Latest SHA-256 Root</div>
                <div className="font-mono text-[11px] text-text-secondary bg-surface rounded px-3 py-2 break-all">
                  {data.chain.latestSHA256Root}
                </div>
              </div>
            )}
            {data.chain.latestPQRoot && (
              <div>
                <div className="text-[9px] font-mono uppercase tracking-widest mb-1" style={{ color: "#a78bfa" }}>Latest SHA3-256 Root (Post-Quantum)</div>
                <div className="font-mono text-[11px] bg-surface rounded px-3 py-2 break-all" style={{ color: "#a78bfa" }}>
                  {data.chain.latestPQRoot}
                </div>
              </div>
            )}
            <div className="text-[10px] text-text-muted">
              When quantum computers break SHA-256, your chain remains verifiable via the SHA3-256 roots.
            </div>
          </div>
        </div>

        {/* Quantum Cloud */}
        <div className="rounded-xl border border-border bg-panel">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2">
            <Atom className="w-4 h-4" style={{ color: "#a78bfa" }} />
            <span className="text-[10px] font-mono uppercase tracking-widest" style={{ color: "#a78bfa" }}>Origin Quantum Cloud</span>
            <StatusBadge active={data.quantumCloud.connected} label={data.quantumCloud.connected ? "Connected" : "Local PQC"} />
          </div>
          <div className="p-5 space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs text-text-muted">Provider</span>
              <span className="font-mono text-xs text-text-secondary">{data.quantumCloud.provider}</span>
            </div>
            {data.quantumCloud.connected && (
              <>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-text-muted">Entropy Pool</span>
                  <span className="font-mono text-sm text-green">{data.quantumCloud.entropyPool} bytes</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-xs text-text-muted">Quantum Attestations</span>
                  <span className="font-mono text-sm" style={{ color: "#a78bfa" }}>{data.quantumCloud.attestations}</span>
                </div>
              </>
            )}
            <div className="rounded-lg p-3 text-xs text-text-muted" style={{ background: "rgba(167, 139, 250, 0.05)", border: "1px solid rgba(167, 139, 250, 0.1)" }}>
              <Waves className="w-3.5 h-3.5 inline mr-1.5" style={{ color: "#a78bfa" }} />
              {data.quantumCloud.connected
                ? "Quantum random numbers from 72-qubit Wukong processor. Merkle roots attested via quantum circuits."
                : "Post-quantum algorithms (ML-DSA-65, SHA3-256) active locally. Connect Origin Quantum Cloud for hardware QRNG and quantum attestation."}
            </div>
          </div>
        </div>
      </div>

      {/* NIST Compliance */}
      <div className="rounded-xl border border-border bg-panel p-5">
        <div className="flex items-center gap-2 mb-4">
          <ShieldCheck className="w-4 h-4 text-green" />
          <span className="text-[10px] font-mono uppercase tracking-widest text-green">NIST Post-Quantum Standards Compliance</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {[
            { std: "FIPS 203", name: "ML-KEM (Kyber)", desc: "Key encapsulation for encrypted channels", level: "Level 3" },
            { std: "FIPS 204", name: "ML-DSA (Dilithium)", desc: "Digital signatures for block signing", level: "Level 3" },
            { std: "FIPS 205", name: "SLH-DSA (SPHINCS+)", desc: "Stateless hash-based signatures", level: "Ready" },
          ].map(s => (
            <div key={s.std} className="rounded-lg border border-border p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-mono font-semibold" style={{ color: "#a78bfa" }}>{s.std}</span>
                <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-green/10 text-green border border-green/20">{s.level}</span>
              </div>
              <div className="text-sm font-medium mb-1">{s.name}</div>
              <div className="text-[11px] text-text-muted">{s.desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
