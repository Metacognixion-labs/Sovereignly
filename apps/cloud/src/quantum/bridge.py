"""
Sovereignly Cloud — Origin Quantum Cloud Bridge Service
Business Source License 1.1 — MetaCognixion

Lightweight FastAPI service that wraps pyQPanda's QCloud SDK.
Sovereignly (Bun/TS) calls this over HTTP to access quantum hardware.

Endpoints:
    POST /quantum/qrng     → Quantum Random Number Generation
    POST /quantum/attest   → Quantum Audit Attestation (Merkle root → circuit → measure)
    GET  /health           → Service health check

Install:
    pip install pyqpanda fastapi uvicorn

Run:
    uvicorn bridge:app --host 0.0.0.0 --port 9900

    Or with auto-reload for development:
    uvicorn bridge:app --host 0.0.0.0 --port 9900 --reload
"""

import os
import hashlib
import json
import time
from typing import Optional

from fastapi import FastAPI, HTTPException, Header
from pydantic import BaseModel

# ── pyQPanda Import ──────────────────────────────────────────────────────────

try:
    from pyqpanda import (
        CPUQVM, QCloud, H, CNOT, RX, RY, RZ, Measure,
        QProg, QCircuit,
        create_empty_qprog,
    )
    QPANDA_AVAILABLE = True
except ImportError:
    QPANDA_AVAILABLE = False
    print("[Bridge] WARNING: pyqpanda not installed. Using simulation fallback.")
    print("[Bridge] Install with: pip install pyqpanda")

# ── App Setup ────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Sovereignly Quantum Bridge",
    description="Bridge between Sovereignly Cloud and Origin Quantum Cloud (Wukong 72q)",
    version="1.0.0",
)

ORIGIN_API_TOKEN = os.getenv("QUANTUM_API_TOKEN", "")


# ── Request Models ───────────────────────────────────────────────────────────

class QRNGRequest(BaseModel):
    action: str = "generate_random"
    num_bytes: int = 32
    num_qubits: int = 8
    shots: int = 4096
    chip_id: str = "Simulation"
    use_hardware: bool = False


class AttestRequest(BaseModel):
    action: str = "attest_merkle_root"
    merkle_root: str
    block_index: int
    event_count: int
    org_id: str = "platform"
    chip_id: str = "Simulation"
    shots: int = 4096
    use_hardware: bool = False


# ── QRNG Endpoint ────────────────────────────────────────────────────────────

@app.post("/quantum/qrng")
async def quantum_random(req: QRNGRequest, x_api_token: Optional[str] = Header(None)):
    """
    Generate quantum random numbers using Hadamard + Measure circuit.

    Circuit: |0⟩ → H → Measure
    Each qubit produces a truly random 0 or 1 when measured.
    Multiple shots give a distribution; we extract raw bits from outcomes.
    """
    num_qubits = min(max(1, req.num_qubits), 30)

    if QPANDA_AVAILABLE and req.use_hardware and ORIGIN_API_TOKEN:
        # ── Real Hardware (Origin Wukong) ──
        try:
            machine = QCloud()
            machine.set_configure(72, 72)
            machine.init_qvm(ORIGIN_API_TOKEN, True)

            q = machine.qAlloc_many(num_qubits)
            c = machine.cAlloc_many(num_qubits)

            prog = create_empty_qprog()
            for i in range(num_qubits):
                prog.insert(H(q[i]))
            for i in range(num_qubits):
                prog.insert(Measure(q[i], c[i]))

            result = machine.real_chip_measure(prog, req.shots, chip_id=req.chip_id)
            machine.finalize()

            random_hex = _distribution_to_random_hex(result, req.num_bytes)

            return {
                "random_hex": random_hex,
                "source": "quantum_hardware",
                "chip": req.chip_id,
                "qubits": num_qubits,
                "shots": req.shots,
                "distribution_size": len(result),
            }
        except Exception as e:
            print(f"[Bridge] Hardware QRNG failed, falling back to simulator: {e}")

    if QPANDA_AVAILABLE:
        # ── Local Simulator ──
        try:
            machine = CPUQVM()
            machine.init_qvm()

            q = machine.qAlloc_many(num_qubits)
            c = machine.cAlloc_many(num_qubits)

            prog = create_empty_qprog()
            for i in range(num_qubits):
                prog.insert(H(q[i]))
            for i in range(num_qubits):
                prog.insert(Measure(q[i], c[i]))

            result = machine.run_with_configuration(prog, c, req.shots)
            machine.finalize()

            random_hex = _distribution_to_random_hex(result, req.num_bytes)

            return {
                "random_hex": random_hex,
                "source": "quantum_simulator",
                "chip": "CPUQVM",
                "qubits": num_qubits,
                "shots": req.shots,
                "distribution_size": len(result),
            }
        except Exception as e:
            print(f"[Bridge] Simulator QRNG failed: {e}")

    # ── Pure Python Fallback (no pyqpanda) ──
    random_hex = os.urandom(req.num_bytes).hex()
    return {
        "random_hex": random_hex,
        "source": "python_fallback",
        "chip": "none",
        "qubits": 0,
        "shots": 0,
        "distribution_size": 0,
    }


# ── Attestation Endpoint ─────────────────────────────────────────────────────

@app.post("/quantum/attest")
async def quantum_attest(req: AttestRequest, x_api_token: Optional[str] = Header(None)):
    """
    Encode a Merkle root into a quantum circuit and measure it.

    The circuit uses the Merkle root bits to parameterize rotation gates,
    creating a unique quantum state. Measuring this state produces a
    distribution that serves as a quantum fingerprint.

    Circuit structure:
        For each byte b_i of merkle_root[0:8]:
            RY(b_i * π / 256) on qubit i
            If b_i > 127: H on qubit i  (superposition for high bits)
            CNOT chain: q[i] → q[i+1]
        Measure all qubits
    """
    # Use 8 qubits for attestation (first 8 bytes of Merkle root)
    num_qubits = 8
    root_bytes = bytes.fromhex(req.merkle_root[:16].ljust(16, '0'))

    if QPANDA_AVAILABLE and req.use_hardware and ORIGIN_API_TOKEN:
        try:
            machine = QCloud()
            machine.set_configure(72, 72)
            machine.init_qvm(ORIGIN_API_TOKEN, True)

            q = machine.qAlloc_many(num_qubits)
            c = machine.cAlloc_many(num_qubits)

            prog = _build_attestation_circuit(q, c, root_bytes, num_qubits)

            result = machine.real_chip_measure(prog, req.shots, chip_id=req.chip_id)
            machine.finalize()

            return {
                "distribution": result,
                "circuit_depth": num_qubits * 3,
                "qubits": num_qubits,
                "chip": req.chip_id,
                "task_id": f"qattest_{int(time.time())}_{req.block_index}",
                "source": "quantum_hardware",
            }
        except Exception as e:
            print(f"[Bridge] Hardware attestation failed, falling back: {e}")

    if QPANDA_AVAILABLE:
        try:
            machine = CPUQVM()
            machine.init_qvm()

            q = machine.qAlloc_many(num_qubits)
            c = machine.cAlloc_many(num_qubits)

            prog = _build_attestation_circuit(q, c, root_bytes, num_qubits)

            result = machine.run_with_configuration(prog, c, req.shots)
            machine.finalize()

            return {
                "distribution": result,
                "circuit_depth": num_qubits * 3,
                "qubits": num_qubits,
                "chip": "CPUQVM",
                "task_id": f"qattest_{int(time.time())}_{req.block_index}",
                "source": "quantum_simulator",
            }
        except Exception as e:
            print(f"[Bridge] Simulator attestation failed: {e}")

    # ── Fallback: simulate distribution from hash ──
    import math
    distribution = {}
    for i in range(min(2 ** num_qubits, 256)):
        state = format(i, f'0{num_qubits}b')
        h = hashlib.sha256(f"{req.merkle_root}:{state}".encode()).hexdigest()
        distribution[state] = int(h[:4], 16) % (req.shots // 16) + 1

    return {
        "distribution": distribution,
        "circuit_depth": num_qubits * 3,
        "qubits": num_qubits,
        "chip": "python_fallback",
        "task_id": f"qattest_{int(time.time())}_{req.block_index}",
        "source": "fallback",
    }


# ── Health Check ──────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "sovereignly-quantum-bridge",
        "pyqpanda": QPANDA_AVAILABLE,
        "api_token_set": bool(ORIGIN_API_TOKEN),
        "timestamp": int(time.time()),
    }


# ── Helpers ───────────────────────────────────────────────────────────────────

def _distribution_to_random_hex(distribution: dict, num_bytes: int) -> str:
    """
    Extract random bytes from a quantum measurement distribution.

    Each measurement outcome is a bitstring. We concatenate all outcomes
    weighted by their frequency and hash them to produce uniform random bytes.
    """
    # Concatenate all measurement outcomes
    raw_bits = ""
    for outcome, count in sorted(distribution.items()):
        raw_bits += outcome * min(count, 10)  # Weight by frequency, cap for speed

    # Hash to produce uniform random bytes
    # Use multiple SHA-256 rounds if we need more bytes than 32
    result = b""
    counter = 0
    while len(result) < num_bytes:
        data = f"{raw_bits}:{counter}:{time.time_ns()}".encode()
        result += hashlib.sha256(data).digest()
        counter += 1

    return result[:num_bytes].hex()


def _build_attestation_circuit(q, c, root_bytes, num_qubits):
    """
    Build a quantum circuit that encodes a Merkle root.

    Each byte of the root parameterizes a rotation gate on a qubit.
    High bits trigger Hadamard gates for superposition.
    CNOT chain entangles adjacent qubits.
    """
    import math

    prog = create_empty_qprog()

    # Encode each byte as a rotation
    for i in range(min(num_qubits, len(root_bytes))):
        angle = root_bytes[i] * math.pi / 256.0
        prog.insert(RY(q[i], angle))

        if root_bytes[i] > 127:
            prog.insert(H(q[i]))

    # Entangle with CNOT chain
    for i in range(num_qubits - 1):
        prog.insert(CNOT(q[i], q[i + 1]))

    # Second rotation layer (from byte XOR)
    for i in range(min(num_qubits, len(root_bytes))):
        xor_byte = root_bytes[i] ^ root_bytes[(i + 1) % len(root_bytes)]
        angle2 = xor_byte * math.pi / 256.0
        prog.insert(RZ(q[i], angle2))

    # Measure all
    for i in range(num_qubits):
        prog.insert(Measure(q[i], c[i]))

    return prog


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("QUANTUM_BRIDGE_PORT", "9900"))
    print(f"\n  Sovereignly Quantum Bridge v1.0")
    print(f"  pyQPanda: {'available' if QPANDA_AVAILABLE else 'NOT INSTALLED'}")
    print(f"  API Token: {'set' if ORIGIN_API_TOKEN else 'not set'}")
    print(f"  Port: {port}\n")
    uvicorn.run(app, host="0.0.0.0", port=port)
