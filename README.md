# Minicrypt & Cryptomania Web Explorer

A from-scratch cryptographic primitive explorer implementing the full **Minicrypt Clique**, **Public-Key Cryptomania**, and **Multi-Party Computation (MPC)** frameworks (PA #0 through PA #20).

## ⚠️ The No-Library Rule

As per project requirements, **NO external cryptographic libraries** (e.g., `cryptography`, `PyCryptodome`, `OpenSSL`, etc.) are used in any `core` component. Everything—from PRGs (HILL variant) and block encapsulation (CBC, OFB, CTR) to Merkle-Damgård hashing, RSA, ElGamal, and Secure MPC—is constructed from scratch using:

- **Python's built-in `int`** for arbitrary-precision integer arithmetic (including `pow(base, exp, mod)`)
- **`os.urandom`** for OS-level randomness

FastAPI is used solely as a decoupled API boundary for the web frontend (PA #0).

---

## Project Structure

```text
POIS_Project/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI Application & API Routing (PA#0)
│   │   ├── core/
│   │   │   ├── minicrypt.py       # Core Minicrypt Clique (PA#1-#10 + bidirectional reductions)
│   │   │   │                      # OWF, PRG, PRF, PRP (Luby-Rackoff), OWP, MAC, CRHF, HMAC
│   │   │   ├── math_core.py       # Mathematical Foundations (Primes, CRT, Modular Math)
│   │   │   ├── cryptomania.py     # Public-Key Cryptography (RSA, ElGamal, Signatures)
│   │   │   ├── mpc.py             # Multi-Party Computation (OT, Secure Gates, DAG Circuits)
│   │   │   └── routing.py         # Graph Theory Logic (BFS across Minicrypt Clique)
│   ├── scripts/
│   │   └── demos.py               # Cryptanalytic Games, Demos, Attacks & Validations
│   └── requirements.txt           # Backend dependencies (fastapi, uvicorn)
├── frontend/                      # React Frontend (Vite)
│   ├── src/
│   │   ├── App.jsx                # Main React component with all PA panels
│   │   ├── index.css              # Global styles (dark theme)
│   │   └── main.jsx               # React entry point
│   ├── index.html                 # Vite HTML template
│   └── package.json               # Frontend dependencies
├── pois project.pdf               # Project specification
├── IMPLEMENTATION_DETAILS.md       # Detailed implementation document
└── README.md                      # This file
```

---

## Implemented Primitives Summary

### Part I: Minicrypt Clique (PA#1–PA#6)

| PA | Primitive | Forward | Backward | Status |
|----|-----------|---------|----------|--------|
| #1 | OWF ⇔ PRG | `DLP_OWF` → `HILL_PRG` | `PRG_to_OWF` | ✅ |
| #1 | OWF ⇔ OWP | `DLP_OWP` | `DLP_OWP.as_owf()` | ✅ |
| #2 | PRG ⇔ PRF | `GGM_PRF` (GGM tree) | `PRF_to_PRG` | ✅ |
| — | OWP ⇔ PRG | `OWP_to_PRG` | `PRG_to_OWP` | ✅ |
| — | PRF ⇔ PRP | `LubyRackoff_PRP` (3-round Feistel) | `PRP_to_PRF` | ✅ |
| — | OWP ⇔ PRF | `OWP_to_PRF` | `PRF_to_OWP` | ✅ |
| #3 | PRF → CPA | `CPA_Symmetric` | — | ✅ |
| #4 | PRF → Modes | `ModesOfOperation` (CBC/OFB/CTR) | — | ✅ |
| #5 | PRF ⇔ MAC | `PRF_MAC` (CBC-MAC) | `MAC_to_PRF` | ✅ |
| — | PRP ⇔ MAC | `PRP_to_MAC` | `MAC_to_PRP` | ✅ |
| #6 | CPA+MAC → CCA | `CCA_Symmetric` (Encrypt-then-MAC) | — | ✅ |

### Part II: Hashing & Data Integrity (PA#7–PA#10)

| PA | Primitive | Status |
|----|-----------|--------|
| #7 | Merkle-Damgård Transform | ✅ `MerkleDamgard` |
| #8 | DLP-Based CRHF | ✅ `DLP_CRHF` + `dlp_hash` |
| #9 | Birthday Attack (Naive + Floyd) | ✅ `CollisionFinder` |
| #10 | HMAC + CCA-Secure Encryption | ✅ `HMAC_Implementation` + `EncryptThenHMAC` |
| — | CRHF ⇔ HMAC | ✅ Bidirectional |
| — | HMAC ⇔ MAC | ✅ `HMAC_to_MAC` / `MAC_to_HMAC` |
| — | CRHF ⇔ MAC (full bridge) | ✅ `CRHF_to_MAC` / `MAC_to_CRHF_Full` |

### Part III: Cryptomania (PA#11–PA#17)

| PA | Primitive | Status |
|----|-----------|--------|
| #11 | Diffie-Hellman Key Exchange | ✅ + MITM & CDH demos |
| #12 | Textbook RSA + PKCS#1 v1.5 | ✅ + determinism demo |
| #13 | Miller-Rabin Primality | ✅ + Carmichael 561 test |
| #14 | CRT + Håstad Broadcast Attack | ✅ |
| #15 | Digital Signatures (Hash-then-Sign) | ✅ + multiplicative forgery |
| #16 | ElGamal PKC | ✅ + malleability demo |
| #17 | CCA-Secure PKC (Encrypt-then-Sign) | ✅ |

### Part IV: Secure MPC (PA#18–PA#20)

| PA | Primitive | Status |
|----|-----------|--------|
| #18 | 1-out-of-2 Oblivious Transfer (RSA) | ✅ |
| #19 | Secure AND (via OT) + Free XOR | ✅ |
| #20 | DAG Circuit Evaluator | ✅ |
| #20 | Millionaire's Problem | ✅ `run_millionaire()` |
| #20 | Secure Equality Test | ✅ `run_equality()` |
| #20 | Secure Bit-Addition | ✅ `run_addition()` |

---

## Setup & Execution

### 1. Backend Environment Setup

```bash
cd backend
python -m venv venv

# Windows
.\venv\Scripts\activate

# Linux/Mac
# source venv/bin/activate

pip install -r requirements.txt
```

### 2. Running the Demo Suite (All PAs)

Validates all cryptographic primitives, games, attacks, and MPC circuits:

```bash
cd backend
python scripts/demos.py
```

This runs:
- **NIST Statistical Tests** (Frequency + Runs) on PRG output
- **Security Games**: PRF Distinguishing, IND-CPA, EUF-CMA
- **Birthday Attack**: 100-trial benchmark (Naive vs Floyd)
- **Attack Demos**: Nonce reuse, malleability, length extension, collision propagation
- **Math Foundations**: Miller-Rabin, CRT, Newton's roots
- **Cryptomania**: DH, RSA, ElGamal, Håstad, Signatures, CCA-PKC
- **MPC**: OT, Secure AND/XOR, DAG circuits

### 3. Running the API Server

```bash
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Navigate to `http://localhost:8000/docs` for the Swagger API interface.

**Available API Endpoints:**
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/owf/evaluate` | POST | PA#1: Evaluate OWF |
| `/api/prg/next_bits` | POST | PA#1: PRG output |
| `/api/cpa/encrypt` | POST | PA#3: CPA encryption |
| `/api/cpa/decrypt` | POST | PA#3: CPA decryption |
| `/api/modes/encrypt` | POST | PA#4: Modes (CBC/OFB/CTR) |
| `/api/mac/compute` | POST | PA#5: MAC computation |
| `/api/cca/encrypt` | POST | PA#6: CCA encryption |
| `/api/cca/decrypt` | POST | PA#6: CCA decryption |
| `/api/hash/dlp` | POST | PA#8: DLP hash |
| `/api/hmac/compute` | POST | PA#10: HMAC computation |
| `/api/prp/encrypt` | POST | Luby-Rackoff PRP encrypt |
| `/api/prp/decrypt` | POST | Luby-Rackoff PRP decrypt |
| `/api/dh/exchange` | POST | PA#11: DH key exchange |
| `/api/rsa/demo` | POST | PA#12: RSA enc/dec demo |
| `/api/elgamal/demo` | POST | PA#16: ElGamal enc/dec |
| `/api/mpc/and` | POST | PA#19: Secure AND gate |
| `/api/mpc/xor` | POST | PA#19: Free Secure XOR |
| `/api/mpc/millionaire` | POST | PA#20: Millionaire's Problem |
| `/api/mpc/equality` | POST | PA#20: Secure Equality |
| `/api/mpc/addition` | POST | PA#20: Secure Addition |
| `/api/graph/schema` | GET | Full graph schema |
| `/api/graph/reduce` | POST | BFS reduction path |

### 4. Frontend (Vite + React Web Explorer)

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser (with the API server running on port 8000).

**Features:**
- **Sidebar navigation** for all 21 PAs organized by section
- **Foundation toggle** (DLP / AES) in the header
- **Graph Explorer** (PA#0): BFS pathfinding across the 14-node, 32-edge Minicrypt Clique
- **Live Panels**: PRG output viewer (PA#1), CPA encryption (PA#3), DLP Hash (PA#8)
- **Stub panels** for all other PAs with descriptions and CLI fallback
- **Proof summary bar** at the bottom

---

## End-to-End Lineage (PA#20 Requirement)

A single AND gate evaluation triggers the following call chain:

```
PA#20: SecureDAG.evaluate()
  └─ PA#19: SecureGateSimulator.secure_and(a, b)
       └─ PA#18: RSA_OT_Sender / RSA_OT_Receiver
            ├─ RSA keygen (PA#12): rsa_keygen()
            │    └─ Miller-Rabin (PA#13): miller_rabin() → gen_prime()
            ├─ RSA decrypt: rsa_dec_textbook()
            │    └─ fast_mod_exp (PA#12)
            └─ DLP Hash (PA#8): dlp_hash()
                 └─ Merkle-Damgård (PA#7) + DLP_CRHF compression
```

---

## Bidirectional Reductions Clique

The Minicrypt Clique graph (14 nodes, 32 edges):

```
OWF ⇔ PRG ⇔ PRF ⇔ PRP
 ↕         ↕       ↕
OWP ─────→ PRF ⇔ MAC ⇔ PRP
                   ↕
              CRHF ⇔ HMAC ⇔ MAC
```

All bidirectional reductions are implemented:
- **OWF ⇔ PRG**: HILL construction / G(s) is OWF
- **OWF ⇔ OWP**: DLP on Z_q / OWP ⊂ OWF
- **PRG ⇔ PRF**: GGM tree / F_s(0)||F_s(1)
- **OWP ⇔ PRG**: Hard-core predicate / length-preserving PRG
- **PRF ⇔ PRP**: Luby-Rackoff 3-round Feistel / Switching Lemma
- **PRF ⇔ MAC**: CBC-MAC / MAC on uniform inputs
- **PRP ⇔ MAC**: Via PRF bridge
- **OWP ⇔ PRF**: Via OWP→PRG→PRF chain
- **CRHF ⇔ HMAC**: PA#10 construction / fixed-key HMAC
- **HMAC ⇔ MAC**: HMAC is EUF-CMA / MAC in double-hash structure
- **CRHF ⇔ MAC**: Full bridge via HMAC

---

## Toy Examples for UI Testing

Here are some toy parameters you can copy and paste into the interactive web explorer panels to easily test their functionality without typing long hex strings:

### PA#0: Clique Explorer
*   **Key / Seed (hex)**: `00112233445566778899aabbccddeeff`
*   **Query / Message (hex)**: `48656c6c6f`

### PA#1: OWF & PRG
*   **Seed (Hex)**: `deadbeef`

### PA#2: PRF (GGM Tree)
*   **Key (int)**: `12345`
*   **Query (bits)**: `1011`

### PA#3: CPA Encryption
*   **m₀ (hex)**: `48656c6c6f20776f726c6421` (Hello world!)
*   **m₁ (hex)**: `476f6f646279652121212121` (Goodbye!!!!!)

### PA#4: Modes of Operation
*   **Key**: `00112233445566778899aabbccddeeff`
*   **IV**: `aabbccddeeff00112233445566778899`
*   **Message**: `48656c6c6f20576f726c6421212121215365636f6e6420626c6f636b21212121546869726420626c6f636b2121212121`

### PA#5: MACs
*   **Message m***: `48656c6c6f`

### PA#6: CCA Encryption (Malleability)
*   **Message**: `48656c6c6f20576f726c642121212121`

### PA#7: Merkle-Damgård Hash
*   **Message (Text)**: `Hello World! This is a long message to test blocks.`

### PA#8: DLP-Based CRHF
*   **Message**: `48656c6c6f`

### PA#9: Birthday Attack
*   *Use the slider in the UI to test different bit lengths. No input required.*

### PA#10: HMAC vs Naive MAC
*   **Original Message m**: `48656c6c6f`
*   **Attacker Append m'**: `41747461636b`
