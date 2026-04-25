# Comprehensive Implementation Details: Minicrypt & Cryptomania Web Explorer

This document provides a highly structured and comprehensive overview of the **POIS_Project**, encompassing the **Minicrypt Clique**, **Public-Key Cryptomania**, and **Multi-Party Computation (MPC)** implementations. It outlines the architectural design, cryptographic primitives (enforcing the strict "No-Library Rule"), API layer, mathematical validations, and the interactive frontend.

---

## 1. Architectural Overview

The project is structured into a decoupled system using a Python-based core cryptographic engine served via a modern REST API (FastAPI), which is consumed by an interactive React.js frontend.

### 1.1 Directory Structure
`	ext
POIS_Project/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI Application & API Routing Logic
│   │   ├── core/
│   │   │   ├── minicrypt.py       # Core Cryptographic Primitives (Symmetric, Hashing)
│   │   │   ├── math_core.py       # Mathematical Foundations (Primes, CRT, Modular Math)
│   │   │   ├── cryptomania.py     # Public-Key Cryptography (RSA, ElGamal, Signatures)
│   │   │   ├── mpc.py             # Multi-Party Computation (OT, Yao's Gates, DAG Eval)
│   │   │   └── routing.py         # Graph Theory Logic (BFS Cryptanalysis Map)
│   ├── scripts/
│   │   └── demos.py               # Cryptanalytic Games, Demos & Validations
│   └── requirements.txt           # Backend dependencies (fastapi, uvicorn)
├── frontend/
│   └── index.html                 # React Frontend (Babel/Tailwind via CDN)
├── IMPLEMENTATION_DETAILS.md      # This implementation document
└── README.md                      # Quickstart guide
`

---

## 2. Core Cryptographic Engine (ackend/app/core/)

Adhering strictly to the **No-Library Rule**, all primitives are implemented from scratch using Python's large integer arithmetic (int) and operating system entropy (os.urandom). 

### 2.1 Mathematical Foundations (math_core.py)
*   **Fast Modular Exponentiation:** Square-and-multiply, avoiding Python's pow(base, exp, mod).
*   **Prime Generation (PA #13):** Safe prime selection using the **Miller-Rabin Primality Test**.
*   **Extended Euclidean Algorithm (PA #14):** egcd for calculating modular inverses.
*   **Chinese Remainder Theorem (CRT) (PA #14):** Mathematical solvers used heavily in Broadcast Attacks.
*   **Integer N-th Root (PA #14):** Newton's Method solver mapped natively for RSA payload recovery.

### 2.2 Core Cryptographic Constructions (minicrypt.py)
1.  **PA #1 (OWF <-> PRG) [✓ Bidirectional]:** 
    *   *Forward:* Custom HILL_PRG structured from DLP_OWF and the Goldreich-Levin Hard-Core Bit.
    *   *Backward:* PRG_to_OWF constructs an explicit mapping.
2.  **PA #2 (PRG <-> PRF) [✓ Bidirectional]:**
    *   *Forward:* GGM_PRF implementing the Goldreich-Goldwasser-Micali binary tree.
    *   *Backward:* PRF_to_PRG natively mapping backwards.
3.  **PA #3 (PRF -> CPA):** Standard randomized symmetric encryption.
4.  **PA #4 (Block Cipher Modes):** Scratch implementations of CBC, OFB, and CTR using the base PRF.
5.  **PA #5 (PRF -> MAC):** Custom CBC-MAC implementations with secure compare functions avoiding timing attacks.
6.  **PA #6 (CPA + MAC -> CCA):** Encrypt-then-MAC pattern achieving Chosen-Ciphertext Security.

### 2.3 Hashing & Collision Resistance (minicrypt.py)
7.  **PA #7 (Fixed Compression -> Hash):** Classical Merkle-Damgård domain extension logic.
8.  **PA #8 (DLP -> CRHF):** A Collision-Resistant Hash Function.
9.  **PA #9 (Hash Analysis/Birthday Attack):** Validation tooling (Floyd's Cycle-Finding Algorithm & Naive Search).
10. **PA #10 (CRHF <-> HMAC) [✓ Bidirectional]:** 
    *   *Forward:* Scratch building HMAC inside EncryptThenHMAC.
    *   *Backward:* MAC_to_CRHF mapping the MAC state to an active CRHF compression sequence.

### 2.4 Public-Key Cryptography (cryptomania.py)
11. **PA #11 (Diffie-Hellman):** Ephemeral Key Exchange parameters building subgroup g. 
12. **PA #12 (Textbook RSA + PKCS#1 v1.5):** Native N = p * q mapping utilizing OS random paddings.
13. **PA #13 (Miller-Rabin Primality):** Integrated into math_core.py.
14. **PA #14 (CRT + Håstad Broadcast Attack):** Native application of crt() and integer roots.
15. **PA #15 (Digital Signatures):** Hash-then-Sign framework incorporating the fundamental dlp_hash.
16. **PA #16 (ElGamal PKC):** Public-Key variant of DH ensuring probabilistic asymmetric encryption.
17. **PA #17 (CCA-Secure PKC):** Custom Encrypt-then-Sign combination (ElGamal Encryption + RSA Signatures).

### 2.5 Multi-Party Computation / Protocols (mpc.py)
18. **PA #18 (Oblivious Transfer):** 1-out-of-2 OT built directly on RSA. 
19. **PA #19 (Secure AND / Gates):** Isolated simulated secure logic operations directly mapping OT exchanges.
20. **PA #20 (All 2-party MPC):** Advanced topological logic evaluator converting arbitrary circuit DAGs into sequential secure gates.

---

## 3. Cryptanalytic Verification & Games (scripts/demos.py)
### 3.1 Indistinguishability Games (Security Proofs)
*   **PRF Distinguishing Game**, **IND-CPA Game**, **EUF-CMA Game**

### 3.2 Collision & Statistical Valuations
*   **NIST Frequency & Runs Tests**
*   **PA #8 5-Message Test**
*   **PA #9 Birthday Attack Simulations (Naive vs. Floyd)**

---

## 4. API & Orchestration Layer (ackend/app/main.py & outing.py)
A **FastAPI** structure wrapping the core Python cryptography modules to expose them as a REST interface. The BFS architecture proves reductions natively.

---

## 5. View Controller / React Frontend (rontend/index.html)
To strictly fulfill structural capabilities while avoiding specific node package managers natively, the frontend is deployed as a massive single-page application utilizing **React via Unpkg CDNs** and **Babel Standalone**.
