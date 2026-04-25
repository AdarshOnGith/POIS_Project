# Minicrypt & Cryptomania Web Explorer: Comprehensive Implementation Details

This document provides a highly structured and comprehensive overview of the **Minicrypt Clique Web Explorer** project. It outlines the architectural design, cryptographic implementations (enforcing the strict "No-Library Rule"), API layer, mathematical validations, and the interactive frontend.

---

## 1. Architectural Overview

The project is structured into a decoupled system using a Python-based core cryptographic engine served via a modern REST API (FastAPI), which is consumed by an interactive React.js frontend.

### 1.1 Directory Structure
```text
POIS_Project/
â”œâ”€â”€ backend/
â”‚   â”œâ”€â”€ app/
â”‚   â”‚   â”œâ”€â”€ main.py                # FastAPI Application & API Routing Logic
â”‚   â”‚   â”œâ”€â”€ core/
â”‚   â”‚   â”‚   â”œâ”€â”€ minicrypt.py       # Core Cryptographic Primitives (Phase 2)
â”‚   â”‚   â”‚   â”œâ”€â”€ math_core.py       # Core Math Foundations (Phase 3)
â”‚   â”‚   â”‚   â”œâ”€â”€ cryptomania.py     # Public-Key Crypto (Phase 3)
â”‚   â”‚   â”‚   â”œâ”€â”€ mcp.py             # Multi-Party Computation (Phase 4)
â”‚   â”‚   â”‚   â””â”€â”€ routing.py         # Graph Theory Logic (BFS Cryptanalysis Map)
â”‚   â”œâ”€â”€ scripts/
â”‚   â”‚   â””â”€â”€ demos.py               # Cryptanalytic Games, Demos & NIST validations
â”‚   â””â”€â”€ requirements.txt           # Backend dependencies (fastapi, uvicorn)
â”œâ”€â”€ frontend/
â”‚   â””â”€â”€ index.html                 # React Frontend (Babel/Tailwind via CDN)
â””â”€â”€ README.md                      # Quickstart guide
```

---

## 2. Core Cryptographic Engine (Phases 1-4)

Adhering strictly to the **No-Library Rule**, all primitives are implemented from scratch using Python's large integer arithmetic (`int`) and operating system entropy (`os.urandom`). 

### 2.1 Minicrypt Base (Phase 2)
*   **PA #1-#2 (PRG/PRF):** Built via custom DLP constraints and GGM trees.
*   **PA #3-#6 (CPA/CCA/MAC):** Native Encrypt-then-MAC combinations natively rejecting malleability.
*   **PA #7-#10 (Hashes):** Custom Merkle-DamgÃ¥rd logic utilizing DLP collision resistance.

### 2.2 Mathematical Foundations (Phase 3 | `math_core.py`)
*   **PA #13 (Miller-Rabin & Primes):** Probabilistic compositeness evaluations enforcing Carmichael bounds (e.g., 561) over custom recursive definitions.
*   **CRT & Modular Roots:** Extended Euclidean algorithm implementations powering Fast Modular Exponentiations cleanly isolated.

### 2.3 Cryptomania Public-Key Core (Phase 3 | `cryptomania.py`)
*   **PA #11 (Key Exchange):** Diffie-Hellman protocols relying directly on generated safe-primes.
*   **PA #12 & PA #16 (RSA/ElGamal):** Textbook & PKCS#1 v1.5 Mapped paradigms allowing strict structural malleability tests.
*   **PA #14 & PA #15 (Attacks & Sigs):** HÃ¥stad's Broadcast logic evaluating limits of $e=3$ bounds via CRT and Integer Roots natively. Hash-then-Sign signature generation explicitly breaking multiplicative forgeries.
*   **PA #17 (CCA PKC):** Encrypt-then-Sign frameworks demonstrating identical rejection boundaries evaluated via ElGamal packages nested across RSA identities.

### 2.4 Multi-Party Computation (Phase 4 | `mpc.py`)
*   **PA #18 (Oblivious Transfer):** 1-out-of-2 OT based upon textbook RSA math constructs enabling private bit selections without Alice learning Bob's pick.
*   **PA #19 (Secure Gates):** Secure Boolean AND/XOR evaluations using standard OT execution patterns explicitly mirroring garbled limits.
*   **PA #20 (Circuit Evaluation):** Topological mapping DAG evaluating secure primitives strictly without resolving dependencies improperly.

---

## 3. Cryptanalytic Verification & Games (`backend/scripts/demos.py`)

A standalone execution script designed to mathematically prove the theoretical boundaries of the implemented primitives. Spans all 4 Phases comprehensively:
*   Indistinguishability Games (CPA / EUF-CMA).
*   Hash Collision (Floyd Cycle O(1) checks).
*   Cryptomania Native Validation (HÃ¥stad, Multiplicative Forgery derivations, Indistinguishability checks).
*   Topological DAG MPC Evaluations strictly bound to the local OS random seed limitations.

---

## 4. API Layer & Frontend (`backend/app/main.py`)
A single-page, multi-view React application consuming standard FastAPI REST endpoints executing mathematical evaluation natively without browser Node constraints mapping local networks effectively to strict execution graphs.