# Minicrypt Clique Web Explorer: Comprehensive Implementation Details

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
â”‚   â”‚   â”‚   â”œâ”€â”€ minicrypt.py       # Core Cryptographic Primitives (No-Library)
â”‚   â”‚   â”‚   â””â”€â”€ routing.py         # Graph Theory Logic (BFS Cryptanalysis Map)
â”‚   â”œâ”€â”€ scripts/
â”‚   â”‚   â””â”€â”€ demos.py               # Cryptanalytic Games, Demos & NIST validations
â”‚   â””â”€â”€ requirements.txt           # Backend dependencies (fastapi, uvicorn)
â”œâ”€â”€ frontend/
â”‚   â””â”€â”€ index.html                 # React Frontend (Babel/Tailwind via CDN)
â””â”€â”€ README.md                      # Quickstart guide
```

---

## 2. Core Cryptographic Engine (`backend/app/core/minicrypt.py`)

Adhering strictly to the **No-Library Rule**, all primitives are implemented from scratch using Python's large integer arithmetic (`int`) and operating system entropy (`os.urandom`). 

### 2.1 Pure Mathematical Foundations
*   **Discrete Logarithm Problem (DLP_OWF):** Implementations of $f(x) = g^x \pmod p$. Used as the baseline for One-Way Functions (OWFs).
*   **Length-Extension Resilient Merkle-DamgÃ¥rd:** Custom padding schemes and iterative compression structures based off small block states.
*   **Pseudo-Random Generators (PRG):** A custom structured stream generator leveraging Blum-Micali/HILL-like iterations over DLP and Hard-Core Predicates.

### 2.2 Implemented Primitive List (Programming Assignments #1 - #10)
1.  **PA #1 (OWF $\leftrightarrow$ PRG):** Proves reductions between One-Way Functions and Pseudo-Random Generators.
2.  **PA #2 (PRG $\rightarrow$ PRF):** Implements the Goldreich-Goldwasser-Micali (GGM) binary tree construction mapping a PRG to a Pseudo-Random Function.
3.  **PA #3 (PRF $\rightarrow$ CPA):** Standard randomized symmetric encryption utilizing $F_k(r) \oplus m$.
4.  **PA #4 (Block Cipher Modes):** Scratch implementations of CBC, CFB, OFB, and CTR using the base PRF.
5.  **PA #5 (PRF $\leftrightarrow$ MAC):** Custom CBC-MAC implementations with secure compare functions avoiding timing attacks.
6.  **PA #6 (CPA + MAC $\rightarrow$ CCA):** Encrypt-then-MAC pattern achieving Chosen-Ciphertext Security.
7.  **PA #7 (Fixed Compression $\rightarrow$ Hash):** Classical Merkle-DamgÃ¥rd domain extension.
8.  **PA #8 (DLP $\rightarrow$ CRHF):** A Collision-Resistant Hash Function built via $H(x_1, x_2) = g^{x_1} h^{x_2} \pmod p$.
9.  **PA #9 (Hash Analysis):** Validation tooling for expected threshold limits on CRHFs.
10. **PA #10 (CRHF $\rightarrow$ HMAC):** Scratch implementation of `hash( (K \oplus opad) || hash( (K \oplus ipad) || M ) )`.

---

## 3. Cryptanalytic Verification & Games (`backend/scripts/demos.py`)

A standalone execution script designed to mathematically prove the theoretical boundaries of the implemented primitives.

### 3.1 Indistinguishability Games (Security Proofs)
*   **PRF Distinguishing Game:** Simulates an adversary querying either a true Random Oracle or the GGM PRF.
*   **IND-CPA Game:** Proves that an adversary cannot guess which of two chosen messages were encrypted.
*   **EUF-CMA Game:** Demonstrates existential unforgeability under chosen-message attacks on the custom CBC-MAC.

### 3.2 Collision & Statistical Valuations
*   **NIST Frequency & Runs Tests:** Statistical randomness checks applied to the scratch-built PRG.
*   **PA #8 5-Message Test:** Hashes 5 specifically sized strings to mathematically confirm distinct outputs and the resilience of MD padding against native collisions.
*   **PA #9 Birthday Attack Simulations (Naive vs. Floyd):**
    *   **Naive Dictionary Attack:** $O(N)$ Space complexity. Stores every hash until a collision occurs.
    *   **Floyd's Cycle-Finding Algorithm (Tortoise and Hare):** $O(1)$ Space complexity. Validates evaluations matching theoretical limits ~ $1.25 \times \sqrt{2^N}$.

---

## 4. API Layer (`backend/app/main.py`)

A **FastAPI** structure wrapping the core Python cryptography modules to expose them as a REST interface.

### Endpoints
*   `POST /api/graph/reduce`: Takes taking a Source and Target primitive via Breadth-First-Search (BFS) inside `routing.py` and returns the stringified mathematical proofs reducing them.
*   `POST /api/owf/evaluate`: Executes the DLP One-Way Function live.
*   `POST /api/prg/next_bits`: Computes deterministic pseudo-random bitstreams.
*   `POST /api/cpa/encrypt` / `decrypt`: Encrypts/Decrypts payloads dynamically.
*   `POST /api/hash/dlp`: Runs the custom CRHF mapping.
*   `GET /api/graph/schema`: Returns the total interconnected network array of all 10 PA primitives and their edge conditions.

---

## 5. View Controller / React Frontend (`frontend/index.html`)

To strictly fulfill structural capabilities while avoiding specific node package managers natively, the frontend is deployed as a massive single-page application utilizing **React via Unpkg CDNs** and **Babel Standalone**.

### 5.1 Interactive Two-Column UI (PA #0 Rule)
*   **Column 1 (Build Panel):** Selects the **Source Primitive** and injects an initial Hex Key / Seed.
*   **Column 2 (Reduce Panel):** Selects the **Target Primitive** to map the reduction proof boundary. It dynamically renders the BFS algorithmic shortest path mapped between the elements.
*   **Bidirectional Swap Button:** Rotates columns mathematically bridging PA Inverse equivalences (e.g. PRG $\rightarrow$ OWF).

### 5.2 Live Data Flow Sandbox
Within Column 2, users can inject raw strings or hex payloads into the selected target. "Execute Live" natively triggers the FastAPI router crossing boundaries back into the `minicrypt.py` engine, proving execution states without ever dropping down into the terminal.