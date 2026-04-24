# Minicrypt Clique Web Explorer

A from-scratch cryptographic primitive explorer evaluating core dependencies and equivalences within the Minicrypt complexity-theoretic framework (PA #1 through #10).

## ⚠️ Important Context: "The No-Library Rule"
As per project requirements, **NO external arbitrary cryptographic libraries** (e.g., `cryptography`, `PyCryptodome`, `OpenSSL`, etc.) are permitted at any tier inside the `core` components. **Everything**—from PRGs (HILL variant) and CPA/CCA block encapsulation (CBC, OFB, CTR) down to generic Merkle-Damgård collision logic and math evaluation—is constructed entirely from scratch using native Python primitives relying exclusively on generic arbitrary-precision integers and standard OS-level randomness (`os.urandom`).

FastAPI is deployed exclusively as a decoupled structural mapping boundary enabling front-end UI visualization (thus fulfilling PA #0).

## Project Structure

```text
POIS_Project/
├── backend/
│   ├── app/
│   │   ├── main.py                # FastAPI Application routing logic (API Layer for PA#0 frontend)
│   │   ├── core/
│   │   │   └── minicrypt.py       # (formerly pa_combined.py) Central Core Crypto implementation definitions
│   ├── scripts/
│   │   └── demos.py               # Phase 2 Executable tests: NIST math, IND-CPA Games, Attacks, Demos
│   ├── requirements.txt           # Standard backend dependencies
│   └── tests/                     # Reserved for further module testing implementations
├── frontend/
│   └── index.html                 # Phase 4 React UI (CDN-based) Web Visualizer
└── README.md
```

## Supported Logic Configurations

**Forward Reductions (Source → Target):**
*   PA#1: OWF $\rightarrow$ PRG
*   PA#2: PRG $\rightarrow$ PRF (GGM Binary Tree)
*   PA#3: PRF $\rightarrow$ CPA-Secure Encryption (Encrypt-then-PRF)
*   PA#4: PRF $\rightarrow$ CBC, OFB, and CTR Mode Mappings
*   PA#5: PRF $\rightarrow$ MAC (CBC-MAC structure)
*   PA#6: CPA + MAC $\rightarrow$ CCA-Secure Encryption (Encrypt-then-MAC)
*   PA#7: Fixed-Length Compression $\rightarrow$ Variable Hash (Merkle-Damgård)
*   PA#8: DLP Group $\rightarrow$ CRHF (Collision Resistant Hash Function)
*   PA#10: CRHF $\rightarrow$ HMAC $\Rightarrow$ CCA-Secure Encryption

**Backward / Bidirectional Equivalences:**
*   PA#1: PRG $\rightarrow$ OWF  [$f(s) = G(s)$]
*   PA#2: PRF $\rightarrow$ PRG  [$G(s) = F_s(0^n) || F_s(1^n)$]
*   PA#5: MAC $\rightarrow$ PRF 
*   PA#10: MAC $\rightarrow$ CRHF [$h'(cv, block) = HMAC_k(cv||block)$]

## Setup & Execution Steps

### 1. Terminal / Local Environment Setup
Before launching the backend framework, instantiate a clean virtual environment and load the requirements logic.

```sh
cd backend
python -m venv venv

# Windows Activate
.\venv\Scripts\activate

# Linux / Mac Activate
# source venv/bin/activate

pip install -r requirements.txt
```

### 2. Execution - Phase 2 Demonstration Modules
Verify the baseline mathematical tests, games, and security failure evaluations (Naive vs. Floyd collisions) locally natively strictly via the command line:

```sh
cd backend
python scripts/demos.py
```
*(This triggers empirical NIST frequency mapping, indistinguishability query setups natively, and collision propagation logs outputs directly.)*

### 3. Execution - Initializing the API Layer
To prepare for web connectivity (The PA #0 mapping logic API):

```sh
cd backend
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```
Navigate your browser to `http://localhost:8000/docs` to natively interact with the Swagger visual representations representing standard primitive mappings.

### 4. Phase 4 - Exploring the Visualized Graphic Node Target Path API Map
With the Uvicorn terminal actively spinning locally, spin up the React frontend.
As `npm` is structurally absent contextually on this OS execution build tier natively, Phase 4 React logic was structurally engineered deliberately via natively embedded React+Babel CDN structures bound mathematically via raw HTML.

Simply open the file directly in any modern browser context natively without any local webserver:
1. Open Chrome, Firefox, or Edge.
2. Select **File > Open File...** (or press Ctrl+O / Cmd+O).
3. Navigate to and open `frontend/index.html`.

You can now interact with the logical nodes, swap primitives for bidirectional mathematical proofs, and execute real encryption queries against the backend via the "Live Data Component."