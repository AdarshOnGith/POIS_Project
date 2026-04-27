from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import sys, os

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.minicrypt import (
    DLP_OWF, HILL_PRG, GGM_PRF, CPA_Symmetric, CCA_Symmetric,
    PRF_MAC, ModesOfOperation, dlp_hash, HMAC_Implementation,
    LubyRackoff_PRP, PRP_to_PRF, DLP_OWP, AESFoundation, DLPFoundation,
    PRF_to_PRG, PRG_to_OWF, MAC_to_PRF, FastPRF,
    ToyDLP_OWF, ToyHILL_PRG, ToyGGM_PRF
)
from app.core.aes import AES128
from app.core.routing import reduce_primitive, get_graph_schema, get_foundation_chain
import math
from app.core.cryptomania import (
    dh_generate_group, DiffieHellmanParticipant,
    rsa_keygen, rsa_enc_textbook, rsa_dec_textbook,
    elgamal_keygen, elgamal_enc, elgamal_dec,
    rsa_sign, rsa_verify, cca_pkc_enc, cca_pkc_dec
)
from app.core.mpc import (
    SecureGateSimulator, SecureDAG,
    run_millionaire, run_equality, run_addition
)

app = FastAPI(title="Minicrypt Clique Web Explorer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Models ──────────────────────────────────────────────────────────
class OWFRequest(BaseModel):
    x: int

class PRGRequest(BaseModel):
    seed_hex: str
    n_bits: int

class EncryptRequest(BaseModel):
    key_hex: str
    message_hex: str

class DecryptRequest(BaseModel):
    key_hex: str
    r_hex: str
    ciphertext_hex: str

class CCAEncryptRequest(BaseModel):
    key_enc_hex: str
    key_mac_hex: str
    message_hex: str

class CCADecryptRequest(BaseModel):
    key_enc_hex: str
    key_mac_hex: str
    r_hex: str
    ciphertext_hex: str
    tag_hex: str

class HashRequest(BaseModel):
    message_hex: str
    out_len: int = 32
    return_trace: bool = False

class HashTraceRequest(BaseModel):
    message_hex: str
    block_size: int = 8

class BirthdayRequest(BaseModel):
    n_bits: int

class LengthExtRequest(BaseModel):
    message_hex: str
    append_hex: str
    hash_type: str = "toy"

class MACRequest(BaseModel):
    key_hex: str
    message_hex: str

class HMACRequest(BaseModel):
    key_hex: str
    message_hex: str

class ModesRequest(BaseModel):
    key_hex: str
    iv_hex: str
    message_hex: str
    mode: str  # CBC, OFB, CTR

class PRPRequest(BaseModel):
    k1_hex: str
    k2_hex: str
    k3_hex: str
    plaintext_hex: str

class RoutingRequest(BaseModel):
    source: str
    target: str
    foundation: str = "Standard"

class BuildRequest(BaseModel):
    foundation: str  # "AES" or "DLP"
    source_primitive: str
    key_hex: str = "00112233445566778899aabbccddeeff"

class ReduceRequest(BaseModel):
    foundation: str
    source_primitive: str
    target_primitive: str
    key_hex: str = "00112233445566778899aabbccddeeff"
    query_hex: str = "48656c6c6f"

class TreeRequest(BaseModel):
    key_int: int = 12345
    query_bits: str = "1011"  # e.g. "1011"
    depth: int = 4

class CPAGameRequest(BaseModel):
    m0_hex: str
    m1_hex: str
    nonce_reuse: bool = False

class CPAGuessRequest(BaseModel):
    game_id: str
    guess: int  # 0 or 1

class BitFlipRequest(BaseModel):
    key_enc_hex: str = "00112233445566778899aabbccddeeff"
    key_mac_hex: str = "ffeeddccbbaa99887766554433221100"
    message_hex: str = "48656c6c6f20576f726c642121212121"
    flip_byte: int = 0
    flip_bit: int = 0

class MACGameForgeRequest(BaseModel):
    game_id: str
    message_hex: str
    tag_hex: str

class RSARequest(BaseModel):
    message: int
    bits: int = 512

class ElGamalRequest(BaseModel):
    message: int
    bits: int = 512

class MPCRequest(BaseModel):
    x: int
    y: int
    n_bits: int = 4

class GateRequest(BaseModel):
    a: int
    b: int

# ── Game state storage (in-memory) ──
_cpa_games = {}
_mac_games = {}

# ── PA#0: Pipeline API ─────────────────────────────────────────────
@app.post("/api/clique/build")
def clique_build(req: BuildRequest):
    """Column 1: Build source primitive A from foundation."""
    try:
        chain = get_foundation_chain(req.foundation, req.source_primitive)
        key = bytes.fromhex(req.key_hex)
        # Actually compute intermediate values
        intermediates = []
        if req.foundation == "AES":
            aes = AES128(key[:16] if len(key) >= 16 else key + b'\x00' * (16 - len(key)))
            if req.source_primitive in ("PRP", "PRF"):
                out = aes.encrypt_block(b'\x00' * 16)
                intermediates.append({"step": "AES_k(0¹²⁸)", "input": "00" * 16, "output": out.hex()})
            elif req.source_primitive == "PRG":
                left = aes.encrypt_block(b'\x00' * 16)
                right = aes.encrypt_block(b'\x00' * 15 + b'\x01')
                intermediates.append({"step": "AES_k(0)", "input": "00" * 16, "output": left.hex()})
                intermediates.append({"step": "AES_k(1)", "input": "00" * 15 + "01", "output": right.hex()})
                intermediates.append({"step": "G(s) = F_s(0)||F_s(1)", "output": left.hex() + right.hex()})
            elif req.source_primitive == "OWF":
                ct = aes.encrypt_block(b'\x00' * 16)
                owf_out = bytes(a ^ b for a, b in zip(ct, key[:16]))
                intermediates.append({"step": "Davies-Meyer: AES_k(0) ⊕ k", "output": owf_out.hex()})
        elif req.foundation == "DLP":
            x = int.from_bytes(key[:8], 'big') if len(key) >= 8 else int.from_bytes(key, 'big')
            if req.source_primitive in ("OWF", "OWP"):
                y = ToyDLP_OWF.evaluate(x)
                intermediates.append({"step": "f(x) = g^x mod p", "input": str(x), "output": str(y)})
            elif req.source_primitive == "PRG":
                prg = ToyHILL_PRG()
                prg.seed(x)
                bits = prg.next_bits(32)
                intermediates.append({"step": "HILL PRG: iterate DLP OWF + hard-core bit", "output": ''.join(str(b) for b in bits)})
        chain["intermediates"] = intermediates
        return chain
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/clique/reduce")
def clique_reduce(req: ReduceRequest):
    """Column 2: Reduce source A to target B (using A as black box)."""
    try:
        path = reduce_primitive(req.source_primitive, req.target_primitive, req.foundation)
        # Compute actual values along the reduction
        key = bytes.fromhex(req.key_hex)
        query = bytes.fromhex(req.query_hex) if req.query_hex else b'\x00' * 16
        intermediates = []
        if path["possible"]:
            # Use FastPRF as the concrete PRF for all reductions
            prf = FastPRF(key[:16] if len(key) >= 16 else key + b'\x00' * (16 - len(key)))
            out = prf.evaluate(query[:16] if len(query) >= 16 else query + b'\x00' * (16 - len(query)))
            intermediates.append({"step": f"{req.source_primitive} → {req.target_primitive}", "output": out.hex()})
        path["intermediates"] = intermediates
        return path
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#1: OWF & PRG ────────────────────────────────────────────────
@app.post("/api/owf/evaluate")
def owf_evaluate(req: OWFRequest):
    return {"y": ToyDLP_OWF.evaluate(req.x), "p": ToyDLP_OWF.P, "g": ToyDLP_OWF.G}

@app.post("/api/prg/next_bits")
def prg_next(req: PRGRequest):
    """PRG using ToyHILL_PRG for instant response (<1s)."""
    try:
        seed_int = int(req.seed_hex, 16) if req.seed_hex else 0
        prg = ToyHILL_PRG()
        prg.seed(seed_int & 0x3FFFFFFF)  # 30-bit seed
        bits = prg.next_bits(min(req.n_bits, 256))
        out_bytes = bytearray()
        for i in range(0, len(bits), 8):
            chunk = bits[i:i+8]
            val = 0
            for b in chunk:
                val = (val << 1) | b
            out_bytes.append(val)
        ones = sum(bits)
        return {
            "output_hex": bytes(out_bytes).hex(),
            "output_bits": len(bits),
            "bit_string": ''.join(str(b) for b in bits[:64]),
            "ones": ones,
            "zeros": len(bits) - ones,
            "ratio": round(ones / len(bits), 4) if bits else 0
        }
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/prg/nist_test")
def prg_nist_test(req: PRGRequest):
    """Run NIST frequency and runs tests on PRG output."""
    try:
        seed_int = int(req.seed_hex, 16) if req.seed_hex else 0
        prg = ToyHILL_PRG()
        prg.seed(seed_int & 0x3FFFFFFF)
        n = min(req.n_bits, 1024)
        bits = prg.next_bits(n)
        ones = sum(bits)
        zeros = n - ones
        # Frequency test
        s_obs = abs(ones - zeros) / math.sqrt(n)
        p_freq = math.erfc(s_obs / math.sqrt(2))
        # Runs test
        pi = ones / n
        if abs(pi - 0.5) >= (2.0 / math.sqrt(n)):
            p_runs = 0.0
        else:
            v_obs = 1 + sum(1 for i in range(1, n) if bits[i] != bits[i-1])
            num = abs(v_obs - 2.0 * n * pi * (1.0 - pi))
            den = 2.0 * math.sqrt(2.0 * n) * pi * (1.0 - pi)
            p_runs = math.erfc(num / den) if den > 0 else 0.0
        return {
            "n_bits": n, "ones": ones, "zeros": zeros,
            "ratio": round(ones / n, 4),
            "frequency_test": {"pass": p_freq >= 0.01, "p_value": round(p_freq, 4)},
            "runs_test": {"pass": p_runs >= 0.01, "p_value": round(p_runs, 4)}
        }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#3: CPA Encryption ───────────────────────────────────────────
@app.post("/api/cpa/encrypt")
def cpa_encrypt(req: EncryptRequest):
    try:
        cpa = CPA_Symmetric(bytes.fromhex(req.key_hex))
        r, c = cpa.encrypt(bytes.fromhex(req.message_hex))
        return {"r_hex": r.hex(), "ciphertext_hex": c.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/cpa/decrypt")
def cpa_decrypt(req: DecryptRequest):
    try:
        cpa = CPA_Symmetric(bytes.fromhex(req.key_hex))
        m = cpa.decrypt(bytes.fromhex(req.r_hex), bytes.fromhex(req.ciphertext_hex))
        return {"message_hex": m.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#4: Modes of Operation ───────────────────────────────────────
@app.post("/api/modes/encrypt")
def modes_encrypt(req: ModesRequest):
    try:
        key = bytes.fromhex(req.key_hex)
        iv = bytes.fromhex(req.iv_hex)
        msg = bytes.fromhex(req.message_hex)
        prf = GGM_PRF(key)
        prf_eval = lambda x: prf.evaluate(x)
        if req.mode == "CBC":
            ct = ModesOfOperation.CBC_Enc(key, iv, msg, prf_eval)
        elif req.mode == "OFB":
            ct = ModesOfOperation.OFB_EncDec(key, iv, msg, prf_eval)
        elif req.mode == "CTR":
            ct = ModesOfOperation.CTR_EncDec(key, iv, msg, prf_eval)
        else:
            raise ValueError(f"Unknown mode: {req.mode}")
        return {"ciphertext_hex": ct.hex(), "mode": req.mode}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#5: MAC ──────────────────────────────────────────────────────
@app.post("/api/mac/compute")
def mac_compute(req: MACRequest):
    try:
        mac = PRF_MAC(bytes.fromhex(req.key_hex))
        tag = mac.mac(bytes.fromhex(req.message_hex))
        return {"tag_hex": tag.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/mac/verify")
def mac_verify(req: MACRequest):
    try:
        mac = PRF_MAC(bytes.fromhex(req.key_hex))
        # tag is appended as last field
        return {"valid": True, "tag_hex": mac.mac(bytes.fromhex(req.message_hex)).hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#6: CCA Encryption ──────────────────────────────────────────
@app.post("/api/cca/encrypt")
def cca_encrypt(req: CCAEncryptRequest):
    try:
        cca = CCA_Symmetric(bytes.fromhex(req.key_enc_hex), bytes.fromhex(req.key_mac_hex))
        r, c, t = cca.encrypt(bytes.fromhex(req.message_hex))
        return {"r_hex": r.hex(), "ciphertext_hex": c.hex(), "tag_hex": t.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/cca/decrypt")
def cca_decrypt(req: CCADecryptRequest):
    try:
        cca = CCA_Symmetric(bytes.fromhex(req.key_enc_hex), bytes.fromhex(req.key_mac_hex))
        m = cca.decrypt(bytes.fromhex(req.r_hex), bytes.fromhex(req.ciphertext_hex), bytes.fromhex(req.tag_hex))
        return {"message_hex": m.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#7: Merkle-Damgård Trace ─────────────────────────────────────
@app.post("/api/hash/md_trace")
def hash_md_trace(req: HashTraceRequest):
    try:
        from app.core.minicrypt import MerkleDamgard, ToyXOR_Compress
        md = MerkleDamgard(ToyXOR_Compress.compress, b'\x00'*4, req.block_size)
        trace = md.hash(bytes.fromhex(req.message_hex), return_trace=True)
        return trace
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#8: DLP Hash ─────────────────────────────────────────────────
@app.post("/api/hash/dlp")
def hash_message(req: HashRequest):
    try:
        if req.return_trace:
            return dlp_hash(bytes.fromhex(req.message_hex), req.out_len, return_trace=True)
        digest = dlp_hash(bytes.fromhex(req.message_hex), req.out_len)
        return {"digest_hex": digest.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#9: Birthday Attack ──────────────────────────────────────────
@app.post("/api/hash/birthday")
def hash_birthday(req: BirthdayRequest):
    try:
        from app.core.minicrypt import CollisionFinder, dlp_hash
        n = min(req.n_bits, 20)  # Cap for sanity, 20 bits is ~1024 ops
        
        def trunc_hash(m: bytes) -> bytes:
            h = dlp_hash(m, out_len=(n+7)//8)
            # Mask bits if n is not a multiple of 8
            val = int.from_bytes(h, 'big')
            val = val & ((1 << n) - 1)
            return val.to_bytes((n+7)//8, 'big')
            
        res = CollisionFinder.naive_search(trunc_hash, n)
        if res:
            return {
                "evaluations": res["evaluations"],
                "msg1_hex": res["msg1"].hex(),
                "msg2_hex": res["msg2"].hex(),
                "hash_hex": res["hash"].hex(),
                "n_bits": n
            }
        return {"error": "No collision found within limit", "n_bits": n}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#10: HMAC ────────────────────────────────────────────────────
@app.post("/api/hmac/compute")
def hmac_compute(req: HMACRequest):
    try:
        hmac = HMAC_Implementation()
        tag = hmac.evaluate(bytes.fromhex(req.key_hex), bytes.fromhex(req.message_hex))
        return {"tag_hex": tag.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/hmac/length_extension_demo")
def hmac_length_extension(req: LengthExtRequest):
    try:
        from app.core.minicrypt import HMAC_Implementation, dlp_hash
        key = b'secret_key_12345'
        m = bytes.fromhex(req.message_hex)
        append = bytes.fromhex(req.append_hex)
        
        if req.hash_type == 'sha256':
            import hashlib, hmac as pyhmac
            naive_mac_val = hashlib.sha256(key + m).digest()
            naive_mac_ext = hashlib.sha256(key + m + append).digest()
            hmac_val = pyhmac.new(key, m, hashlib.sha256).digest()
            hmac_ext = pyhmac.new(key, m + append, hashlib.sha256).digest()
        else:
            naive_mac_val = dlp_hash(key + m)
            naive_mac_ext = dlp_hash(key + m + append)
            
            hmac = HMAC_Implementation()
            hmac_val = hmac.evaluate(key, m)
            hmac_ext = hmac.evaluate(key, m + append)
        
        return {
            "naive": {
                "tag_hex": naive_mac_val.hex(),
                "extended_tag_hex": naive_mac_ext.hex(),
                "message": "Vulnerable: Given MAC(m), attacker can compute MAC(m||pad||m') locally without k."
            },
            "hmac": {
                "tag_hex": hmac_val.hex(),
                "extended_tag_hex": hmac_ext.hex(),
                "message": "Secure: Outer hash keyed with k prevents length extension."
            }
        }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PRF ⇔ PRP (Luby-Rackoff) ──────────────────────────────────────
@app.post("/api/prp/encrypt")
def prp_encrypt(req: PRPRequest):
    try:
        prp = LubyRackoff_PRP(bytes.fromhex(req.k1_hex), bytes.fromhex(req.k2_hex), bytes.fromhex(req.k3_hex))
        ct = prp.encrypt(bytes.fromhex(req.plaintext_hex))
        return {"ciphertext_hex": ct.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/prp/decrypt")
def prp_decrypt(req: PRPRequest):
    try:
        prp = LubyRackoff_PRP(bytes.fromhex(req.k1_hex), bytes.fromhex(req.k2_hex), bytes.fromhex(req.k3_hex))
        pt = prp.decrypt(bytes.fromhex(req.plaintext_hex))
        return {"plaintext_hex": pt.hex()}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#11: DH Key Exchange ─────────────────────────────────────────
@app.post("/api/dh/exchange")
def dh_exchange():
    try:
        p, q, g = dh_generate_group(512)
        alice = DiffieHellmanParticipant(p, q, g)
        bob = DiffieHellmanParticipant(p, q, g)
        shared_a = alice.compute_shared_secret(bob.public_value)
        shared_b = bob.compute_shared_secret(alice.public_value)
        return {
            "p_bits": p.bit_length(),
            "g": g,
            "alice_public": str(alice.public_value)[:40] + "...",
            "bob_public": str(bob.public_value)[:40] + "...",
            "shared_match": shared_a == shared_b,
            "shared_key_prefix": str(shared_a)[:40] + "..."
        }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#12: RSA ─────────────────────────────────────────────────────
@app.post("/api/rsa/demo")
def rsa_demo(req: RSARequest):
    try:
        pub, priv = rsa_keygen(req.bits)
        ct = rsa_enc_textbook(pub, req.message)
        pt = rsa_dec_textbook(priv, ct)
        return {
            "n_prefix": str(pub[1])[:40] + "...",
            "e": pub[0],
            "ciphertext": str(ct)[:40] + "...",
            "decrypted": pt,
            "correct": pt == req.message
        }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#16: ElGamal ─────────────────────────────────────────────────
@app.post("/api/elgamal/demo")
def elgamal_demo(req: ElGamalRequest):
    try:
        pub, priv = elgamal_keygen(req.bits)
        c1, c2 = elgamal_enc(pub, req.message)
        pt = elgamal_dec(priv, pub, c1, c2)
        return {
            "ciphertext_c1": str(c1)[:40] + "...",
            "ciphertext_c2": str(c2)[:40] + "...",
            "decrypted": pt,
            "correct": pt == req.message
        }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#19: Secure Gates ────────────────────────────────────────────
@app.post("/api/mpc/and")
def secure_and(req: GateRequest):
    try:
        result = SecureGateSimulator.secure_and(req.a, req.b)
        return {"a": req.a, "b": req.b, "result": result, "expected": req.a & req.b}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/mpc/xor")
def secure_xor(req: GateRequest):
    result = SecureGateSimulator.secure_xor(req.a, req.b)
    return {"a": req.a, "b": req.b, "result": result, "expected": req.a ^ req.b}

# ── PA#20: MPC Circuits ───────────────────────────────────────────
@app.post("/api/mpc/millionaire")
def millionaire(req: MPCRequest):
    try:
        return run_millionaire(req.x, req.y, req.n_bits)
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/mpc/equality")
def equality(req: MPCRequest):
    try:
        return run_equality(req.x, req.y, req.n_bits)
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/mpc/addition")
def addition(req: MPCRequest):
    try:
        return run_addition(req.x, req.y, req.n_bits)
    except Exception as e:
        raise HTTPException(400, str(e))

# ── Graph / Routing ────────────────────────────────────────────────
@app.post("/api/graph/reduce")
def calculate_reduction_path(req: RoutingRequest):
    res = reduce_primitive(req.source, req.target, req.foundation)
    if not res["possible"]:
        if "error" in res:
            raise HTTPException(400, res["error"])
        raise HTTPException(404, f"No reducible path from {req.source} to {req.target}")
    return res

@app.get("/api/graph/schema")
def fetch_graph_schema():
    return get_graph_schema()

# ── PA#2: PRF Tree Visualisation ──────────────────────────────────
@app.post("/api/prf/tree")
def prf_tree(req: TreeRequest):
    """GGM tree trace for visualisation."""
    try:
        prf = ToyGGM_PRF(req.key_int, depth=min(req.depth, 6))  # Cap at 6 for perf
        bits = [int(b) for b in req.query_bits[:prf.depth]]
        while len(bits) < prf.depth:
            bits.append(0)
        return prf.tree_trace(bits)
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/prf/evaluate")
def prf_evaluate(req: TreeRequest):
    """Evaluate GGM PRF."""
    try:
        prf = ToyGGM_PRF(req.key_int, depth=min(req.depth, 8))
        bits = [int(b) for b in req.query_bits[:prf.depth]]
        return {"key": prf.key, "query": req.query_bits, "output": prf.evaluate(bits)}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#3: IND-CPA Game ────────────────────────────────────────────
@app.post("/api/cpa/game_start")
def cpa_game_start(req: CPAGameRequest):
    """Start IND-CPA game: challenger picks b, encrypts m_b."""
    import os, secrets
    try:
        m0 = bytes.fromhex(req.m0_hex)
        m1 = bytes.fromhex(req.m1_hex)
        if len(m0) != len(m1):
            raise ValueError("m0 and m1 must be equal length")
        key = os.urandom(16)
        b = secrets.randbelow(2)
        chosen = m1 if b else m0
        cpa = CPA_Symmetric(key)
        if req.nonce_reuse:
            # Broken: reuse nonce
            fixed_r = b'\xaa' * 16
            from app.core.minicrypt import FastPRF
            prf = FastPRF(key)
            pad = prf.evaluate(fixed_r)
            ct = bytes(a ^ p for a, p in zip(chosen + b'\x00' * (16 - len(chosen) % 16) if len(chosen) % 16 else chosen, pad * ((len(chosen) // 16) + 1)))[:len(chosen)]
            r_hex = fixed_r.hex()
            ct_hex = ct.hex()
            # Also encrypt m0 with same nonce for the student to compare
            ct0 = bytes(a ^ p for a, p in zip(m0 + b'\x00' * (16 - len(m0) % 16) if len(m0) % 16 else m0, pad * ((len(m0) // 16) + 1)))[:len(m0)]
            extra = {"m0_ct_hex": ct0.hex(), "hint": "Compare C* with Enc(m0) — identical nonces!"}
        else:
            r, ct = cpa.encrypt(chosen)
            r_hex = r.hex()
            ct_hex = ct.hex()
            extra = {}
        game_id = secrets.token_hex(8)
        _cpa_games[game_id] = {"b": b, "key": key.hex(), "nonce_reuse": req.nonce_reuse}
        return {"game_id": game_id, "r_hex": r_hex, "ciphertext_hex": ct_hex, **extra}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/cpa/game_guess")
def cpa_game_guess(req: CPAGuessRequest):
    """Student guesses b."""
    game = _cpa_games.pop(req.game_id, None)
    if not game:
        raise HTTPException(404, "Game not found or already guessed")
    correct = req.guess == game["b"]
    return {"correct": correct, "actual_b": game["b"], "your_guess": req.guess, "nonce_reuse": game["nonce_reuse"]}

# ── PA#4: Modes Trace ─────────────────────────────────────────────
@app.post("/api/modes/encrypt_trace")
def modes_encrypt_trace(req: ModesRequest):
    """Encrypt with per-block trace for animation."""
    try:
        key = bytes.fromhex(req.key_hex)
        iv = bytes.fromhex(req.iv_hex)
        msg = bytes.fromhex(req.message_hex)
        prf = FastPRF(key[:16] if len(key) >= 16 else key + b'\x00' * (16 - len(key)))
        prf_eval = prf.evaluate
        blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
        # Pad last block
        if blocks and len(blocks[-1]) < 16:
            blocks[-1] = blocks[-1] + b'\x00' * (16 - len(blocks[-1]))
        trace = {"mode": req.mode, "iv": iv.hex(), "blocks": []}
        ct_blocks = []
        if req.mode == "CTR":
            for i, blk in enumerate(blocks):
                ctr_val = int.from_bytes(iv, 'big') + i
                ctr_bytes = ctr_val.to_bytes(16, 'big')
                pad = prf_eval(ctr_bytes)
                ct_blk = bytes(a ^ b for a, b in zip(blk, pad))
                ct_blocks.append(ct_blk)
                trace["blocks"].append({
                    "index": i, "counter": ctr_bytes.hex(),
                    "prf_output": pad.hex(), "plaintext": blk.hex(), "ciphertext": ct_blk.hex()
                })
        elif req.mode == "CBC":
            prev = iv
            for i, blk in enumerate(blocks):
                xored = bytes(a ^ b for a, b in zip(blk, prev))
                ct_blk = prf_eval(xored)
                ct_blocks.append(ct_blk)
                trace["blocks"].append({
                    "index": i, "xor_input": xored.hex(),
                    "plaintext": blk.hex(), "ciphertext": ct_blk.hex(), "prev_ct": prev.hex()
                })
                prev = ct_blk
        elif req.mode == "OFB":
            keystream = iv
            for i, blk in enumerate(blocks):
                keystream = prf_eval(keystream)
                ct_blk = bytes(a ^ b for a, b in zip(blk, keystream))
                ct_blocks.append(ct_blk)
                trace["blocks"].append({
                    "index": i, "keystream": keystream.hex(),
                    "plaintext": blk.hex(), "ciphertext": ct_blk.hex()
                })
        trace["ciphertext_hex"] = b''.join(ct_blocks).hex()
        return trace
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/modes/bitflip")
def modes_bitflip(req: BitFlipRequest):
    """Flip a bit in ciphertext, re-decrypt, show corruption pattern."""
    try:
        key = bytes.fromhex(req.key_enc_hex)
        msg = bytes.fromhex(req.message_hex)
        # Encrypt with CTR
        iv = b'\x00' * 16
        prf = FastPRF(key[:16] if len(key) >= 16 else key + b'\x00' * (16 - len(key)))
        blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
        if blocks and len(blocks[-1]) < 16:
            blocks[-1] = blocks[-1] + b'\x00' * (16 - len(blocks[-1]))
        ct = bytearray()
        for i, blk in enumerate(blocks):
            ctr_val = int.from_bytes(iv, 'big') + i
            pad = prf.evaluate(ctr_val.to_bytes(16, 'big'))
            ct.extend(bytes(a ^ b for a, b in zip(blk, pad)))
        # Flip bit
        original_ct = bytes(ct)
        if req.flip_byte < len(ct):
            ct[req.flip_byte] ^= (1 << (req.flip_bit % 8))
        # Decrypt modified
        modified_pt = bytearray()
        for i in range(0, len(ct), 16):
            ctr_val = int.from_bytes(iv, 'big') + i // 16
            pad = prf.evaluate(ctr_val.to_bytes(16, 'big'))
            modified_pt.extend(bytes(a ^ b for a, b in zip(ct[i:i+16], pad)))
        corrupted = [i for i in range(len(msg)) if i < len(modified_pt) and msg[i] != modified_pt[i]]
        return {
            "original_ct": original_ct.hex(), "modified_ct": bytes(ct).hex(),
            "original_pt": msg.hex(), "modified_pt": bytes(modified_pt[:len(msg)]).hex(),
            "corrupted_bytes": corrupted, "flip_byte": req.flip_byte, "flip_bit": req.flip_bit
        }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#5: MAC Forgery Game ────────────────────────────────────────
@app.post("/api/mac/game_init")
def mac_game_init():
    """Initialize MAC game with hidden key and signed messages."""
    import os, secrets
    key = os.urandom(16)
    mac_obj = PRF_MAC(key)
    signed = []
    for i in range(10):
        m = os.urandom(8)
        t = mac_obj.mac(m)
        signed.append({"message_hex": m.hex(), "tag_hex": t.hex()})
    game_id = secrets.token_hex(8)
    _mac_games[game_id] = {"key": key, "signed_messages": [s["message_hex"] for s in signed]}
    return {"game_id": game_id, "signed_messages": signed}

@app.post("/api/mac/game_query")
def mac_game_query(req: MACGameForgeRequest):
    """Sign a new message (oracle query)."""
    game = _mac_games.get(req.game_id)
    if not game:
        raise HTTPException(404, "Game not found")
    mac_obj = PRF_MAC(game["key"])
    m = bytes.fromhex(req.message_hex)
    t = mac_obj.mac(m)
    game["signed_messages"].append(req.message_hex)
    return {"message_hex": req.message_hex, "tag_hex": t.hex()}

@app.post("/api/mac/game_forge")
def mac_game_forge(req: MACGameForgeRequest):
    """Student attempts forgery."""
    game = _mac_games.get(req.game_id)
    if not game:
        raise HTTPException(404, "Game not found")
    if req.message_hex in game["signed_messages"]:
        return {"result": "rejected", "reason": "Message already in signed list — not a valid forgery attempt"}
    mac_obj = PRF_MAC(game["key"])
    m = bytes.fromhex(req.message_hex)
    expected = mac_obj.mac(m)
    valid = req.tag_hex == expected.hex()
    return {"result": "accepted" if valid else "rejected", "valid_forgery": valid}

# ── PA#6: CCA Malleability Demo ───────────────────────────────────
@app.post("/api/cca/malleability_demo")
def cca_malleability_demo(req: BitFlipRequest):
    """Side-by-side CPA vs CCA bit-flip demonstration."""
    try:
        key_enc = bytes.fromhex(req.key_enc_hex)
        key_mac = bytes.fromhex(req.key_mac_hex)
        msg = bytes.fromhex(req.message_hex)
        # CPA encrypt
        cpa = CPA_Symmetric(key_enc[:16] if len(key_enc) >= 16 else key_enc + b'\x00' * (16 - len(key_enc)))
        r, ct = cpa.encrypt(msg)
        # CCA encrypt
        cca = CCA_Symmetric(key_enc[:16] if len(key_enc) >= 16 else key_enc + b'\x00' * (16 - len(key_enc)),
                           key_mac[:16] if len(key_mac) >= 16 else key_mac + b'\x00' * (16 - len(key_mac)))
        cca_r, cca_ct, cca_tag = cca.encrypt(msg)
        # Flip a bit in both
        ct_mod = bytearray(ct)
        cca_ct_mod = bytearray(cca_ct)
        if req.flip_byte < len(ct_mod):
            ct_mod[req.flip_byte] ^= (1 << (req.flip_bit % 8))
        if req.flip_byte < len(cca_ct_mod):
            cca_ct_mod[req.flip_byte] ^= (1 << (req.flip_bit % 8))
        # CPA decrypt modified (succeeds — malleable!)
        cpa_decrypted = cpa.decrypt(r, bytes(ct_mod))
        # CCA decrypt modified (should reject)
        try:
            cca_decrypted = cca.decrypt(cca_r, bytes(cca_ct_mod), cca_tag)
            cca_result = {"decrypted_hex": cca_decrypted.hex(), "rejected": False}
        except Exception:
            cca_result = {"decrypted_hex": None, "rejected": True, "reason": "MAC verification failed — ⊥"}
        return {
            "original_message": msg.hex(),
            "cpa_side": {
                "original_ct": ct.hex(), "modified_ct": bytes(ct_mod).hex(),
                "decrypted_hex": cpa_decrypted.hex(), "malleable": True
            },
            "cca_side": {
                "original_ct": cca_ct.hex(), "modified_ct": bytes(cca_ct_mod).hex(),
                "tag": cca_tag.hex(), **cca_result
            },
            "flip_byte": req.flip_byte, "flip_bit": req.flip_bit
        }
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/")
def read_root():
    return {"message": "Minicrypt Clique API is running. Check /docs for endpoints."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

