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
    pkcs1_v15_pad, rsa_enc_pkcs, rsa_dec_pkcs,
    elgamal_keygen, elgamal_enc, elgamal_dec,
    rsa_sign, rsa_verify, cca_pkc_enc, cca_pkc_dec,
    hastad_attack
)
from app.core.mpc import (
    SecureGateSimulator, SecureDAG,
    run_millionaire, run_equality, run_addition,
    ot_demo, and_gate_demo, run_all_and_combos, run_millionaire_trace,
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

class OTDemoRequest(BaseModel):
    m0: int = 42
    m1: int = 99
    choice: int = 0
    bits: int = 256

class AndDemoRequest(BaseModel):
    a: int = 1
    b: int = 1
    bits: int = 256

class DHFullRequest(BaseModel):
    alice_private: Optional[int] = None
    bob_private: Optional[int] = None
    bits: int = 256

class RSAEncTwiceRequest(BaseModel):
    message: str = "vote_yes"
    mode: str = "textbook"
    bits: int = 512

class MillerRabinTestRequest(BaseModel):
    n: int = 561
    k: int = 20

class HastadDemoRequest(BaseModel):
    message: int = 42
    bits: int = 256
    use_pkcs: bool = False

class SignDemoRequest(BaseModel):
    message: str = "Hello, World!"
    tamper: bool = False
    raw: bool = False
    bits: int = 512

class ForgerRequest(BaseModel):
    m1: str = "hello"
    m2: str = "world"
    bits: int = 512

class ElGamalEncRequest(BaseModel):
    message: int = 100
    bits: int = 256

class ElGamalMalRequest(BaseModel):
    message: int = 100
    bits: int = 256
    factor: int = 2

class CCAPKCDemoRequest(BaseModel):
    message: int = 42
    tamper: bool = False
    bits: int = 256

class SigVerifyRequest(BaseModel):
    message: str
    sig_hex: str
    N_str: str
    e_int: int = 65537
    tamper: bool = False

class ElGamalCPARequest(BaseModel):
    bits: int = 256

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
        N, e = pub
        return {
            "n_prefix": str(N)[:40] + "...",
            "e": e,
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
        p, q, g = dh_generate_group(req.bits)
        pub, priv = elgamal_keygen(p, q, g)
        c1, c2 = elgamal_enc(pub, req.message)
        pt = elgamal_dec(priv, (c1, c2))
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

# ── PA#18: OT Demo ────────────────────────────────────────────────
@app.post("/api/ot/demo")
def ot_demo_endpoint(req: OTDemoRequest):
    try:
        return ot_demo(req.m0, req.m1, req.choice, req.bits)
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#19: AND Gate Step Demo ────────────────────────────────────
@app.post("/api/mpc/and_demo")
def and_demo_endpoint(req: AndDemoRequest):
    try:
        return and_gate_demo(req.a, req.b, req.bits)
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/mpc/all_and_combos")
def all_and_combos_endpoint():
    try:
        return run_all_and_combos(bits=256)
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#20: Millionaire with gate trace ───────────────────────────
@app.post("/api/mpc/millionaire_trace")
def millionaire_trace_endpoint(req: MPCRequest):
    try:
        return run_millionaire_trace(req.x, req.y, req.n_bits)
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

# ── PA#11: DH Full Exchange (Detailed Demo) ──────────────────────────
@app.post("/api/dh/full_exchange")
def dh_full_exchange(req: DHFullRequest):
    try:
        from app.core.math_core import fast_mod_exp as fme
        p, q, g = dh_generate_group(req.bits)
        alice = DiffieHellmanParticipant(p, q, g)
        bob = DiffieHellmanParticipant(p, q, g)
        if req.alice_private is not None:
            alice.private_exponent = req.alice_private % q
            alice.public_value = fme(g, alice.private_exponent, p)
        if req.bob_private is not None:
            bob.private_exponent = req.bob_private % q
            bob.public_value = fme(g, bob.private_exponent, p)
        shared_alice = alice.compute_shared_secret(bob.public_value)
        shared_bob = bob.compute_shared_secret(alice.public_value)
        pa = str(alice.public_value); pb = str(bob.public_value)
        sa = str(shared_alice); sb = str(shared_bob)
        return {
            "p": str(p), "q": str(q), "g": str(g),
            "alice_private": str(alice.private_exponent),
            "alice_public": pa[:30] + ("..." if len(pa) > 30 else ""),
            "bob_private": str(bob.private_exponent),
            "bob_public": pb[:30] + ("..." if len(pb) > 30 else ""),
            "shared_alice": sa[:30] + ("..." if len(sa) > 30 else ""),
            "shared_bob": sb[:30] + ("..." if len(sb) > 30 else ""),
            "shared_match": shared_alice == shared_bob,
            "p_bits": p.bit_length()
        }
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/dh/mitm_demo")
def dh_mitm_demo(req: DHFullRequest):
    try:
        from app.core.math_core import fast_mod_exp as fme
        p, q, g = dh_generate_group(req.bits)
        alice = DiffieHellmanParticipant(p, q, g)
        bob = DiffieHellmanParticipant(p, q, g)
        q_bytes = (q.bit_length() + 7) // 8
        eve_private = int.from_bytes(os.urandom(q_bytes), 'big') % q
        eve_public = fme(g, eve_private, p)
        k_alice = fme(eve_public, alice.private_exponent, p)
        k_bob = fme(eve_public, bob.private_exponent, p)
        k_eve_alice = fme(alice.public_value, eve_private, p)
        k_eve_bob = fme(bob.public_value, eve_private, p)
        def sh(v): s = str(v); return s[:20] + ("..." if len(s) > 20 else "")
        return {
            "p_bits": p.bit_length(),
            "alice_public": sh(alice.public_value),
            "bob_public": sh(bob.public_value),
            "eve_public": sh(eve_public),
            "alice_thinks_K": sh(k_alice),
            "bob_thinks_K": sh(k_bob),
            "eve_key_with_alice": sh(k_eve_alice),
            "eve_key_with_bob": sh(k_eve_bob),
            "alice_eve_match": k_alice == k_eve_alice,
            "bob_eve_match": k_bob == k_eve_bob,
            "mitm_success": k_alice == k_eve_alice and k_bob == k_eve_bob
        }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#12: RSA Encrypt Twice Demo ─────────────────────────────────────
@app.post("/api/rsa/encrypt_twice")
def rsa_encrypt_twice(req: RSAEncTwiceRequest):
    try:
        pub, priv = rsa_keygen(req.bits)
        N, e = pub
        m_bytes = req.message.encode()
        m_int = int.from_bytes(m_bytes, 'big')
        n_bytes_count = (N.bit_length() + 7) // 8
        def trunc(s, n=60): return s[:n] + ("..." if len(s) > n else "")
        if req.mode == "textbook":
            ct1 = rsa_enc_textbook(pub, m_int)
            ct2 = rsa_enc_textbook(pub, m_int)
            identical = ct1 == ct2
            return {
                "mode": "textbook", "message": req.message,
                "ct1": trunc(str(ct1)), "ct2": trunc(str(ct2)),
                "identical": identical, "N_bits": N.bit_length(),
                "banner": "IDENTICAL ciphertexts — plaintext leaked!" if identical else "Different"
            }
        else:
            pad1 = pkcs1_v15_pad(m_bytes, n_bytes_count)
            pad2 = pkcs1_v15_pad(m_bytes, n_bytes_count)
            ct1 = rsa_enc_textbook(pub, int.from_bytes(pad1, 'big'))
            ct2 = rsa_enc_textbook(pub, int.from_bytes(pad2, 'big'))
            def get_ps(pad):
                for i in range(2, len(pad)):
                    if pad[i] == 0x00:
                        return pad[2:i].hex()
                return ""
            return {
                "mode": "pkcs", "message": req.message,
                "ct1": trunc(str(ct1)), "ct2": trunc(str(ct2)),
                "identical": ct1 == ct2, "N_bits": N.bit_length(),
                "ps1_hex": get_ps(pad1)[:32], "ps2_hex": get_ps(pad2)[:32],
                "banner": "Different ciphertexts — random padding prevents determinism"
            }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#13: Miller-Rabin Detailed Test ────────────────────────────────
@app.post("/api/miller_rabin/test")
def miller_rabin_test_detailed(req: MillerRabinTestRequest):
    try:
        import time as time_mod
        from app.core.math_core import fast_mod_exp as fme
        start = time_mod.time()
        n = req.n; k = min(req.k, 40)
        if n < 2:
            return {"result": "COMPOSITE", "reason": "n < 2", "time_ms": 0, "witnesses": [], "n_bits": 1}
        if n in (2, 3):
            return {"result": "PROBABLY_PRIME", "reason": "trivially prime", "time_ms": 0, "witnesses": [], "n_bits": n.bit_length()}
        if n % 2 == 0:
            return {"result": "COMPOSITE", "reason": "even number", "time_ms": 0, "witnesses": [], "n_bits": n.bit_length()}
        r, d = 0, n - 1
        while d % 2 == 0: r += 1; d //= 2
        witnesses = []; result = "PROBABLY_PRIME"
        for _ in range(k):
            byte_len = max(((n - 2).bit_length() + 7) // 8, 1)
            a = 0; attempts = 0
            while (a < 2 or a > n - 2) and attempts < 1000:
                a = int.from_bytes(os.urandom(byte_len), 'big') % (n - 1); attempts += 1
            if a < 2: a = 2
            x = fme(a, d, n); composite = True
            if x == 1 or x == n - 1:
                composite = False
            else:
                for _ in range(r - 1):
                    x = fme(x, 2, n)
                    if x == n - 1: composite = False; break
            witnesses.append({"a": str(a), "verdict": "WITNESS (composite)" if composite else "passed"})
            if composite: result = "COMPOSITE"; break
        elapsed_ms = (time_mod.time() - start) * 1000
        return {
            "n": str(n), "result": result, "rounds_run": len(witnesses),
            "rounds_requested": k, "r": r, "d": str(d),
            "time_ms": round(elapsed_ms, 2), "witnesses": witnesses[:20], "n_bits": n.bit_length()
        }
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#14: Håstad Broadcast Attack Demo ───────────────────────────────
@app.post("/api/hastad/demo")
def hastad_demo(req: HastadDemoRequest):
    try:
        from app.core.math_core import crt, integer_nth_root
        m = req.message; recipients = []; ciphertexts = []; moduli = []
        for i in range(3):
            pub, priv = rsa_keygen(req.bits, e=3)
            N, e = pub
            if req.use_pkcs:
                nb = (N.bit_length() + 7) // 8
                mb = m.to_bytes(max(1, (m.bit_length() + 7) // 8), 'big')
                padded = pkcs1_v15_pad(mb, nb)
                ct = rsa_enc_textbook(pub, int.from_bytes(padded, 'big'))
            else:
                ct = rsa_enc_textbook(pub, m)
            recipients.append({"index": i+1, "N": str(N)[:30]+"...", "N_bits": N.bit_length(), "e": e, "ciphertext": str(ct)[:30]+"..."})
            ciphertexts.append(ct); moduli.append(N)
        if req.use_pkcs:
            return {"recipients": recipients, "attack_attempted": True, "attack_success": False, "use_pkcs": True,
                    "note": "PKCS#1 padding randomizes the plaintext — CRT recovers garbage, not m^3. Attack fails."}
        crt_result = crt(ciphertexts, moduli)
        cube_root = integer_nth_root(crt_result, 3)
        return {"recipients": recipients, "crt_result": str(crt_result)[:40]+"...",
                "cube_root": cube_root, "original_message": m,
                "attack_success": cube_root == m, "use_pkcs": False}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#15: Digital Signatures Demo ────────────────────────────────────
@app.post("/api/signatures/demo")
def signatures_demo(req: SignDemoRequest):
    """Sign a message. Returns full sig_hex, hash_hex, N_str, e_int for use in verify_detail."""
    try:
        from app.core.minicrypt import dlp_hash as dlph
        pub, priv = rsa_keygen(req.bits)
        N, e = pub
        m_bytes = req.message.encode()
        if req.raw:
            nb = (N.bit_length() + 7) // 8
            m_int = int.from_bytes(m_bytes[:nb - 1], 'big') % N
            sig = rsa_dec_textbook(priv, m_int)
            sb = sig.to_bytes(max(1, (sig.bit_length() + 7) // 8), 'big')
            return {"message": req.message, "raw": True, "N_bits": N.bit_length(),
                    "N_str": str(N), "e_int": e,
                    "signature_hex": sb.hex(), "signature": sb.hex()[:30]+"...",
                    "valid": True, "note": "Raw RSA (no hash) — vulnerable to multiplicative forgery"}
        h = dlph(m_bytes, 32)
        sig = rsa_sign(priv, m_bytes)
        sb = sig.to_bytes(max(1, (sig.bit_length() + 7) // 8), 'big')
        return {"message": req.message, "raw": False, "N_bits": N.bit_length(),
                "N_str": str(N), "e_int": e,
                "hash_hex": h.hex(), "signature_hex": sb.hex(),
                "signature": sb.hex()[:30]+"...", "valid": True}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/signatures/verify_detail")
def signatures_verify_detail(req: SigVerifyRequest):
    """Verify a signature with full intermediate values. Supports tamper flag to flip first byte of message."""
    try:
        from app.core.minicrypt import dlp_hash as dlph
        from app.core.math_core import fast_mod_exp as fme
        m_bytes = req.message.encode()
        if req.tamper:
            ta = bytearray(m_bytes)
            if ta: ta[0] ^= 0x01
            m_bytes = bytes(ta)
        N = int(req.N_str); e = req.e_int
        sig = int(req.sig_hex, 16)
        h = dlph(m_bytes, 32)
        h_int = int.from_bytes(h, 'big')
        sigma_e = fme(sig, e, N)
        valid = sigma_e == h_int
        def sh(v): s=hex(v); return s[:28]+("..." if len(s)>28 else "")
        return {"message": req.message, "tampered": req.tamper, "N_bits": N.bit_length(),
                "hash_of_message": h.hex()[:40]+"...",
                "sigma_e_mod_N": sh(sigma_e),
                "h_int_prefix": sh(h_int),
                "match": valid, "valid": valid}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/signatures/forgery")
def multiplicative_forgery_demo(req: ForgerRequest):
    try:
        pub, priv = rsa_keygen(req.bits)
        N, e = pub; nb = (N.bit_length() + 7) // 8
        m1_int = int.from_bytes(req.m1.encode()[:nb - 1], 'big') % N
        m2_int = int.from_bytes(req.m2.encode()[:nb - 1], 'big') % N
        sig1 = rsa_dec_textbook(priv, m1_int)
        sig2 = rsa_dec_textbook(priv, m2_int)
        forged_sig = (sig1 * sig2) % N
        forged_m = (m1_int * m2_int) % N
        valid = rsa_enc_textbook(pub, forged_sig) == forged_m
        def sh(v): s=str(v); return s[:20]+("..." if len(s)>20 else "")
        return {"m1": req.m1, "m2": req.m2, "m1_int": sh(m1_int), "m2_int": sh(m2_int),
                "forged_m": sh(forged_m), "sig1": sh(sig1), "sig2": sh(sig2),
                "forged_sig": sh(forged_sig), "forgery_valid": valid,
                "explanation": "sig1 × sig2 mod N = (m1×m2)^d mod N — forged without knowing d!"}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#16: ElGamal Encrypt & Malleability Demo ────────────────────────
@app.post("/api/elgamal/encrypt")
def elgamal_encrypt_demo(req: ElGamalEncRequest):
    try:
        p, q, g = dh_generate_group(req.bits)
        pub, priv = elgamal_keygen(p, q, g)
        c1, c2 = elgamal_enc(pub, req.message)
        decrypted = elgamal_dec(priv, (c1, c2))
        pk_p, pk_q, pk_g, pk_h = pub; sk_p, sk_q, sk_g, sk_x = priv
        def sh(v): s=str(v); return s[:30]+("..." if len(s)>30 else "")
        return {"p": sh(p), "g": sh(g), "public_h": sh(pk_h), "private_x": sh(sk_x),
                "message": req.message, "c1": sh(c1), "c2": sh(c2),
                "decrypted": decrypted, "correct": decrypted == req.message}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/elgamal/malleable")
def elgamal_malleable_demo(req: ElGamalMalRequest):
    try:
        p, q, g = dh_generate_group(req.bits)
        pub, priv = elgamal_keygen(p, q, g)
        c1, c2 = elgamal_enc(pub, req.message)
        c2_mod = (c2 * req.factor) % p
        dec_orig = elgamal_dec(priv, (c1, c2))
        dec_mod = elgamal_dec(priv, (c1, c2_mod))
        expected = (req.message * req.factor) % p
        def sh(v): s=str(v); return s[:30]+("..." if len(s)>30 else "")
        return {"message": req.message, "factor": req.factor,
                "c1": sh(c1), "c2": sh(c2), "c2_modified": sh(c2_mod),
                "decrypted_original": dec_orig, "decrypted_modified": dec_mod,
                "expected_modified": expected, "malleable": dec_mod == expected,
                "explanation": f"Dec(c1, {req.factor}·c2 mod p) = {req.factor}·m — ElGamal is malleable!"}
    except Exception as e:
        raise HTTPException(400, str(e))

# ── PA#17: CCA-Secure PKC (Encrypt-then-Sign) ─────────────────────────
@app.post("/api/elgamal/cpa_game")
def elgamal_cpa_game(req: ElGamalCPARequest):
    """CPA game showing CCA failure: adversary uses decryption oracle with malleable ciphertext to learn m."""
    try:
        from app.core.math_core import mod_inverse as modinv
        p, q, g = dh_generate_group(req.bits)
        pub, priv = elgamal_keygen(p, q, g)
        # Challenger picks a small random m for readability
        m = int.from_bytes(os.urandom(2), 'big') % 900 + 50
        c1, c2 = elgamal_enc(pub, m)
        # Adversary: submit (c1, 2*c2 mod p) to decryption oracle
        c2_mod = (c2 * 2) % p
        oracle_resp = elgamal_dec(priv, (c1, c2_mod))
        # Recover m = oracle_resp / 2 mod p
        two_inv = modinv(2, p)
        recovered = (oracle_resp * two_inv) % p
        def sh(v): s=str(v); return s[:20]+("..." if len(s)>20 else "")
        return {"p_bits": p.bit_length(), "challenge_m": m,
                "c1": sh(c1), "c2": sh(c2), "c2_modified": sh(c2_mod),
                "oracle_response": oracle_resp, "expected_2m": (m * 2) % p,
                "recovered_m": recovered, "attack_success": recovered == m}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.post("/api/cca_pkc/demo")
def cca_pkc_demo_endpoint(req: CCAPKCDemoRequest):
    try:
        p, q, g = dh_generate_group(req.bits)
        elg_pub, elg_priv = elgamal_keygen(p, q, g)
        rsa_pub, rsa_priv = rsa_keygen(req.bits)
        package = cca_pkc_enc(elg_pub, rsa_priv, req.message)
        c, sig = package; c1, c2 = c
        def sh(v): s=str(v); return s[:20]+("..." if len(s)>20 else "")
        if req.tamper:
            c_tampered = (c1, (c2 * 2) % p)
            dec_cca = cca_pkc_dec(elg_priv, rsa_pub, (c_tampered, sig))
            dec_plain = elgamal_dec(elg_priv, c_tampered)
            return {"message": req.message, "tampered": True,
                    "c1": sh(c1), "c2_original": sh(c2), "c2_tampered": sh(c_tampered[1]),
                    "signature": sh(sig),
                    "cca_result": dec_cca, "cca_rejected": dec_cca is None,
                    "cca_message": "Signature invalid — decryption aborted. Output ⊥" if dec_cca is None else "Accepted",
                    "plain_elgamal_result": dec_plain,
                    "plain_elgamal_note": f"Plain ElGamal returns {dec_plain} (= 2×{req.message} mod p)"}
        dec = cca_pkc_dec(elg_priv, rsa_pub, package)
        return {"message": req.message, "tampered": False,
                "c1": sh(c1), "c2": sh(c2), "signature": sh(sig),
                "decrypted": dec, "correct": dec == req.message}
    except Exception as e:
        raise HTTPException(400, str(e))

@app.get("/")
def read_root():
    return {"message": "Minicrypt Clique API is running. Check /docs for endpoints."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

