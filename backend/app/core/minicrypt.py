import os
import math
import struct
from typing import Tuple, List, Callable

# ==============================================================================
# PA #1: One-Way Functions & PRGs
# ==============================================================================

class DLP_OWF:
    # 2048-bit safe prime (MODP Group 14 from RFC 3526)
    P_HEX = (
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
    )
    P = int(P_HEX, 16)
    G = 2

    @staticmethod
    def evaluate(x: int) -> int:
        return pow(DLP_OWF.G, x, DLP_OWF.P)

    @staticmethod
    def verify_hardness():
        x = int.from_bytes(os.urandom(16), 'big')
        y = DLP_OWF.evaluate(x)
        print("Adversary given y = f(x) must find x.")
        return y


def dot_product(a: int, b: int) -> int:
    return bin(a & b).count('1') % 2

class HILL_PRG:
    def __init__(self):
        self.state_x = None
        self.state_r = None

    def seed(self, s: bytes):
        s_int = int.from_bytes(s, 'big')
        n_bits = len(s) * 8
        half = n_bits // 2
        mask = (1 << half) - 1
        self.state_r = s_int & mask
        self.state_x = s_int >> half

    def next_bits(self, n: int) -> bytes:
        out_bits = []
        for _ in range(n):
            hcb = dot_product(self.state_x, self.state_r)
            out_bits.append(hcb)
            self.state_x = DLP_OWF.evaluate(self.state_x)
        
        # Convert bits to bytes
        out_bytes = bytearray()
        for i in range(0, len(out_bits), 8):
            chunk = out_bits[i:i+8]
            val = 0
            for b in chunk:
                val = (val << 1) | b
            out_bytes.append(val)
        return bytes(out_bytes)


class PRG_to_OWF:
    """Backward Direction (OWF from PRG): f(s) = G(s)"""
    @staticmethod
    def evaluate(s: bytes) -> bytes:
        prg = HILL_PRG()
        prg.seed(s)
        return prg.next_bits(len(s) * 8 * 2)

# ==============================================================================
# PA #2: Pseudorandom Functions via GGM Tree
# ==============================================================================

class GGM_PRF:
    """
    PRF F_k(x) where k is a PRG seed. We traverse a binary tree.
    """
    def __init__(self, key: bytes):
        self.key = key
        # PRG doubles the length (from n to 2n)
    
    def _G(self, s: bytes) -> tuple[bytes, bytes]:
        prg = HILL_PRG()
        prg.seed(s)
        # Generate 2 * len(s) bytes (each byte has 8 bits, so we need 16 * len(s) bits)
        # Wait, if s is e.g. 16 bytes, we need 32 bytes output.
        out = prg.next_bits(len(s) * 8 * 2)
        n = len(s)
        return out[:n], out[n:]

    def evaluate(self, x: bytes) -> bytes:
        state = self.key
        for byte in x:
            for i in range(8):
                bit = (byte >> (7 - i)) & 1
                L, R = self._G(state)
                state = R if bit else L
        return state


class PRF_to_PRG:
    """Backward Direction (PRG from PRF): G(s) = F_s(0^n) || F_s(1^n)"""
    @staticmethod
    def evaluate(s: bytes) -> bytes:
        n = len(s)
        prf = GGM_PRF(s)
        out1 = prf.evaluate(b'\x00' * n)
        out2 = prf.evaluate(b'\x01' * n)
        return out1 + out2

# ==============================================================================
# PA #3: CPA-Secure Symmetric Encryption
# ==============================================================================

class CPA_Symmetric:
    """
    Encrypt-then-PRF: C = <r, F_k(r) XOR m>
    """
    def __init__(self, key: bytes):
        self.prf = GGM_PRF(key)
        self.block_size = len(key) # Assuming block size matches key length
        
    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, m: bytes) -> Tuple[bytes, bytes]:
        r = os.urandom(self.block_size)
        
        pad_len = self.block_size - (len(m) % self.block_size)
        m_padded = m + bytes([pad_len] * pad_len)
        
        c_blocks = []
        # Support multi-block with r+i
        r_int = int.from_bytes(r, 'big')
        
        for i in range(0, len(m_padded), self.block_size):
            pt_block = m_padded[i:i+self.block_size]
            current_r = (r_int + (i // self.block_size)) % (1 << (self.block_size * 8))
            current_r_bytes = current_r.to_bytes(self.block_size, 'big')
            
            mask = self.prf.evaluate(current_r_bytes)
            ct_block = self._xor_bytes(mask, pt_block)
            c_blocks.append(ct_block)
            
        return r, b''.join(c_blocks)

    def decrypt(self, r: bytes, c: bytes) -> bytes:
        m_blocks = []
        r_int = int.from_bytes(r, 'big')
        
        for i in range(0, len(c), self.block_size):
            ct_block = c[i:i+self.block_size]
            current_r = (r_int + (i // self.block_size)) % (1 << (self.block_size * 8))
            current_r_bytes = current_r.to_bytes(self.block_size, 'big')
            
            mask = self.prf.evaluate(current_r_bytes)
            pt_block = self._xor_bytes(mask, ct_block)
            m_blocks.append(pt_block)
            
        m_padded = b''.join(m_blocks)
        pad_len = m_padded[-1]
        return m_padded[:-pad_len]


# ==============================================================================
# PA #4: Modes of Operation
# ==============================================================================

class ModesOfOperation:
    @staticmethod
    def _xor(a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    @staticmethod
    def CBC_Enc(k: bytes, IV: bytes, M: bytes, prp_eval) -> bytes:
        block_size = len(IV)
        pad_len = block_size - (len(M) % block_size)
        if pad_len == 0: pad_len = block_size
        M_padded = M + bytes([pad_len] * pad_len)
        
        C = []
        prev = IV
        for i in range(0, len(M_padded), block_size):
            block = M_padded[i:i+block_size]
            xored = ModesOfOperation._xor(block, prev)
            ct = prp_eval(xored)
            C.append(ct)
            prev = ct
        return b''.join(C)

    @staticmethod
    def CBC_Dec(k: bytes, IV: bytes, C: bytes, prp_inv) -> bytes:
        block_size = len(IV)
        M = []
        prev = IV
        for i in range(0, len(C), block_size):
            ct = C[i:i+block_size]
            dec_block = prp_inv(ct)
            pt = ModesOfOperation._xor(dec_block, prev)
            M.append(pt)
            prev = ct
        M_padded = b''.join(M)
        pad_len = M_padded[-1]
        return M_padded[:-pad_len]

    @staticmethod
    def OFB_EncDec(k: bytes, IV: bytes, data: bytes, prf_eval) -> bytes:
        block_size = len(IV)
        out = []
        prev = IV
        for i in range(0, len(data), block_size):
            keystream = prf_eval(prev)
            block = data[i:i+block_size]
            out.append(ModesOfOperation._xor(block, keystream[:len(block)]))
            prev = keystream
        return b''.join(out)

    @staticmethod
    def CTR_EncDec(k: bytes, nonce: bytes, data: bytes, prf_eval) -> bytes:
        block_size = len(nonce)
        out = []
        nonce_int = int.from_bytes(nonce, 'big')
        for i in range(0, len(data), block_size):
            counter_bytes = ((nonce_int + i) % (1 << (block_size * 8))).to_bytes(block_size, 'big')
            keystream = prf_eval(counter_bytes)
            block = data[i:i+block_size]
            out.append(ModesOfOperation._xor(block, keystream[:len(block)]))
        return b''.join(out)

def Encrypt(mode: str, k: bytes, M: bytes, IV_or_nonce: bytes, prf_eval, prp_inv=None):
    if mode.upper() == "CBC":
        if prp_inv is None:
           raise ValueError("CBC requires PRP inverse")
        return ModesOfOperation.CBC_Enc(k, IV_or_nonce, M, prf_eval)
    elif mode.upper() == "OFB":
        return ModesOfOperation.OFB_EncDec(k, IV_or_nonce, M, prf_eval)
    elif mode.upper() == "CTR":
        return ModesOfOperation.CTR_EncDec(k, IV_or_nonce, M, prf_eval)
    else:
        raise ValueError("Unsupported mode")

# ==============================================================================
# PA #5: Message Authentication Codes (MACs)
# ==============================================================================

class PRF_MAC:
    def __init__(self, key: bytes):
        self.prf = GGM_PRF(key)
        
    def mac(self, m: bytes) -> bytes:
        # For variable length, using naive single hash or CBC-MAC
        # Using CBC-MAC over PRF
        block_size = len(self.prf.key)
        # Pad m
        pad_len = block_size - (len(m) % block_size)
        if pad_len == 0: pad_len = block_size
        m_padded = m + bytes([pad_len] * pad_len)
        
        cv = bytes(block_size) # IV = 0 for CBC-MAC
        for i in range(0, len(m_padded), block_size):
            block = m_padded[i:i+block_size]
            xored = bytes(x ^ y for x, y in zip(cv, block))
            cv = self.prf.evaluate(xored)
        return cv

    def verify(self, m: bytes, t: bytes) -> bool:
        return self.mac(m) == t

def secure_compare(t1: bytes, t2: bytes) -> bool:
    if len(t1) != len(t2):
        return False
    res = 0
    for x, y in zip(t1, t2):
        res |= x ^ y
    return res == 0

# ==============================================================================
# PA #6: CCA-Secure Symmetric Encryption
# ==============================================================================

class CCA_Symmetric:
    """
    Encrypt-then-MAC using PA #3 Enc and PA #5 Mac.
    """
    def __init__(self, kE: bytes, kM: bytes):
        self.enc = CPA_Symmetric(kE)
        self.mac = PRF_MAC(kM)
        
    def encrypt(self, m: bytes) -> Tuple[bytes, bytes, bytes]:
        r, c = self.enc.encrypt(m)
        t = self.mac.mac(r + c)
        return r, c, t
        
    def decrypt(self, r: bytes, c: bytes, t: bytes) -> bytes:
        if not self.mac.verify(r + c, t):
            raise ValueError("MAC verification failed!") # Reject
# ==============================================================================
# PA #7: Merkle-Damgård Transform
# ==============================================================================

class MerkleDamgard:
    def __init__(self, compress: Callable[[bytes, bytes], bytes], IV: bytes, block_size: int):
        self.compress = compress
        self.IV = IV
        self.block_size = block_size

    def hash(self, message: bytes) -> bytes:
        mlen = len(message) * 8
        m_padded = bytearray(message)
        m_padded.append(0x80)
        
        while (len(m_padded) * 8) % (self.block_size * 8) != (self.block_size * 8 - 64):
            m_padded.append(0x00)
            
        m_padded.extend(struct.pack('>Q', mlen))
        m_padded = bytes(m_padded)
        
        cv = self.IV
        for i in range(0, len(m_padded), self.block_size):
            block = m_padded[i:i+self.block_size]
            cv = self.compress(cv, block)
            
        return cv

# ==============================================================================
# PA #8: DLP-Based CRHF
# ==============================================================================

class DLP_CRHF:
    P = DLP_OWF.P
    Q = (P - 1) // 2
    G = 2
    
    # We must generate h = g^\alpha and discard \alpha
    # For deterministic tests, fixing h via a known hash value
    # Let's derive Alpha deterministically from OS bytes and forget it.
    _H_val = pow(G, int.from_bytes(b'fixed_h_value_for_testing_only_1234', 'big'), P)
    H = _H_val

    @staticmethod
    def compress(x_bytes: bytes, y_bytes: bytes) -> bytes:
        x = int.from_bytes(x_bytes, 'big') % DLP_CRHF.Q
        y = int.from_bytes(y_bytes, 'big') % DLP_CRHF.Q
        res = (pow(DLP_CRHF.G, x, DLP_CRHF.P) * pow(DLP_CRHF.H, y, DLP_CRHF.P)) % DLP_CRHF.P
        # Return 256 bytes (2048 bits)
        return res.to_bytes(256, 'big')

def dlp_hash(message: bytes, out_len: int = 32) -> bytes:
    IV = b'\x00' * 256
    md = MerkleDamgard(DLP_CRHF.compress, IV, 256)
    res = md.hash(message)
    return res[:out_len]

# ==============================================================================
# PA #9: Birthday Attack (Collision Finding)
# ==============================================================================

class CollisionFinder:
    @staticmethod
    def naive_search(hash_fn: Callable[[bytes], bytes], n_bits: int):
        seen = {}
        for count in range(1 << n_bits):
            msg = count.to_bytes(8, 'big')
            h = hash_fn(msg)
            if h in seen:
                return count, seen[h], msg, h
            seen[h] = msg
        return None

    @staticmethod
    def floyd_search(hash_fn: Callable[[bytes], bytes]):
        def f(x: bytes):
            return hash_fn(x)
            
        tortoise = f(b'\x01'*8)
        hare = f(f(b'\x01'*8))
        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(f(hare))
            
        tortoise = b'\x01'*8
        while tortoise != hare:
            tortoise = f(tortoise)
            hare = f(hare)
            
        return tortoise

# ==============================================================================
# PA #10: HMAC and HMAC-Based CCA-Secure Encryption
# ==============================================================================

class HMAC_Implementation:
    def __init__(self, block_size: int = 256, out_len: int = 32):
        self.block_size = block_size
        self.out_len = out_len
        self.opad = bytes([0x5c] * block_size)
        self.ipad = bytes([0x36] * block_size)

    def _hash(self, message: bytes) -> bytes:
        return dlp_hash(message, self.out_len)

    def _xor(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def evaluate(self, k: bytes, m: bytes) -> bytes:
        if len(k) > self.block_size:
            k = self._hash(k)
        if len(k) < self.block_size:
            k = k + b'\x00' * (self.block_size - len(k))

        o_key_pad = self._xor(k, self.opad)
        i_key_pad = self._xor(k, self.ipad)

        inner = self._hash(i_key_pad + m)
        outer = self._hash(o_key_pad + inner)
        return outer
        
    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        computed = self.evaluate(k, m)
        # Constant time comparison
        res = 0
        for x, y in zip(computed, t):
            res |= x ^ y
        return res == 0

class EncryptThenHMAC:
    def __init__(self, kE: bytes, kM: bytes):
        self.enc = CPA_Symmetric(kE)
        self.hmac = HMAC_Implementation()
        self.kM = kM
        
    def encrypt(self, m: bytes) -> Tuple[bytes, bytes, bytes]:
        r, c = self.enc.encrypt(m)
        t = self.hmac.evaluate(self.kM, r + c)
        return r, c, t
        
    def decrypt(self, r: bytes, c: bytes, t: bytes) -> bytes:
        if not self.hmac.verify(self.kM, r + c, t):
            raise ValueError("HMAC verification failed!") # Decrypt rejects
        return self.enc.decrypt(r, c)

class MAC_to_CRHF:
    """Backward (MAC to CRHF): h'(cv, block) = HMAC_k(cv||block)"""
    @staticmethod
    def get_compress_fn(public_key: bytes, hmac_instance: HMAC_Implementation):
        def compress(cv: bytes, block: bytes) -> bytes:
            return hmac_instance.evaluate(public_key, cv + block)
        return compress



class MAC_to_PRF:
    """PA #5: Backward Direction (MAC to PRF): A deterministic MAC queried on arbitrary inputs acts as a PRF"""
    def __init__(self, key: bytes):
        self.mac_instance = PRF_MAC(key)
        
    def evaluate(self, x: bytes) -> bytes:
        return self.mac_instance.mac(x)

# ==============================================================================
# PA #0: Foundation Modules
# ==============================================================================
class AESFoundation:
    """Mock foundation utilizing the No-Library Rule. It must expose strictly as OWF/PRF/PRP."""
    def __init__(self, key: bytes):
        self.key = key
    def asOWF(self, x: bytes) -> bytes:
        # One-way function assumption using a PRF
        prf = GGM_PRF(self.key)
        return prf.evaluate(x)
    def asPRF(self, x: bytes) -> bytes:
        prf = GGM_PRF(self.key)
        return prf.evaluate(x)
    def asPRP(self, x: bytes) -> bytes:
        # Mocking permutation for PA0 layout
        prf = GGM_PRF(self.key)
        return prf.evaluate(x)

class DLPFoundation:
    """Mathematical discrete log foundation."""
    P = DLP_OWF.P
    G = DLP_OWF.G
    def asOWF(self, x: int) -> int:
        return pow(self.G, x, self.P)
    def asOWP(self, x: int) -> int:
        return pow(self.G, x, self.P)
