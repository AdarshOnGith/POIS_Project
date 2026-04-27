"""
From-scratch AES-128 implementation for the No-Library Rule.

Implements the full AES-128 algorithm:
- GF(2^8) arithmetic for S-box generation
- SubBytes, ShiftRows, MixColumns, AddRoundKey
- Key Expansion (10 rounds)
- ECB encrypt/decrypt single 16-byte block

No external crypto libraries used. Only Python built-in int arithmetic.
"""

# ============================================================================
# GF(2^8) Arithmetic (irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11b)
# ============================================================================

def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(2^8)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit = a & 0x80
        a = (a << 1) & 0xFF
        if hi_bit:
            a ^= 0x1B  # x^8 + x^4 + x^3 + x + 1
        b >>= 1
    return p

def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(2^8). 0 maps to 0."""
    if a == 0:
        return 0
    # Use Fermat's little theorem: a^(-1) = a^(254) in GF(2^8)
    r = a
    for _ in range(6):  # a^2, a^4, a^8, ... a^128, then multiply
        r = _gf_mul(r, r)
        r = _gf_mul(r, a)
    # Actually: a^254 = a^(2+4+8+16+32+64+128) 
    # Let's just do extended Euclidean or power chain
    # Simpler: compute a^254 directly
    p = 1
    base = a
    exp = 254
    while exp > 0:
        if exp & 1:
            p = _gf_mul(p, base)
        base = _gf_mul(base, base)
        exp >>= 1
    return p

# ============================================================================
# S-box Generation (from GF(2^8) inverse + affine transform)
# ============================================================================

def _build_sbox():
    """Build AES S-box from scratch using GF(2^8) math."""
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for i in range(256):
        # Step 1: multiplicative inverse in GF(2^8)
        b = _gf_inv(i)
        # Step 2: affine transformation
        # s = b ⊕ ROTL(b,1) ⊕ ROTL(b,2) ⊕ ROTL(b,3) ⊕ ROTL(b,4) ⊕ 0x63
        s = b
        for shift in [1, 2, 3, 4]:
            s ^= ((b << shift) | (b >> (8 - shift))) & 0xFF
        s ^= 0x63
        s &= 0xFF
        sbox[i] = s
        inv_sbox[s] = i
    return sbox, inv_sbox

SBOX, INV_SBOX = _build_sbox()

# Round constants
RCON = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# ============================================================================
# AES-128 Core Operations
# ============================================================================

def _sub_bytes(state):
    return [SBOX[b] for b in state]

def _inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state]

def _shift_rows(state):
    """State is 16 bytes in column-major order: state[row + 4*col]."""
    s = list(state)
    # Row 1: shift left by 1
    s[1], s[5], s[9], s[13] = s[5], s[9], s[13], s[1]
    # Row 2: shift left by 2
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    # Row 3: shift left by 3
    s[3], s[7], s[11], s[15] = s[15], s[3], s[7], s[11]
    return s

def _inv_shift_rows(state):
    s = list(state)
    s[1], s[5], s[9], s[13] = s[13], s[1], s[5], s[9]
    s[2], s[6], s[10], s[14] = s[10], s[14], s[2], s[6]
    s[3], s[7], s[11], s[15] = s[7], s[11], s[15], s[3]
    return s

def _mix_columns(state):
    """MixColumns using GF(2^8) matrix multiplication."""
    s = list(state)
    for c in range(4):
        i = 4 * c
        a = s[i:i+4]
        s[i]   = _gf_mul(2, a[0]) ^ _gf_mul(3, a[1]) ^ a[2] ^ a[3]
        s[i+1] = a[0] ^ _gf_mul(2, a[1]) ^ _gf_mul(3, a[2]) ^ a[3]
        s[i+2] = a[0] ^ a[1] ^ _gf_mul(2, a[2]) ^ _gf_mul(3, a[3])
        s[i+3] = _gf_mul(3, a[0]) ^ a[1] ^ a[2] ^ _gf_mul(2, a[3])
    return s

def _inv_mix_columns(state):
    s = list(state)
    for c in range(4):
        i = 4 * c
        a = s[i:i+4]
        s[i]   = _gf_mul(14,a[0]) ^ _gf_mul(11,a[1]) ^ _gf_mul(13,a[2]) ^ _gf_mul(9,a[3])
        s[i+1] = _gf_mul(9,a[0]) ^ _gf_mul(14,a[1]) ^ _gf_mul(11,a[2]) ^ _gf_mul(13,a[3])
        s[i+2] = _gf_mul(13,a[0]) ^ _gf_mul(9,a[1]) ^ _gf_mul(14,a[2]) ^ _gf_mul(11,a[3])
        s[i+3] = _gf_mul(11,a[0]) ^ _gf_mul(13,a[1]) ^ _gf_mul(9,a[2]) ^ _gf_mul(14,a[3])
    return s

def _add_round_key(state, round_key):
    return [s ^ k for s, k in zip(state, round_key)]

# ============================================================================
# Key Expansion
# ============================================================================

def _key_expansion(key: bytes) -> list:
    """Expand 16-byte key into 11 round keys (176 bytes)."""
    assert len(key) == 16
    w = list(key)  # 16 bytes = 4 words
    for i in range(4, 44):  # Expand to 44 words (4 bytes each)
        idx = (i - 1) * 4
        temp = w[idx:idx+4]
        if i % 4 == 0:
            # RotWord + SubWord + Rcon
            temp = [SBOX[temp[1]], SBOX[temp[2]], SBOX[temp[3]], SBOX[temp[0]]]
            temp[0] ^= RCON[i // 4]
        prev = w[(i-4)*4:(i-4)*4+4]
        w.extend([p ^ t for p, t in zip(prev, temp)])
    # Split into 11 round keys
    return [w[i*16:(i+1)*16] for i in range(11)]

# ============================================================================
# AES-128 Encrypt / Decrypt (single 16-byte block)
# ============================================================================

class AES128:
    """
    From-scratch AES-128 implementation.
    No external crypto libraries. Implements the full Rijndael algorithm
    with GF(2^8) S-box, ShiftRows, MixColumns, and 10 rounds.
    """
    def __init__(self, key: bytes):
        assert len(key) == 16, "AES-128 requires a 16-byte key"
        self.key = key
        self.round_keys = _key_expansion(key)
    
    def encrypt_block(self, plaintext: bytes) -> bytes:
        """Encrypt a single 16-byte block."""
        assert len(plaintext) == 16
        state = list(plaintext)
        state = _add_round_key(state, self.round_keys[0])
        for r in range(1, 10):
            state = _sub_bytes(state)
            state = _shift_rows(state)
            state = _mix_columns(state)
            state = _add_round_key(state, self.round_keys[r])
        # Final round (no MixColumns)
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _add_round_key(state, self.round_keys[10])
        return bytes(state)
    
    def decrypt_block(self, ciphertext: bytes) -> bytes:
        """Decrypt a single 16-byte block."""
        assert len(ciphertext) == 16
        state = list(ciphertext)
        state = _add_round_key(state, self.round_keys[10])
        for r in range(9, 0, -1):
            state = _inv_shift_rows(state)
            state = _inv_sub_bytes(state)
            state = _add_round_key(state, self.round_keys[r])
            state = _inv_mix_columns(state)
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, self.round_keys[0])
        return bytes(state)
    
    def as_prf(self, x: bytes) -> bytes:
        """Use AES as a PRF: F_k(x) = AES_k(x)."""
        if len(x) < 16:
            x = x + b'\x00' * (16 - len(x))
        return self.encrypt_block(x[:16])
    
    def as_owf(self, x: bytes) -> bytes:
        """Davies-Meyer OWF: f(k) = AES_k(0^128) XOR k."""
        ct = self.encrypt_block(b'\x00' * 16)
        return bytes(a ^ b for a, b in zip(ct, self.key))
    
    def as_prg(self, seed: bytes) -> bytes:
        """PRG from AES: G(s) = AES_s(0) || AES_s(1)."""
        aes = AES128(seed[:16] if len(seed) >= 16 else seed + b'\x00' * (16 - len(seed)))
        left = aes.encrypt_block(b'\x00' * 16)
        right = aes.encrypt_block(b'\x00' * 15 + b'\x01')
        return left + right
