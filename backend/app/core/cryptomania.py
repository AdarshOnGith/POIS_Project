import os
from .math_core import gen_prime, fast_mod_exp, egcd, mod_inverse

# ==============================================================================
# PA #11: Diffie-Hellman Key Exchange
# ==============================================================================

def generate_safe_prime(bits: int) -> tuple:
    """
    PA #11: Generates a safe prime p = 2q + 1, where q is also prime.
    Returns (p, q).
    """
    while True:
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        # Simple test to check if p is roughly prime without full MR if it's explicitly composite
        if (p % 3 == 0) and p != 3:
            continue
        # Check if p is prime using Miller-Rabin test
        from .math_core import miller_rabin
        if miller_rabin(p, 40):
            return p, q

def dh_generate_group(bits: int = 512) -> tuple:
    """Returns (p, q, g) for DH."""
    p, q = generate_safe_prime(bits)
    # Find generator g of subgroup of order q
    # For a safe prime p = 2q+1, elements have order 1, 2, q, or 2q.
    # An element g in {2, ..., p-2} has order q if g^2 != 1 mod p and g^q == 1 mod p
    # Actually, elements of the form h^2 mod p (for h in {2,...,p-1}) generate the subgroup of order q
    g = 2
    while True:
        g = fast_mod_exp(g, 2, p)
        if g != 1 and g != p - 1:
            if fast_mod_exp(g, q, p) == 1:
                break
        g += 1
    return p, q, g

class DiffieHellmanParticipant:
    def __init__(self, p: int, q: int, g: int):
        self.p = p
        self.q = q
        self.g = g
        # Step 1: produces private exponent and public value
        q_bytes = (q.bit_length() + 7) // 8
        self.private_exponent = int.from_bytes(os.urandom(q_bytes), 'big') % q
        self.public_value = fast_mod_exp(self.g, self.private_exponent, self.p)
    
    def compute_shared_secret(self, other_public_value: int) -> int:
        # Step 2: computes shared secret K
        return fast_mod_exp(other_public_value, self.private_exponent, self.p)

# ==============================================================================
# PA #12: Textbook RSA & PKCS#1 v1.5
# ==============================================================================

def rsa_keygen(bits: int, e: int = 65537) -> tuple:
    """PA #12: Generates (pk, sk) where pk=(N, e) and sk=(N, d, p, q)."""
    p = gen_prime(bits // 2)
    q = gen_prime(bits // 2)
    while p == q:
        q = gen_prime(bits // 2)
    N = p * q
    phi = (p - 1) * (q - 1)
    
    # Ensure gcd(e, phi) == 1
    g, _, _ = egcd(e, phi)
    while g != 1:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        N = p * q
        phi = (p - 1) * (q - 1)
        g, _, _ = egcd(e, phi)
    
    d = mod_inverse(e, phi)
    return ((N, e), (N, d, p, q))

def rsa_enc_textbook(pk: tuple, m: int) -> int:
    """PA #12: Textbook RSA Encryption."""
    N, e = pk
    return fast_mod_exp(m, e, N)

def rsa_dec_textbook(sk: tuple, c: int) -> int:
    """PA #12: Textbook RSA Decryption."""
    N, d, _, _ = sk
    return fast_mod_exp(c, d, N)

def pkcs1_v15_pad(m: bytes, n_bytes: int) -> bytes:
    """PA #12: PKCS#1 v1.5 Padding for Encryption."""
    m_len = len(m)
    if m_len > n_bytes - 11:
        raise ValueError("Message too long for this RSA key length")
    
    # 00 || 02 || PS || 00 || M
    ps_len = n_bytes - m_len - 3
    ps = bytearray(os.urandom(ps_len))
    # Replace zero bytes in padding, as PS must not contain 0x00
    for i in range(ps_len):
        while ps[i] == 0x00:
            ps[i] = os.urandom(1)[0]
            
    return b'\x00\x02' + bytes(ps) + b'\x00' + m

def pkcs1_v15_unpad(padded_m: bytes, n_bytes: int) -> bytes:
    """PA #12: PKCS#1 v1.5 De-padding."""
    if len(padded_m) != n_bytes:
        # Handle zero-padding drop off if N was slightly smaller byte-wise
        if len(padded_m) < n_bytes:
            padded_m = b'\x00' * (n_bytes - len(padded_m)) + padded_m
            
    if padded_m[0:2] != b'\x00\x02':
        return None # Return None / perp on failure
    
    try:
        zero_idx = padded_m.index(b'\x00', 2)
        if zero_idx < 10:
            return None # PS must be at least 8 bytes
        return padded_m[zero_idx+1:]
    except ValueError:
        return None

def rsa_enc_pkcs(pk: tuple, m: bytes) -> int:
    N, e = pk
    n_bytes = (N.bit_length() + 7) // 8
    padded = pkcs1_v15_pad(m, n_bytes)
    return rsa_enc_textbook(pk, int.from_bytes(padded, 'big'))

def rsa_dec_pkcs(sk: tuple, c: int) -> bytes:
    N, d, _, _ = sk
    n_bytes = (N.bit_length() + 7) // 8
    m_int = rsa_dec_textbook(sk, c)
    m_bytes = m_int.to_bytes(n_bytes, 'big')
    return pkcs1_v15_unpad(m_bytes, n_bytes)

# ==============================================================================
# PA #14: Håstad's Broadcast Attack
# ==============================================================================

def hastad_attack(ciphertexts: list, moduli: list) -> int:
    """PA #14: Recovers plaintext sent to 3 recipients using e=3 via CRT and Integer roots."""
    from .math_core import crt, integer_nth_root
    if len(ciphertexts) != 3 or len(moduli) != 3:
        raise ValueError("Requires exactly 3 recipients for e=3 attack.")
    
    # CRT maps C_i = M^3 mod N_i to C' = M^3 mod N_1*N_2*N_3
    c_prime = crt(ciphertexts, moduli)
    # Since M < min(N_i), M^3 is less than N_1*N_2*N_3 natively, so we just take the standard cube root
    m = integer_nth_root(c_prime, 3)
    return m

# ==============================================================================
# PA #15: Digital Signatures
# ==============================================================================

def rsa_sign(sk: tuple, m: bytes) -> int:
    """PA #15: Hash-then-Sign framework utilizing PA #8 Hash."""
    from .minicrypt import dlp_hash
    # Standard Hash
    h = dlp_hash(m, 32)
    # Signature gen
    N, d, _, _ = sk
    return fast_mod_exp(int.from_bytes(h, 'big'), d, N)

def rsa_verify(pk: tuple, m: bytes, sig: int) -> bool:
    """PA #15: Signature Validation."""
    from .minicrypt import dlp_hash
    h = dlp_hash(m, 32)
    N, e = pk
    # Confirm sig^e == h mod N
    validation = fast_mod_exp(sig, e, N)
    return validation == int.from_bytes(h, 'big')

# ==============================================================================
# PA #16: ElGamal Public-Key Cryptosystem
# ==============================================================================

def elgamal_keygen(p: int, q: int, g: int) -> tuple:
    """PA #16: ElGamal Keygen utilizing PA #11 group parameters."""
    q_bytes = (q.bit_length() + 7) // 8
    x = int.from_bytes(os.urandom(q_bytes), 'big') % q
    h = fast_mod_exp(g, x, p)
    return ((p, q, g, h), (p, q, g, x))

def elgamal_enc(pk: tuple, m: int) -> tuple:
    """PA #16: ElGamal Encryption."""
    p, q, g, h = pk
    if m >= p or m < 0:
        raise ValueError("Message out of bounds")
    q_bytes = (q.bit_length() + 7) // 8
    y = int.from_bytes(os.urandom(q_bytes), 'big') % q
    
    c1 = fast_mod_exp(g, y, p)
    s = fast_mod_exp(h, y, p)
    c2 = (m * s) % p
    return (c1, c2)

def elgamal_dec(sk: tuple, c: tuple) -> int:
    """PA #16: ElGamal Decryption."""
    p, q, g, x = sk
    c1, c2 = c
    s = fast_mod_exp(c1, x, p)
    s_inv = mod_inverse(s, p)
    return (c2 * s_inv) % p

# ==============================================================================
# PA #17: CCA-Secure PKC (Encrypt-then-Sign)
# ==============================================================================

def cca_pkc_enc(pk_enc: tuple, sk_sign: tuple, m: int) -> tuple:
    """
    PA #17: CCA-Secure PKC Encryption. 
    1. Encrypt with ElGamal
    2. Sign the structured ciphertext with RSA.
    """
    c = elgamal_enc(pk_enc, m)
    # Serialize components for signature binding
    c1_bytes = c[0].to_bytes((c[0].bit_length() + 7) // 8, 'big')
    c2_bytes = c[1].to_bytes((c[1].bit_length() + 7) // 8, 'big')
    c_bytes = c1_bytes + b"||" + c2_bytes
    
    sig = rsa_sign(sk_sign, c_bytes)
    return (c, sig)

def cca_pkc_dec(sk_dec: tuple, pk_verify: tuple, package: tuple) -> int:
    """
    PA #17: CCA-Secure Validation & Decryption.
    Must verify signature before decrypting!
    """
    c, sig = package
    c1_bytes = c[0].to_bytes((c[0].bit_length() + 7) // 8, 'big')
    c2_bytes = c[1].to_bytes((c[1].bit_length() + 7) // 8, 'big')
    c_bytes = c1_bytes + b"||" + c2_bytes
    
    if not rsa_verify(pk_verify, c_bytes, sig):
        # Verification failed! Return perp (None here indicates aborted attempt)
        return None
    
    # Signature is valid. Proceed to standard decryption.
    return elgamal_dec(sk_dec, c)

