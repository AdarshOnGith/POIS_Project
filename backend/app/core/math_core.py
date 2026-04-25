import os
import time

def fast_mod_exp(base: int, exp: int, mod: int) -> int:
    """
    PA #12 & PA #13: Fast Modular Exponentiation (Square-and-Multiply).
    Strictly written from scratch to avoid using Python's built-in pow(x, y, mod).
    """
    if mod == 1:
        return 0
    result = 1
    base = base % mod
    while exp > 0:
        if (exp % 2) == 1:
            result = (result * base) % mod
        exp = exp >> 1
        base = (base * base) % mod
    return result

def miller_rabin(n: int, k: int = 40) -> bool:
    """
    PA #13: Miller-Rabin Primality Test.
    Returns True if n is PROBABLY PRIME, False if COMPOSITE.
    """
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False

    # Find d and r such that n - 1 = 2^r * d
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        # Pick random a in [2, n-2]
        # Calculate byte length to avoid bias
        byte_len = ((n - 2).bit_length() + 7) // 8
        a = 0
        while a < 2 or a > n - 2:
            a = int.from_bytes(os.urandom(byte_len), 'big') % (n - 1)

        x = fast_mod_exp(a, d, n)
        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(r - 1):
            x = fast_mod_exp(x, 2, n)
            if x == n - 1:
                composite = False
                break
                
        if composite:
            return False

    return True

def gen_prime_with_trials(bits: int, k: int = 40) -> tuple:
    """
    PA #13: Prime Generator.
    Repeatedly samples random odd integers and tests them.
    Returns (prime_number, trials_count) to evaluate performance.
    """
    byte_len = bits // 8
    trials = 0
    while True:
        trials += 1
        # Generate random bytes
        raw_bytes = bytearray(os.urandom(byte_len))
        # Ensure MSB is 1 (highest bit set) and LSB is 1 (odd number)
        raw_bytes[0] |= 0x80
        raw_bytes[-1] |= 0x01
        
        candidate = int.from_bytes(raw_bytes, 'big')
        
        if miller_rabin(candidate, k):
            return candidate, trials

def gen_prime(bits: int, k: int = 40) -> int:
    """Convenience wrapper for PA #13 Prime Generation."""
    prime, _ = gen_prime_with_trials(bits, k)
    return prime

def egcd(a: int, b: int) -> tuple:
    """
    PA #14: Extended Euclidean Algorithm.
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def mod_inverse(a: int, m: int) -> int:
    """
    PA #14: Modular Inverse using Extended Euclidean Algorithm.
    Computes x such that (a * x) % m == 1.
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return x % m

def crt(residues: list, moduli: list) -> int:
    """
    PA #14: Chinese Remainder Theorem Solver.
    Uses the constructive formula and native mod_inverse.
    """
    if len(residues) != len(moduli):
        raise ValueError("Residues and moduli lists must be the same length.")
    
    # Calculate N = product of all moduli
    N = 1
    for m in moduli:
        N *= m
    
    result = 0
    for r_i, m_i in zip(residues, moduli):
        N_i = N // m_i
        M_i = mod_inverse(N_i, m_i)
        result = (result + (r_i * N_i * M_i) % N) % N
        
    return result % N

def integer_nth_root(x: int, n: int) -> int:
    """
    PA #14: Integer N-th Root using Newton's Method.
    Solves for the largest integer r such that r^n <= x.
    Used extensively in Håstad's Broadcast Attack.
    """
    if x < 0:
        raise ValueError("Cannot compute real nth root of a negative integer")
    if x == 0:
        return 0
        
    # Initial guess
    r = x
    while True:
        # y = ((n - 1) * r + x / (r^(n - 1))) / n
        y = ((n - 1) * r + x // (r ** (n - 1))) // n
        if y >= r:
            return r
        r = y
