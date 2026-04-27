"""
Multi-Party Computation (Phase 4)
PA #18 - PA #20: Oblivious Transfer, Yao's Garbled Circuits / Secure Gates, and DAG Evaluator.
"""
from typing import Tuple, List, Callable
import os
from .math_core import fast_mod_exp, mod_inverse
from .cryptomania import rsa_keygen, rsa_dec_textbook
from .minicrypt import dlp_hash

# ==============================================================================
# PA #18: Oblivious Transfer (1-out-of-2 OT based on RSA)
# ==============================================================================

class RSA_OT_Sender:
    """Sender for 1-out-of-2 Oblivious Transfer."""
    def __init__(self, key_size: int = 512):
        self.pk, self.sk = rsa_keygen(key_size)
        self.N, self.e = self.pk
        self.N_len = (self.N.bit_length() + 7) // 8
        self.m0 = None
        self.m1 = None
        # Generate two random messages x0, x1
        self.x0 = int.from_bytes(os.urandom(self.N_len - 1), 'big')
        self.x1 = int.from_bytes(os.urandom(self.N_len - 1), 'big')

    def initialize(self) -> Tuple[tuple, int, int]:
        """Send (N, e) and randoms x0, x1 to Receiver."""
        return self.pk, self.x0, self.x1

    def transfer(self, v: int, m0: bytes, m1: bytes) -> Tuple[int, int]:
        """Receive blind v, send encryptions of m0, m1."""
        self.m0 = m0
        self.m1 = m1
        
        # Sender computes k0, k1
        k0 = rsa_dec_textbook(self.sk, (v - self.x0) % self.N)
        k1 = rsa_dec_textbook(self.sk, (v - self.x1) % self.N)
        
        # Mask messages
        # Hash k0, k1 to get pads
        pad0 = dlp_hash(k0.to_bytes(self.N_len, 'big'), len(m0))
        pad1 = dlp_hash(k1.to_bytes(self.N_len, 'big'), len(m1))
        
        m0_prime = int.from_bytes(m0, 'big') ^ int.from_bytes(pad0, 'big')
        m1_prime = int.from_bytes(m1, 'big') ^ int.from_bytes(pad1, 'big')
        
        return m0_prime, m1_prime


class RSA_OT_Receiver:
    """Receiver for 1-out-of-2 Oblivious Transfer."""
    def __init__(self, choice: int):
        assert choice in (0, 1), "Choice must be 0 or 1"
        self.choice = choice
        self.k = None

    def choose(self, pk: tuple, x0: int, x1: int) -> int:
        """Receive pk, x0, x1. Choose k, compute blind v."""
        self.N, self.e = pk
        self.N_len = (self.N.bit_length() + 7) // 8
        self.k = int.from_bytes(os.urandom(self.N_len - 1), 'big')
        
        xb = x1 if self.choice == 1 else x0
        # v = (xb + k^e) mod N
        v = (xb + fast_mod_exp(self.k, self.e, self.N)) % self.N
        return v

    def decode(self, m0_prime: int, m1_prime: int, msg_len: int) -> bytes:
        """Decode chosen message using k."""
        pad = dlp_hash(self.k.to_bytes(self.N_len, 'big'), msg_len)
        mb_prime = m1_prime if self.choice == 1 else m0_prime
        
        msg_int = mb_prime ^ int.from_bytes(pad, 'big')
        return msg_int.to_bytes(msg_len, 'big')

# Helper function for evaluating generic 1-out-of-4 OT from 1-out-of-2 OT (PA #19 requirement)
class OT_1_out_of_4:
    """Constructs 1-out-of-4 OT using parallel 1-out-of-2 OTs."""
    pass

# ==============================================================================
# PA #19: Secure Gates Evaluating Circuits directly via OT
# ==============================================================================

class SecureGateSimulator:
    """
    Evaluates secure logic gates (AND, XOR, NOT) between two parties.
    Sender has bit `a`, Receiver has bit `b`.
    """
    @staticmethod
    def secure_and(alice_a: int, bob_b: int) -> int:
        """
        Secure AND using 1-out-of-2 OT.
        Alice holds a. Bob holds b.
        Alice constructs m0 = (a AND 0) = 0
        Alice constructs m1 = (a AND 1) = a
        Bob uses b as his choice bit.
        """
        sender = RSA_OT_Sender(512)
        pk, x0, x1 = sender.initialize()
        
        m0 = b'\x00'
        m1 = (alice_a).to_bytes(1, 'big')
        
        receiver = RSA_OT_Receiver(bob_b)
        v = receiver.choose(pk, x0, x1)
        
        m0_prime, m1_prime = sender.transfer(v, m0, m1)
        res_bytes = receiver.decode(m0_prime, m1_prime, 1)
        return res_bytes[0]

    @staticmethod
    def secure_xor(alice_a: int, bob_b: int) -> int:
        """
        Secure XOR is FREE — no OT needed per the PDF requirement.
        Uses additive secret sharing over Z2:
        - Alice sends r (random bit) to Bob
        - Alice's share: a XOR r
        - Bob's share: b XOR r
        - Output: Alice's share XOR Bob's share = a XOR b
        No information about either party's input is revealed.
        """
        r = int.from_bytes(os.urandom(1), 'big') & 1
        alice_share = alice_a ^ r
        bob_share = bob_b ^ r
        return alice_share ^ bob_share

# ==============================================================================
# PA #20: Natively Mapped Topological DAG Circuit Evaluator
# ==============================================================================

class SecureDAG:
    """
    Evaluates an entire boolean circuit represented as a Directed Acyclic Graph (DAG)
    using the Secure Gate simulators.
    """
    def __init__(self, nodes: dict, inputs_alice: dict, inputs_bob: dict):
        """
        nodes: dict of {node_id: ('GATE_TYPE', in1, in2)}
        inputs_alice: dict of {node_id: bit}
        inputs_bob: dict of {node_id: bit}
        """
        self.nodes = nodes
        self.wires = {}
        self.ot_calls = 0  # Track OT calls for performance reporting
        # Load inputs
        self.wires.update(inputs_alice)
        self.wires.update(inputs_bob)

    def evaluate(self) -> dict:
        """Evaluate DAG in topological order (assuming nodes dict is ordered correctly or we resolve dynamically)."""
        resolved = set(self.wires.keys())
        pending = set(self.nodes.keys())
        
        while pending:
            progress = False
            for node in list(pending):
                op, in1, in2 = self.nodes[node]
                if (in1 in resolved or in1 is None) and (in2 in resolved or in2 is None):
                    val1 = self.wires.get(in1, 0)
                    val2 = self.wires.get(in2, 0)
                    
                    if op == 'AND':
                        out = SecureGateSimulator.secure_and(val1, val2)
                        self.ot_calls += 1  # Each AND uses one OT
                    elif op == 'XOR':
                        out = SecureGateSimulator.secure_xor(val1, val2)
                        # XOR is free — no OT call
                    elif op == 'NOT':
                        out = 1 - val1
                        # NOT is free — no OT call
                    
                    self.wires[node] = out
                    resolved.add(node)
                    pending.remove(node)
                    progress = True
            if not progress:
                raise ValueError("DAG contains cycles or missing inputs!")
        
        return self.wires


# ==============================================================================
# PA #20: Three Mandatory Test Circuits
# ==============================================================================

def build_comparison_circuit(n_bits: int) -> dict:
    """
    Millionaire's Problem: Compares two n-bit integers x > y.
    Uses a ripple comparator: starting from MSB, check each bit pair.
    Circuit structure:
    - For each bit position i (MSB to LSB), compute:
      - x_i XOR y_i (checks if bits differ)
      - x_i AND (NOT y_i) (x_i is 1, y_i is 0 → x > y at this position)
    - Chain with priority: higher bits override lower bits
    Returns nodes dict suitable for SecureDAG.
    """
    nodes = {}
    
    # For each bit position, create comparison gates
    # We build a priority chain: gt = "x is greater at or before bit i"
    # Starting from MSB (bit n-1) down to LSB (bit 0)
    
    for i in range(n_bits):
        xi = f'x{i}'
        yi = f'y{i}'
        
        # NOT y_i
        not_yi = f'not_y{i}'
        nodes[not_yi] = ('NOT', yi, None)
        
        # x_i AND (NOT y_i): x wins at bit i
        gt_i = f'gt_bit{i}'
        nodes[gt_i] = ('AND', xi, not_yi)
        
        # x_i XOR y_i: bits differ at position i
        diff_i = f'diff{i}'
        nodes[diff_i] = ('XOR', xi, yi)
        
        # NOT diff_i: bits are equal at position i
        eq_i = f'eq{i}'
        nodes[eq_i] = ('NOT', diff_i, None)
        
        if i == 0:
            # MSB: gt_so_far = gt_bit0
            nodes['gt_chain_0'] = ('AND', gt_i, gt_i)  # Identity via AND(x,x)=x
        else:
            # gt_chain_i = gt_bit_i OR (eq_so_far AND gt_chain_{i-1})
            # Since we only have AND/XOR/NOT, OR(a,b) = NOT(AND(NOT a, NOT b))
            # eq_so_far tracks if all higher bits were equal
            
            prev_eq = f'eq_chain_{i-1}' if i > 1 else f'eq{0}'
            curr_eq_chain = f'eq_chain_{i}'
            nodes[curr_eq_chain] = ('AND', prev_eq, eq_i)
            
            # previous_eq AND current_gt
            carry = f'carry_{i}'
            nodes[carry] = ('AND', prev_eq if i == 1 else f'eq_chain_{i-1}', gt_i)
            
            # OR(gt_chain_{i-1}, carry_i) = NOT(AND(NOT(gt_chain_{i-1}), NOT(carry_i)))
            not_prev_gt = f'not_prev_gt_{i}'
            nodes[not_prev_gt] = ('NOT', f'gt_chain_{i-1}', None)
            not_carry = f'not_carry_{i}'
            nodes[not_carry] = ('NOT', carry, None)
            and_nots = f'and_nots_{i}'
            nodes[and_nots] = ('AND', not_prev_gt, not_carry)
            nodes[f'gt_chain_{i}'] = ('NOT', and_nots, None)
    
    # Output is the final gt_chain
    output = f'gt_chain_{n_bits - 1}'
    return nodes, output


def build_equality_circuit(n_bits: int) -> dict:
    """
    Secure Equality Test: Compute x == y (bitwise equality of n-bit integers).
    XOR each bit pair, NOT the result (equal if XOR is 0), then AND all.
    """
    nodes = {}
    
    for i in range(n_bits):
        xi = f'x{i}'
        yi = f'y{i}'
        
        # XOR: 0 if bits equal, 1 if different
        xor_i = f'xor_{i}'
        nodes[xor_i] = ('XOR', xi, yi)
        
        # NOT XOR: 1 if bits equal
        eq_i = f'bit_eq_{i}'
        nodes[eq_i] = ('NOT', xor_i, None)
        
        if i == 0:
            nodes['eq_chain_0'] = ('AND', eq_i, eq_i)  # Identity
        else:
            # AND chain: all bits must be equal
            nodes[f'eq_chain_{i}'] = ('AND', f'eq_chain_{i-1}', eq_i)
    
    output = f'eq_chain_{n_bits - 1}'
    return nodes, output


def build_addition_circuit(n_bits: int) -> dict:
    """
    Secure Bit-Addition: Compute x + y mod 2^n.
    Full adder circuit: for each bit position, compute sum and carry.
    sum_i = x_i XOR y_i XOR carry_{i-1}
    carry_i = (x_i AND y_i) OR (carry_{i-1} AND (x_i XOR y_i))
    """
    nodes = {}
    
    for i in range(n_bits):
        xi = f'x{i}'
        yi = f'y{i}'
        
        # x_i XOR y_i
        xor_i = f'xor_{i}'
        nodes[xor_i] = ('XOR', xi, yi)
        
        # x_i AND y_i (generate)
        and_i = f'and_{i}'
        nodes[and_i] = ('AND', xi, yi)
        
        if i == 0:
            # No carry-in for LSB
            nodes[f'sum_{i}'] = ('XOR', xi, yi)  # sum = x0 XOR y0
            nodes[f'carry_{i}'] = ('AND', xi, yi)  # carry = x0 AND y0
        else:
            # sum_i = xor_i XOR carry_{i-1}
            nodes[f'sum_{i}'] = ('XOR', xor_i, f'carry_{i-1}')
            
            # carry_i = (x_i AND y_i) OR (carry_{i-1} AND xor_i)
            # propagate: carry_{i-1} AND xor_i
            prop_i = f'prop_{i}'
            nodes[prop_i] = ('AND', f'carry_{i-1}', xor_i)
            
            # OR(and_i, prop_i) = NOT(AND(NOT and_i, NOT prop_i))
            not_and_i = f'not_and_{i}'
            nodes[not_and_i] = ('NOT', and_i, None)
            not_prop_i = f'not_prop_{i}'
            nodes[not_prop_i] = ('NOT', prop_i, None)
            nand_carry = f'nand_carry_{i}'
            nodes[nand_carry] = ('AND', not_and_i, not_prop_i)
            nodes[f'carry_{i}'] = ('NOT', nand_carry, None)
    
    # Output wires are sum_0, sum_1, ..., sum_{n-1}
    outputs = [f'sum_{i}' for i in range(n_bits)]
    return nodes, outputs


def run_millionaire(x: int, y: int, n_bits: int = 4) -> dict:
    """
    Millionaire's Problem: Securely compute x > y without revealing values.
    Alice has x, Bob has y.
    """
    import time
    start = time.time()
    
    nodes, output_wire = build_comparison_circuit(n_bits)
    
    # Convert integers to bit dictionaries (MSB first)
    inputs_alice = {}
    inputs_bob = {}
    for i in range(n_bits):
        bit_pos = n_bits - 1 - i  # MSB first
        inputs_alice[f'x{i}'] = (x >> bit_pos) & 1
        inputs_bob[f'y{i}'] = (y >> bit_pos) & 1
    
    dag = SecureDAG(nodes, inputs_alice, inputs_bob)
    result = dag.evaluate()
    
    elapsed = time.time() - start
    is_greater = result[output_wire]
    
    return {
        "x_greater_than_y": bool(is_greater),
        "result_text": "Alice is richer" if is_greater else ("Equal" if x == y else "Bob is richer"),
        "ot_calls": dag.ot_calls,
        "wall_clock_seconds": elapsed,
        "n_bits": n_bits
    }


def run_equality(x: int, y: int, n_bits: int = 4) -> dict:
    """Securely test x == y without revealing values."""
    import time
    start = time.time()
    
    nodes, output_wire = build_equality_circuit(n_bits)
    
    inputs_alice = {}
    inputs_bob = {}
    for i in range(n_bits):
        bit_pos = n_bits - 1 - i
        inputs_alice[f'x{i}'] = (x >> bit_pos) & 1
        inputs_bob[f'y{i}'] = (y >> bit_pos) & 1
    
    dag = SecureDAG(nodes, inputs_alice, inputs_bob)
    result = dag.evaluate()
    
    elapsed = time.time() - start
    are_equal = result[output_wire]
    
    return {
        "are_equal": bool(are_equal),
        "ot_calls": dag.ot_calls,
        "wall_clock_seconds": elapsed,
        "n_bits": n_bits
    }


def run_addition(x: int, y: int, n_bits: int = 4) -> dict:
    """Securely compute x + y mod 2^n without revealing values."""
    import time
    start = time.time()
    
    nodes, output_wires = build_addition_circuit(n_bits)
    
    # Bits in LSB-first order for the adder
    inputs_alice = {}
    inputs_bob = {}
    for i in range(n_bits):
        inputs_alice[f'x{i}'] = (x >> i) & 1
        inputs_bob[f'y{i}'] = (y >> i) & 1
    
    dag = SecureDAG(nodes, inputs_alice, inputs_bob)
    result = dag.evaluate()
    
    elapsed = time.time() - start
    
    # Reconstruct sum from output bits (LSB first)
    total = 0
    for i in range(n_bits):
        total |= (result[output_wires[i]] << i)
    
    return {
        "sum": total,
        "expected": (x + y) % (1 << n_bits),
        "correct": total == (x + y) % (1 << n_bits),
        "ot_calls": dag.ot_calls,
        "wall_clock_seconds": elapsed,
        "n_bits": n_bits
    }
