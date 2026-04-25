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
        Secure XOR using 1-out-of-2 OT.
        m0 = a XOR 0 = a
        m1 = a XOR 1 = 1 - a
        """
        sender = RSA_OT_Sender(512)
        pk, x0, x1 = sender.initialize()
        
        m0 = (alice_a).to_bytes(1, 'big')
        m1 = (1 - alice_a).to_bytes(1, 'big')
        
        receiver = RSA_OT_Receiver(bob_b)
        v = receiver.choose(pk, x0, x1)
        
        m0_prime, m1_prime = sender.transfer(v, m0, m1)
        res_bytes = receiver.decode(m0_prime, m1_prime, 1)
        return res_bytes[0]

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
                    elif op == 'XOR':
                        out = SecureGateSimulator.secure_xor(val1, val2)
                    elif op == 'NOT':
                        out = 1 - val1
                    
                    self.wires[node] = out
                    resolved.add(node)
                    pending.remove(node)
                    progress = True
            if not progress:
                raise ValueError("DAG contains cycles or missing inputs!")
        
        return self.wires
