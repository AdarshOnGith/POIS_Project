from typing import List, Dict, Any

# ==============================================================================
# PA #0: The Clique Graph Routing Table
# ==============================================================================
# Complete bidirectional graph for the Minicrypt clique.
# Every node that appears as a target must also have outgoing edges.

MINICRYPT_GRAPH = {
    "OWF": {
        "PRG": {"proof": "PA#1: HILL PRG — iterative hard-core-bit construction G(x) = b(x₀)||b(x₁)||...||b(xₗ) where xᵢ₊₁ = f(xᵢ)", "pa": 1},
        "OWP": {"proof": "OWF ⇒ OWP: DLP f(x)=g^x mod p is bijective on Zq, hence a OWP", "pa": 1},
    },
    "OWP": {
        "OWF": {"proof": "OWP ⇒ OWF: Immediate — a OWP is a bijective OWF (special case)", "pa": 1},
        "PRG": {"proof": "OWP ⇒ PRG: OWP + hard-core predicate ⇒ G(x) = (f(x), b(x))", "pa": 1},
        "PRF": {"proof": "OWP ⇒ PRF: Chain OWP⇒PRG (hard-core) then PRG⇒PRF (GGM)", "pa": 2},
    },
    "PRG": {
        "OWF": {"proof": "PRG ⇒ OWF: f(s) = G(s) is one-way (inverting G breaks PRG security)", "pa": 1},
        "OWP": {"proof": "PRG ⇒ OWP: Length-preserving PRG is injective ⇒ permutation on range", "pa": 1},
        "PRF": {"proof": "PA#2: GGM tree construction — Fk(b₁...bₙ) = Gbₙ(...Gb₁(k))", "pa": 2},
    },
    "PRF": {
        "PRG": {"proof": "PRF ⇒ PRG: G(s) = Fs(0ⁿ) || Fs(1ⁿ) is a length-doubling PRG", "pa": 2},
        "PRP": {"proof": "PRF ⇒ PRP: Luby-Rackoff 3-round Feistel network using PRF as round function", "pa": 2},
        "CPA": {"proof": "PA#3: CPA-secure encryption — C = ⟨r, Fk(r) ⊕ m⟩", "pa": 3},
        "MAC": {"proof": "PA#5: PRF ⇒ MAC — Mac_k(m) = F_k(m) is EUF-CMA secure", "pa": 5},
        "OWP": {"proof": "PRF ⇒ OWP: via Luby-Rackoff PRP, f(k) = PRP_k(0ⁿ)", "pa": 2},
    },
    "PRP": {
        "PRF": {"proof": "PRP ⇒ PRF: PRF/PRP switching lemma (PRP on super-poly domain ≈ PRF)", "pa": 2},
        "MAC": {"proof": "PRP ⇒ MAC: Use PRP as PRF (switching lemma), then PRF ⇒ MAC", "pa": 5},
        "CPA": {"proof": "PRP ⇒ CPA: Use PRP as PRF, then PRF ⇒ CPA encryption (PA#3)", "pa": 3},
    },
    "CPA": {
        "PRF": {"proof": "CPA ⇒ PRF: CPA construction requires PRF; reverse reduces via oracle access", "pa": 3},
        "CCA": {"proof": "PA#6: CPA + MAC ⇒ CCA via Encrypt-then-MAC paradigm", "pa": 6},
    },
    "MAC": {
        "PRF": {"proof": "MAC ⇒ PRF: Secure EUF-CMA MAC on uniform inputs is a PRF", "pa": 5},
        "PRP": {"proof": "MAC ⇒ PRP: via MAC⇒PRF then PRF⇒PRP (Luby-Rackoff)", "pa": 5},
        "CRHF": {"proof": "MAC ⇒ CRHF: MAC as collision-resistant compression + Merkle-Damgård", "pa": 10},
        "HMAC": {"proof": "MAC ⇒ HMAC: MAC in HMAC double-hash structure", "pa": 10},
        "CCA": {"proof": "PA#6: MAC used in Encrypt-then-MAC for CCA security", "pa": 6},
    },
    "CCA": {
        "CPA": {"proof": "CCA ⇒ CPA: CCA-secure scheme is also CPA-secure (stronger notion)", "pa": 6},
        "MAC": {"proof": "CCA ⇒ MAC: CCA construction includes MAC component", "pa": 6},
    },
    "CRHF": {
        "HMAC": {"proof": "CRHF ⇒ HMAC: PA#10 — HMAC built on CRHF compression function", "pa": 10},
        "MAC": {"proof": "CRHF ⇒ MAC: via CRHF⇒HMAC⇒MAC chain", "pa": 10},
    },
    "HMAC": {
        "MAC": {"proof": "HMAC ⇒ MAC: HMAC is a secure EUF-CMA MAC (PA#10)", "pa": 10},
        "CRHF": {"proof": "HMAC ⇒ CRHF: Fix key k, H'(m)=HMAC_k(m) is collision-resistant", "pa": 10},
        "CCA": {"proof": "HMAC ⇒ CCA: Encrypt-then-HMAC achieves CCA security (PA#10)", "pa": 10},
    },
}

# Foundation → primitive mapping (Leg 1)
FOUNDATION_CHAINS = {
    "AES": {
        "PRP": [{"step": "AES is a PRP", "fn": "AES_k(x)"}],
        "PRF": [{"step": "PRP/PRF switching lemma", "fn": "AES_k(x) ≈ PRF"}],
        "OWF": [{"step": "Davies-Meyer OWF", "fn": "f(k) = AES_k(0¹²⁸) ⊕ k"}],
        "PRG": [
            {"step": "PRP/PRF switching lemma", "fn": "AES_k(x) ≈ PRF"},
            {"step": "PRF ⇒ PRG", "fn": "G(s) = F_s(0) || F_s(1)"},
        ],
        "MAC": [
            {"step": "PRP/PRF switching lemma", "fn": "AES ≈ PRF"},
            {"step": "PRF ⇒ MAC", "fn": "Mac_k(m) = F_k(m)"},
        ],
    },
    "DLP": {
        "OWF": [{"step": "DLP OWF", "fn": "f(x) = g^x mod p"}],
        "OWP": [{"step": "DLP OWP", "fn": "f(x) = g^x mod p (bijective on Zq)"}],
        "PRG": [
            {"step": "DLP OWF", "fn": "f(x) = g^x mod p"},
            {"step": "HILL PRG", "fn": "G(x) = b(x₀)||b(x₁)||..."},
        ],
        "PRF": [
            {"step": "DLP OWF", "fn": "f(x) = g^x mod p"},
            {"step": "HILL PRG", "fn": "G(x) = b(x₀)||..."},
            {"step": "GGM tree", "fn": "F_k(x) = Gxₙ(...Gx₁(k))"},
        ],
        "PRP": [
            {"step": "DLP OWF → HILL PRG → GGM PRF"},
            {"step": "Luby-Rackoff 3-round Feistel"},
        ],
        "MAC": [
            {"step": "DLP OWF → PRG → PRF chain"},
            {"step": "PRF ⇒ MAC: Mac_k(m) = F_k(m)"},
        ],
    }
}


def reduce_primitive(source: str, target: str, foundation: str = "Standard") -> Dict[str, Any]:
    """BFS shortest-path across the Minicrypt reduction graph."""
    if source == target:
        return {
            "source": source, "target": target, "foundation": foundation,
            "path": [source], "edges": [], "steps": 0, "possible": True
        }
    
    # Check source exists in graph
    all_nodes = set()
    for src, tgts in MINICRYPT_GRAPH.items():
        all_nodes.add(src)
        for t in tgts:
            all_nodes.add(t)
    
    if source not in all_nodes:
        return {"possible": False, "error": f"Unknown source primitive: {source}"}
    if target not in all_nodes:
        return {"possible": False, "error": f"Unknown target primitive: {target}"}
    
    # BFS
    queue = [(source, [source], [])]
    visited = {source}
    
    while queue:
        current, path, edges = queue.pop(0)
        for neighbor, edge_data in MINICRYPT_GRAPH.get(current, {}).items():
            if neighbor not in visited:
                proof = edge_data["proof"] if isinstance(edge_data, dict) else edge_data
                pa = edge_data.get("pa", "?") if isinstance(edge_data, dict) else "?"
                new_path = path + [neighbor]
                new_edges = edges + [{"from": current, "to": neighbor, "proof": proof, "pa": pa}]
                
                if neighbor == target:
                    return {
                        "source": source, "target": target, "foundation": foundation,
                        "path": new_path, "edges": new_edges,
                        "steps": len(new_edges), "possible": True
                    }
                visited.add(neighbor)
                queue.append((neighbor, new_path, new_edges))
    
    return {
        "source": source, "target": target, "foundation": foundation,
        "path": [], "edges": [], "steps": -1, "possible": False,
        "error": f"No reduction path from {source} to {target} in the clique"
    }


def get_graph_schema() -> Dict[str, Any]:
    """Returns the graph for the React UI."""
    nodes = set()
    edges = []
    for src, targets in MINICRYPT_GRAPH.items():
        nodes.add(src)
        for tgt, data in targets.items():
            nodes.add(tgt)
            proof = data["proof"] if isinstance(data, dict) else data
            edges.append({"source": src, "target": tgt, "proof": proof})
    return {"nodes": sorted(list(nodes)), "edges": edges}


def get_foundation_chain(foundation: str, target_primitive: str) -> Dict:
    """Get the Foundation → Primitive chain for Column 1."""
    chains = FOUNDATION_CHAINS.get(foundation, {})
    if target_primitive in chains:
        return {"foundation": foundation, "target": target_primitive, "steps": chains[target_primitive], "supported": True}
    return {"foundation": foundation, "target": target_primitive, "steps": [], "supported": False,
            "error": f"No direct chain from {foundation} to {target_primitive}"}
