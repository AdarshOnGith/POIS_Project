from typing import List, Dict, Any

# ==============================================================================
# PA #3: The Clique Graph Routing Table
# ==============================================================================
# Maps the logical cryptanalysis reductions within the Minicrypt framework.
# Keys are source primitives; values are dicts of target primitives and their reduction proofs.

MINICRYPT_GRAPH = {
    "DLP Group": {
        "OWF": "Modular Exponentiation (Discrete Log Problem)",
        "CRHF": "PA#8 (Pedersen Hash / Collision Resistant Hash)"
    },
    "Fixed-Length Compression": {
        "Hash": "PA#7 (Merkle-Damgård Transform)"
    },
    "OWF": {
        "PRG": "PA#1 (HILL PRG Variant / Hard-Core Predicate)"
    },
    "PRG": {
        "OWF": "Bidirectional PA#1 (f(s) = G(s))",
        "PRF": "PA#2 (GGM Tree Evaluation)"
    },
    "PRF": {
        "PRG": "Bidirectional PA#2 (G(s) = F_s(0^n) || F_s(1^n))",
        "CPA": "PA#3 (Encrypt-then-PRF / Block Cipher)",
        "MAC": "PA#5 (CBC-MAC Construction)",
        "CPA_Modes": "PA#4 (CBC, OFB, CTR block encapsulation)"
    },
    "MAC": {
        "PRF": "Bidirectional PA#5 (Standard equivalence)",
        "CRHF": "Bidirectional PA#10 (HMAC block conversion)",
        "CCA": "PA#6 (Encrypt-then-MAC - requires CPA input)"
    },
    "CPA": {
        "CCA": "PA#6 (Encrypt-then-MAC - requires MAC input)"
    },
    "CRHF": {
        "MAC": "PA#10 (HMAC Structure)"
    }
}

def reduce_primitive(source: str, target: str, foundation: str = "Standard") -> Dict[str, Any]:
    """
    Executes a BFS unweighted shortest-path algorithm across the Minicrypt
    reduction graph, answering whether a Target primitive can be constructed
    assuming the Source primitive exists, and outlining the exact proof steps.
    """
    if source not in MINICRYPT_GRAPH and source != "Hash":
        return {"possible": False, "error": f"Unknown source primitive: {source}"}
        
    if source == target:
        return {
            "source": source,
            "target": target,
            "foundation": foundation,
            "path": [source],
            "edges": [],
            "steps": 0,
            "possible": True
        }
        
    # BFS Queue: (Current_Node, Path_So_Far, Edges_Taken)
    queue = [(source, [source], [])]
    visited = {source}
    
    while queue:
        current_node, current_path, current_edges = queue.pop(0)
        
        # Traverse connections
        for neighbor, edge_proof in MINICRYPT_GRAPH.get(current_node, {}).items():
            if neighbor not in visited:
                new_path = current_path + [neighbor]
                new_edges = current_edges + [{"from": current_node, "to": neighbor, "proof": edge_proof}]
                
                if neighbor == target:
                    return {
                        "source": source,
                        "target": target,
                        "foundation": foundation,
                        "path": new_path,
                        "edges": new_edges,
                        "steps": len(new_edges),
                        "possible": True
                    }
                    
                visited.add(neighbor)
                queue.append((neighbor, new_path, new_edges))
                
    return {
        "source": source,
        "target": target,
        "foundation": foundation,
        "path": [],
        "edges": [],
        "steps": -1,
        "possible": False
    }

def get_graph_schema() -> Dict[str, Any]:
    """Returns the entire graph for the React UI to consume and visualize."""
    nodes = set()
    edges = []
    
    for src, targets in MINICRYPT_GRAPH.items():
        nodes.add(src)
        for tgt, proof in targets.items():
            nodes.add(tgt)
            edges.append({"source": src, "target": tgt, "proof": proof})
            
    return {
        "nodes": list(nodes),
        "edges": edges
    }
