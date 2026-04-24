from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import sys
import os

# Ensure the backend directory is in the path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.core.minicrypt import (
    DLP_OWF, 
    HILL_PRG, 
    CPA_Symmetric, 
    CCA_Symmetric,
    PRF_MAC,
    dlp_hash
)
from app.core.routing import reduce_primitive, get_graph_schema

app = FastAPI(title="Minicrypt Clique Web Explorer API")

# Setup CORS for the React frontend to communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- Models -----------------

class OWFEvaluateRequest(BaseModel):
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

class HashRequest(BaseModel):
    message_hex: str
    out_len: int = 32
class RoutingRequest(BaseModel):
    source: str
    target: str
    foundation: str = "Standard"
# ----------------- API Endpoints -----------------

@app.post("/api/owf/evaluate")
def owf_evaluate(req: OWFEvaluateRequest):
    """PA #1: Evaluate One-Way Function"""
    return {"y": DLP_OWF.evaluate(req.x)}

@app.post("/api/prg/next_bits")
def prg_next(req: PRGRequest):
    """PA #1: PRG Forward Direction"""
    try:
        prg = HILL_PRG()
        prg.seed(bytes.fromhex(req.seed_hex))
        output_bytes = prg.next_bits(req.n_bits)
        return {"output_hex": output_bytes.hex()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/cpa/encrypt")
def cpa_encrypt(req: EncryptRequest):
    """PA #3: CPA-Secure Encryption"""
    try:
        key = bytes.fromhex(req.key_hex)
        msg = bytes.fromhex(req.message_hex)
        cpa = CPA_Symmetric(key)
        r, c = cpa.encrypt(msg)
        return {"r_hex": r.hex(), "ciphertext_hex": c.hex()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/cpa/decrypt")
def cpa_decrypt(req: DecryptRequest):
    """PA #3: CPA-Secure Decryption"""
    try:
        key = bytes.fromhex(req.key_hex)
        r = bytes.fromhex(req.r_hex)
        c = bytes.fromhex(req.ciphertext_hex)
        cpa = CPA_Symmetric(key)
        m = cpa.decrypt(r, c)
        return {"message_hex": m.hex()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/hash/dlp")
def hash_message(req: HashRequest):
    """PA #8: DLP-Based CRHF Hash"""
    try:
        msg = bytes.fromhex(req.message_hex)
        digest = dlp_hash(msg, req.out_len)
        return {"digest_hex": digest.hex()}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/graph/reduce")
def calculate_reduction_path(req: RoutingRequest):
    """Phase 3: Computes shortest path across the cryptanalysis clique graph."""
    res = reduce_primitive(req.source, req.target, req.foundation)
    if not res["possible"]:
        if "error" in res:
            raise HTTPException(status_code=400, detail=res["error"])
        raise HTTPException(status_code=404, detail=f"No reducible path from {req.source} to {req.target}")
    return res

@app.get("/api/graph/schema")
def fetch_graph_schema():
    """Fetches the full PA graph specification of nodes and edges."""
    return get_graph_schema()

@app.get("/")
def read_root():
    return {"message": "Minicrypt Clique API is running. Check /docs for endpoints."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
