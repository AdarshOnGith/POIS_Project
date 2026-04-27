import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA6_CCA() {
  const [flipByte,setFlipByte]=useState(0)
  const [flipBit,setFlipBit]=useState(0)
  const [result,setResult]=useState(null)
  const [loading,setLoading]=useState(false)

  const run = async () => {
    setLoading(true)
    try {
      setResult(await post('cca/malleability_demo',{
        key_enc_hex:'00112233445566778899aabbccddeeff',
        key_mac_hex:'ffeeddccbbaa99887766554433221100',
        message_hex:'48656c6c6f20576f726c642121212121',
        flip_byte:flipByte, flip_bit:flipBit
      }))
    } catch(e) { setResult({error:e.message}) }
    setLoading(false)
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🛡️ PA#6: CCA Security — Malleability Attack</div>
        <div className="panel-subtitle">Side-by-side: CPA-only (malleable) vs Encrypt-then-MAC (CCA-secure). Flip a ciphertext bit and compare.</div>
        <div style={{display:'flex',gap:'1rem',alignItems:'flex-end',flexWrap:'wrap'}}>
          <div className="form-group" style={{maxWidth:'100px'}}>
            <label className="form-label">Flip byte</label>
            <input className="form-input" type="number" min={0} max={15} value={flipByte} onChange={e=>setFlipByte(Number(e.target.value))} />
          </div>
          <div className="form-group" style={{maxWidth:'100px'}}>
            <label className="form-label">Flip bit</label>
            <input className="form-input" type="number" min={0} max={7} value={flipBit} onChange={e=>setFlipBit(Number(e.target.value))} />
          </div>
          <button className="btn btn-primary" onClick={run} disabled={loading}>{loading?'⏳...':'⚡ Flip & Compare'}</button>
        </div>
      </div>

      {result && !result.error && (
        <div className="two-col">
          {/* CPA side */}
          <div className="panel" style={{borderColor:'var(--accent-red)'}}>
            <div className="panel-title" style={{color:'var(--accent-red)'}}>❌ CPA-Only (Malleable!)</div>
            <div className="terminal" style={{fontSize:'0.75rem'}}>
              <div>Original CT: <span className="mono">{result.cpa_side.original_ct?.slice(0,32)}...</span></div>
              <div style={{color:'var(--accent-red)'}}>Modified CT: <span className="mono">{result.cpa_side.modified_ct?.slice(0,32)}...</span></div>
              <div style={{marginTop:'0.5rem'}}>
                <div>Original PT: <span className="mono">{result.original_message}</span></div>
                <div style={{color:'var(--accent-red)'}}>Corrupted PT: <span className="mono">{result.cpa_side.decrypted_hex}</span></div>
              </div>
              <div style={{marginTop:'0.5rem',color:'var(--accent-red)',fontWeight:'bold'}}>
                ⚠ Plaintext modified without detection! Bit flip propagated silently.
              </div>
            </div>
          </div>

          {/* CCA side */}
          <div className="panel" style={{borderColor:'var(--accent-green)'}}>
            <div className="panel-title" style={{color:'var(--accent-green)'}}>✓ CCA / Encrypt-then-MAC</div>
            <div className="terminal" style={{fontSize:'0.75rem'}}>
              <div>Original CT: <span className="mono">{result.cca_side.original_ct?.slice(0,32)}...</span></div>
              <div style={{color:'var(--accent-red)'}}>Modified CT: <span className="mono">{result.cca_side.modified_ct?.slice(0,32)}...</span></div>
              <div>MAC Tag: <span className="mono" style={{color:'var(--accent-blue)'}}>{result.cca_side.tag?.slice(0,32)}...</span></div>
              <div style={{marginTop:'0.5rem'}}>
                {result.cca_side.rejected ? (
                  <div style={{color:'var(--accent-green)',fontWeight:'bold'}}>
                    ✓ REJECTED — ⊥<br/>
                    <span style={{fontWeight:'normal'}}>MAC verification failed. Tampered ciphertext detected and rejected.</span>
                  </div>
                ) : (
                  <div style={{color:'var(--accent-red)'}}>Decrypted: {result.cca_side.decrypted_hex}</div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
