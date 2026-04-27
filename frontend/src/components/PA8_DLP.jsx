import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA8_DLP() {
  const [inputVal, setInputVal] = useState('48656c6c6f')
  const [digest, setDigest] = useState(null)
  const [loading, setLoading] = useState(false)
  const [huntLoading, setHuntLoading] = useState(false)
  const [huntResult, setHuntResult] = useState(null)

  const hash = async () => {
    setLoading(true)
    try {
      const data = await post('hash/dlp', { message_hex: inputVal, out_len: 32 })
      setDigest(data.digest_hex)
    } catch(e) { console.error(e) }
    setLoading(false)
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🔗 PA#8: DLP-Based CRHF</div>
        <div className="panel-subtitle">Collision-Resistant Hash Function based on Discrete Logarithm Problem: h(x,y) = g^x · h^y mod p</div>
        
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Message (Hex)</label>
            <input className="form-input mono" value={inputVal} onChange={e=>setInputVal(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={hash} disabled={loading} style={{alignSelf:'flex-end'}}>
            {loading ? '⏳' : '▶ Hash'}
          </button>
        </div>

        {digest && (
          <div className="terminal" style={{marginTop:'0.75rem'}}>
            <div style={{color:'var(--text-muted)'}}>DLP Hash Digest (256-bit):</div>
            <div className="mono" style={{color:'var(--accent-green)',wordBreak:'break-all'}}>{digest}</div>
          </div>
        )}

        <div style={{marginTop:'1.5rem',borderTop:'1px solid var(--surface-2)',paddingTop:'1rem'}}>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'center'}}>
            <div>
              <div style={{fontWeight:'bold'}}>Collision Hunt (Toy 16-bit output)</div>
              <div style={{fontSize:'0.75rem',color:'var(--text-muted)'}}>Run birthday attack to find a collision on truncated output.</div>
            </div>
            <button className="btn" style={{border:'1px solid var(--accent-red)',color:'var(--accent-red)'}} onClick={async () => {
              setHuntLoading(true)
              try {
                const data = await post('hash/birthday', { n_bits: 16 })
                setHuntResult(data)
              } catch(e) { setHuntResult({error:e.message}) }
              setHuntLoading(false)
            }} disabled={huntLoading}>
              {huntLoading ? '⚔️ Hunting...' : '⚔️ Collision Hunt'}
            </button>
          </div>
          
          {huntResult && !huntResult.error && (
            <div className="terminal fade-in" style={{marginTop:'1rem',fontSize:'0.75rem'}}>
              <div><strong>Hashes evaluated:</strong> {huntResult.evaluations} (Expected ~256)</div>
              <div><strong>Message 1:</strong> <span className="mono">{huntResult.msg1_hex}</span></div>
              <div><strong>Message 2:</strong> <span className="mono">{huntResult.msg2_hex}</span></div>
              <div style={{marginTop:'0.5rem',color:'var(--accent-red)'}}>
                <strong>Shared Hash (16-bit):</strong> <span className="mono">{huntResult.hash_hex}</span>
              </div>
            </div>
          )}
          {huntResult?.error && <div style={{color:'var(--accent-red)',marginTop:'0.5rem'}}>⚠ {huntResult.error}</div>}
        </div>
      </div>

      <div className="panel">
        <div className="panel-title">Security Proof (CRHF under DLP)</div>
        <div style={{fontSize:'0.85rem',lineHeight:'1.6',color:'var(--text-muted)'}}>
          If an adversary finds a collision <code>h(x, y) = h(x', y')</code> with <code>(x,y) ≠ (x',y')</code>:<br/>
          <code>g^x · h^y ≡ g^x' · h^y' (mod p)</code><br/>
          <code>g^(x - x') ≡ h^(y' - y) (mod p)</code><br/>
          Since <code>h = g^α</code>, this means <code>x - x' ≡ α(y' - y) (mod q)</code>.<br/>
          The adversary can then efficiently compute <code>α = (x - x') / (y' - y) mod q</code>, thus solving the Discrete Logarithm Problem.
          <br/><br/>
          Since DLP is assumed hard, finding collisions must be hard.
        </div>
        <div style={{marginTop:'0.5rem',padding:'0.5rem',background:'rgba(255,165,0,0.1)',color:'orange',borderRadius:'4px',fontSize:'0.85rem'}}>
          <strong>Next:</strong> Go to PA#9 to see what happens when the output size is too small, breaking the collision resistance via the Birthday Attack.
        </div>
      </div>
    </div>
  )
}
