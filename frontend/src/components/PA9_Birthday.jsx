import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA9_Birthday() {
  const [nBits, setNBits] = useState(12)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const runAttack = async () => {
    setLoading(true)
    setResult(null)
    try {
      const data = await post('hash/birthday', { n_bits: nBits })
      setResult(data)
    } catch(e) { setResult({error:e.message}) }
    setLoading(false)
  }

  const expected = Math.floor(Math.sqrt(Math.PI / 2) * Math.pow(2, nBits / 2))
  const maxEval = expected * 4

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🎂 PA#9: Birthday Attack</div>
        <div className="panel-subtitle">Finds collisions in O(2^(n/2)) evaluations. The security floor of all hash functions.</div>
        
        <div style={{display:'flex',gap:'1rem',alignItems:'flex-end'}}>
          <div className="form-group" style={{flex:1}}>
            <label className="form-label">Truncated Output Size (n): {nBits} bits</label>
            <input type="range" min={8} max={20} step={2} value={nBits} onChange={e=>setNBits(Number(e.target.value))}
              style={{width:'100%',accentColor:'var(--accent-red)'}} />
            <div style={{fontSize:'0.75rem',color:'var(--text-muted)',display:'flex',justifyContent:'space-between'}}>
              <span>8-bit (fast)</span>
              <span>20-bit (slower)</span>
            </div>
          </div>
          <button className="btn btn-primary" style={{background:'var(--accent-red)'}} onClick={runAttack} disabled={loading}>
            {loading ? '⚔️ Hunting...' : '⚔️ Run Attack'}
          </button>
        </div>
      </div>

      {result && !result.error && (
        <div className="panel fade-in">
          <div className="panel-title" style={{color:'var(--accent-red)'}}>💥 Collision Found!</div>
          <div className="terminal">
            <div><strong>Message 1:</strong> <span className="mono">{result.msg1_hex}</span></div>
            <div><strong>Message 2:</strong> <span className="mono">{result.msg2_hex}</span></div>
            <div style={{marginTop:'0.5rem'}}>
              <strong>Shared Hash ({result.n_bits}-bit):</strong> <span className="mono" style={{color:'var(--accent-red)'}}>{result.hash_hex}</span>
            </div>
          </div>

          <div style={{marginTop:'1rem'}}>
            <div style={{display:'flex',justifyContent:'space-between',fontSize:'0.85rem'}}>
              <span>Expected evaluations: <strong>~{expected}</strong> (2^{nBits/2})</span>
              <span>Actual evaluations: <strong>{result.evaluations}</strong></span>
            </div>
            {/* Progress Bar visualization */}
            <div style={{position:'relative',height:'12px',background:'var(--surface-2)',borderRadius:'6px',marginTop:'0.5rem',overflow:'hidden'}}>
              <div style={{position:'absolute',left:0,top:0,bottom:0,
                width:`${Math.min(100, (result.evaluations / maxEval) * 100)}%`,
                background:'var(--accent-red)',transition:'width 1s'}} />
              {/* Expected marker */}
              <div style={{position:'absolute',left:`${(expected / maxEval) * 100}%`,top:0,bottom:0,width:'2px',background:'#fff',zIndex:1}} />
            </div>
            <div style={{display:'flex',justifyContent:'space-between',fontSize:'0.65rem',color:'var(--text-muted)',marginTop:'2px'}}>
              <span>0</span>
              <span style={{position:'absolute',left:`${(expected / maxEval) * 100}%`,transform:'translateX(-50%)'}}>Theoretical Bound</span>
            </div>
          </div>
        </div>
      )}
      {result?.error && (
        <div className="panel" style={{borderColor:'var(--accent-red)',color:'var(--accent-red)'}}>
          ⚠ {result.error}
        </div>
      )}
    </div>
  )
}
