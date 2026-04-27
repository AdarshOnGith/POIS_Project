import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA10_HMAC() {
  const [msg, setMsg] = useState('48656c6c6f')
  const [append, setAppend] = useState('41747461636b')
  const [hashType, setHashType] = useState('dlp')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const run = async () => {
    setLoading(true)
    try {
      const data = await post('hmac/length_extension_demo', {
        message_hex: msg || '00',
        append_hex: append || '00',
        hash_type: hashType
      })
      setResult(data)
    } catch(e) { console.error(e) }
    setLoading(false)
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🔐 PA#10: HMAC vs Naive MAC</div>
        <div className="panel-subtitle">Demonstrates why t = H(k||m) is vulnerable to Length Extension Attacks, while HMAC(k,m) = H(k⊕opad || H(k⊕ipad || m)) is secure.</div>
        
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Original Message m (Hex)</label>
            <input className="form-input mono" value={msg} onChange={e=>setMsg(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Attacker Append m' (Hex)</label>
            <input className="form-input mono" value={append} onChange={e=>setAppend(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Underlying Hash</label>
            <div style={{display:'flex',gap:'1rem',marginTop:'0.5rem',fontSize:'0.85rem'}}>
              <label><input type="radio" checked={hashType==='dlp'} onChange={()=>setHashType('dlp')} /> DLP Hash</label>
              <label><input type="radio" checked={hashType==='sha256'} onChange={()=>setHashType('sha256')} /> SHA-256</label>
            </div>
          </div>
          <button className="btn btn-primary" onClick={run} disabled={loading} style={{alignSelf:'flex-end'}}>
            {loading ? '⏳' : '▶ Compare'}
          </button>
        </div>
      </div>

      {result && (
        <div className="two-col">
          {/* Naive MAC */}
          <div className="panel" style={{borderColor:'var(--accent-red)'}}>
            <div className="panel-title" style={{color:'var(--accent-red)'}}>❌ Naive MAC: t = H(k||m)</div>
            <div className="terminal" style={{fontSize:'0.75rem'}}>
              <div>Original MAC(m): <span className="mono">{result.naive.tag_hex?.slice(0,32)}...</span></div>
              <div style={{marginTop:'0.5rem',color:'var(--accent-red)'}}>
                Extended MAC(m||pad||m'): <span className="mono">{result.naive.extended_tag_hex?.slice(0,32)}...</span>
              </div>
              <div style={{marginTop:'0.5rem',fontWeight:'bold',color:'var(--accent-red)'}}>
                {result.naive.message}
              </div>
              <div style={{marginTop:'0.3rem',color:'var(--text-muted)'}}>
                Because the hash state is simply H(k||m), the attacker can use it as the IV to continue hashing m' without knowing k.
              </div>
            </div>
          </div>

          {/* HMAC */}
          <div className="panel" style={{borderColor:'var(--accent-green)'}}>
            <div className="panel-title" style={{color:'var(--accent-green)'}}>✓ Secure: HMAC</div>
            <div className="terminal" style={{fontSize:'0.75rem'}}>
              <div>Original HMAC(m): <span className="mono">{result.hmac.tag_hex?.slice(0,32)}...</span></div>
              <div style={{marginTop:'0.5rem',color:'var(--accent-red)'}}>
                Attempted Extension: <span className="mono">{result.hmac.extended_tag_hex?.slice(0,32)}...</span>
              </div>
              <div style={{marginTop:'0.5rem',fontWeight:'bold',color:'var(--accent-green)'}}>
                {result.hmac.message}
              </div>
              <div style={{marginTop:'0.3rem',color:'var(--text-muted)'}}>
                The outer hash H(k⊕opad || inner_hash) completely encapsulates the internal state. The attacker cannot extend the inner hash because it is sealed by the outer keyed hash.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
