import { useState, useEffect } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

// ToyXOR logic from backend: (cv ^ b1) ^ b2
const computeHash = (cvHex, blockHex) => {
  const cv = parseInt(cvHex, 16)
  const b1 = parseInt(blockHex.slice(0,8).padEnd(8,'0'), 16)
  const b2 = parseInt(blockHex.slice(8,16).padEnd(8,'0'), 16)
  return ((cv ^ b1 ^ b2) >>> 0).toString(16).padStart(8, '0')
}

export default function PA7_MD() {
  const [inputType, setInputType] = useState('text')
  const [inputVal, setInputVal] = useState('Hello World!')
  const [baseTrace, setBaseTrace] = useState(null)
  const [overrides, setOverrides] = useState({})
  const [loading, setLoading] = useState(false)

  const toHex = (str) => Array.from(str).map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join('')

  useEffect(() => {
    const run = async () => {
      setLoading(true)
      try {
        const hex = inputType === 'text' ? toHex(inputVal) : inputVal.replace(/[^0-9a-fA-F]/g, '')
        if (hex.length % 2 !== 0) return
        const data = await post('hash/md_trace', { message_hex: hex || '00', block_size: 8 })
        setBaseTrace(data)
        setOverrides({}) // reset edits
      } catch(e) { console.error(e) }
      setLoading(false)
    }
    const t = setTimeout(run, 300)
    return () => clearTimeout(t)
  }, [inputVal, inputType])

  // Recompute trace locally if there are overrides
  const trace = baseTrace ? JSON.parse(JSON.stringify(baseTrace)) : null
  if (trace) {
    let current_cv = trace.iv
    for (let i = 0; i < trace.blocks.length; i++) {
      let b = trace.blocks[i]
      b.cv_in = current_cv
      if (overrides[i] !== undefined) {
        b.block = overrides[i]
      }
      // Ensure block is exactly 16 hex chars (8 bytes) for the toy hash
      const blockPadded = b.block.padEnd(16, '0').slice(0,16)
      b.cv_out = computeHash(b.cv_in, blockPadded)
      current_cv = b.cv_out
    }
    trace.digest_hex = current_cv
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🧱 PA#7: Merkle-Damgård Transform</div>
        <div className="panel-subtitle">Extends a fixed-length compression function h(cv, block) to arbitrary-length messages. Demonstrates MD-strengthening padding.</div>
        
        <div style={{display:'flex',gap:'1rem',alignItems:'flex-end'}}>
          <div className="form-group" style={{flex:1}}>
            <div style={{display:'flex',justifyContent:'space-between'}}>
              <label className="form-label">Message Input</label>
              <div style={{fontSize:'0.75rem',display:'flex',gap:'0.5rem'}}>
                <label><input type="radio" checked={inputType==='text'} onChange={()=>setInputType('text')}/> Text</label>
                <label><input type="radio" checked={inputType==='hex'} onChange={()=>setInputType('hex')}/> Hex</label>
              </div>
            </div>
            <input className={`form-input ${inputType==='hex'?'mono':''}`} value={inputVal} onChange={e=>setInputVal(e.target.value)} placeholder="Enter message..." />
          </div>
        </div>
      </div>

      {trace && !trace.error && (
        <div>
          <div className="panel">
            <div className="panel-title">1. MD-Strengthening Padding</div>
            <div className="terminal">
              <div>Original ({inputType}): <span className="mono">{inputType==='text'?toHex(inputVal):inputVal}</span></div>
              <div style={{marginTop:'0.3rem',wordBreak:'break-all'}}>Padded Message: <span className="mono" style={{color:'var(--accent-blue)'}}>{trace.padded_message}</span></div>
              <div style={{fontSize:'0.75rem',color:'var(--text-muted)',marginTop:'0.2rem'}}>
                Append 0x80 (1-bit), then 0x00 bytes until length ≡ 0 mod block_size (excluding 64-bit length), then 64-bit original length.
              </div>
            </div>
          </div>

          <div className="panel">
            <div className="panel-title">2. Chaining Evaluation (Toy XOR Compression)</div>
            <div className="panel-subtitle">Edit any block below to see the avalanche effect propagate down the chain.</div>
            <div style={{display:'flex',flexDirection:'column',gap:'0.5rem',marginTop:'0.5rem',fontFamily:'monospace',fontSize:'0.8rem'}}>
              <div style={{display:'flex',alignItems:'center',gap:'1rem'}}>
                <div style={{padding:'0.4rem',background:'var(--surface-2)',borderRadius:'4px',border:'1px solid var(--text-muted)'}}>
                  IV = <span style={{color:'var(--accent-green)'}}>{trace.iv}</span>
                </div>
              </div>
              
              {trace.blocks?.map((b,i) => (
                <div key={i} style={{display:'flex',alignItems:'center',gap:'0.5rem'}} className="fade-in">
                  <div style={{color:'var(--text-muted)'}}>↓</div>
                  <div style={{padding:'0.5rem',background:'var(--surface-2)',borderRadius:'6px',flex:1,display:'flex',alignItems:'center',justifyContent:'space-between'}}>
                    <div style={{display:'flex',alignItems:'center'}}>
                      <span style={{color:'var(--text-muted)'}}>cv_in:</span> <span style={{color:'var(--accent-green)'}}>{b.cv_in}</span>
                      <span style={{color:'var(--text-muted)',margin:'0 0.5rem'}}>+</span>
                      <span style={{color:'var(--text-muted)'}}>M_{i+1}:</span> 
                      <input 
                        className="form-input mono" 
                        style={{width:'150px', padding:'0.2rem', marginLeft:'0.5rem', background: overrides[i] ? 'var(--bg-color)' : 'transparent', border: overrides[i] ? '1px solid var(--accent-blue)' : '1px solid transparent', color:'var(--accent-blue)'}}
                        value={b.block}
                        onChange={(e) => setOverrides({...overrides, [i]: e.target.value.replace(/[^0-9a-fA-F]/g, '')})}
                        maxLength={16}
                      />
                    </div>
                    <div>
                      <span style={{color:'var(--text-muted)'}}>→ h() → </span> <span style={{color:'var(--accent-red)',fontWeight:'bold',transition:'color 0.3s'}}>{b.cv_out}</span>
                    </div>
                  </div>
                </div>
              ))}
              
              <div style={{marginTop:'0.5rem',padding:'0.5rem',background:'var(--accent-red)',color:'#fff',borderRadius:'6px',display:'inline-block',alignSelf:'flex-start'}}>
                <strong>H(M) = {trace.digest_hex}</strong>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
