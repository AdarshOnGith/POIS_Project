import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA4_Modes() {
  const [mode,setMode]=useState('CTR')
  const [key]=useState('00112233445566778899aabbccddeeff')
  const [iv]=useState('aabbccddeeff00112233445566778899')
  const [msg]=useState('48656c6c6f20576f726c642121212121'+'5365636f6e6420626c6f636b21212121'+'546869726420626c6f636b2121212121')
  const [trace,setTrace]=useState(null)
  const [reuseIV,setReuseIV]=useState(false)
  const [msg2]=useState('446966666572656e74206d657373616765'+'446966666572656e74206d657373616765'+'446966666572656e74206d657373616765')
  const [trace2,setTrace2]=useState(null)
  const [flipByte,setFlipByte]=useState(0)

  const encrypt = async (m) => {
    const r = await post('modes/encrypt_trace',{key_hex:key,iv_hex:iv,message_hex:m||msg,mode})
    return r
  }

  const run = async () => {
    setTrace(await encrypt(msg))
    if (reuseIV) setTrace2(await encrypt(msg2))
    else setTrace2(null)
  }

  const flipBit = async () => {
    const r = await post('modes/bitflip',{key_enc_hex:key,message_hex:msg,flip_byte:flipByte,flip_bit:0})
    setTrace(prev=>({...prev, bitflip: r}))
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">📦 PA#4: Block Cipher Mode Animator</div>
        <div className="panel-subtitle">3-block message encrypted with CBC/OFB/CTR. Shows per-block intermediate values.</div>
        <div style={{display:'flex',gap:'4px',marginBottom:'0.75rem'}}>
          {['CBC','OFB','CTR'].map(m=>(
            <button key={m} className={`btn ${mode===m?'btn-primary':'btn-secondary'}`} onClick={()=>{setMode(m);setTrace(null);setTrace2(null)}}>{m}</button>
          ))}
        </div>
        <div style={{display:'flex',gap:'0.5rem',alignItems:'center',flexWrap:'wrap'}}>
          <button className="btn btn-primary" onClick={run}>▶ Encrypt</button>
          <label style={{display:'flex',alignItems:'center',gap:'0.4rem',cursor:'pointer',fontSize:'0.85rem'}}>
            <input type="checkbox" checked={reuseIV} onChange={e=>setReuseIV(e.target.checked)} style={{accentColor:'var(--accent-red)'}} />
            <span style={{color:reuseIV?'var(--accent-red)':'var(--text-muted)'}}>⚠ Reuse IV</span>
          </label>
          <div style={{marginLeft:'auto',display:'flex',gap:'0.3rem',alignItems:'center'}}>
            <span style={{fontSize:'0.8rem'}}>Flip byte:</span>
            <input type="number" min={0} max={47} value={flipByte} onChange={e=>setFlipByte(Number(e.target.value))}
              className="form-input" style={{width:'60px',padding:'2px 6px'}} />
            <button className="btn btn-secondary" onClick={flipBit} style={{padding:'4px 10px'}}>Flip Bit</button>
          </div>
        </div>
      </div>

      {trace?.blocks && (
        <div>
          <div className="terminal-label">{mode} — Per-Block Trace</div>
          <div className="terminal">
            <div style={{display:'flex',gap:'8px',flexWrap:'wrap',marginBottom:'0.5rem'}}>
              {trace.blocks.map((b,i)=>(
                <div key={i} style={{background:'var(--surface-2)',padding:'0.5rem',borderRadius:'6px',flex:'1',minWidth:'200px',fontSize:'0.7rem',fontFamily:'monospace'}}>
                  <div style={{color:'var(--accent-blue)',fontWeight:'bold',marginBottom:'0.3rem'}}>Block {i+1}</div>
                  <div>PT: <span style={{color:'var(--accent-green)'}}>{b.plaintext?.slice(0,16)}...</span></div>
                  {b.counter && <div>CTR: {b.counter?.slice(0,16)}...</div>}
                  {b.prf_output && <div>F_k: {b.prf_output?.slice(0,16)}...</div>}
                  {b.xor_input && <div>XOR: {b.xor_input?.slice(0,16)}...</div>}
                  {b.keystream && <div>KS: {b.keystream?.slice(0,16)}...</div>}
                  <div style={{color:'var(--accent-blue)'}}>CT: {b.ciphertext?.slice(0,16)}...</div>
                </div>
              ))}
            </div>
            {mode==='CBC' && <div style={{fontSize:'0.75rem',color:'var(--text-muted)'}}>Error propagation: flipping 1 CT block corrupts 2 PT blocks</div>}
            {mode==='CTR' && <div style={{fontSize:'0.75rem',color:'var(--text-muted)'}}>No error propagation: flipping 1 CT bit only corrupts that PT bit</div>}
          </div>

          {reuseIV && trace2?.blocks && (
            <div style={{marginTop:'0.5rem'}}>
              <div className="terminal-label" style={{color:'var(--accent-red)'}}>⚠ IV Reuse Attack — Same IV, Different Message</div>
              <div className="terminal">
                <div style={{display:'flex',gap:'8px',flexWrap:'wrap'}}>
                  {trace.blocks.map((b,i)=>{
                    const b2 = trace2.blocks[i]
                    const match = b?.ciphertext === b2?.ciphertext
                    return (
                      <div key={i} style={{background: match ? 'rgba(255,80,80,0.15)' : 'var(--surface-2)',
                        padding:'0.5rem',borderRadius:'6px',flex:'1',minWidth:'150px',fontSize:'0.7rem',fontFamily:'monospace',
                        border: match ? '1px solid var(--accent-red)' : 'none'}}>
                        <div>CT₁: {b.ciphertext?.slice(0,12)}...</div>
                        <div>CT₂: {b2?.ciphertext?.slice(0,12)}...</div>
                        {match && <div style={{color:'var(--accent-red)',fontWeight:'bold'}}>⚠ MATCH — identical blocks leaked!</div>}
                      </div>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {trace.bitflip && (
            <div style={{marginTop:'0.5rem'}}>
              <div className="terminal-label">Bit Flip Result (byte {trace.bitflip.flip_byte})</div>
              <div className="terminal">
                <div>Original PT: <span className="mono">{trace.bitflip.original_pt.slice(0,32)}...</span></div>
                <div>Modified PT: <span className="mono" style={{color:'var(--accent-red)'}}>{trace.bitflip.modified_pt.slice(0,32)}...</span></div>
                <div style={{marginTop:'0.3rem'}}>Corrupted bytes: [{trace.bitflip.corrupted_bytes.join(', ')}]</div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
