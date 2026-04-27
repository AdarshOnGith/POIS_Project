import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA5_MAC() {
  const [tab,setTab]=useState('forge')
  const [gameId,setGameId]=useState(null)
  const [signed,setSigned]=useState([])
  const [forgeMsg,setForgeMsg]=useState('')
  const [forgeTag,setForgeTag]=useState('')
  const [attempts,setAttempts]=useState(0)
  const [successes,setSuccesses]=useState(0)
  const [results,setResults]=useState([])

  const initGame = async () => {
    const data = await post('mac/game_init',{})
    setGameId(data.game_id)
    setSigned(data.signed_messages)
    setAttempts(0); setSuccesses(0); setResults([])
  }

  const queryOracle = async () => {
    if (!gameId || !forgeMsg) return
    const data = await post('mac/game_query',{game_id:gameId,message_hex:forgeMsg,tag_hex:''})
    setSigned(prev=>[...prev,data])
  }

  const submitForgery = async () => {
    if (!gameId || !forgeMsg || !forgeTag) return
    const data = await post('mac/game_forge',{game_id:gameId,message_hex:forgeMsg,tag_hex:forgeTag})
    setAttempts(a=>a+1)
    if (data.valid_forgery) setSuccesses(s=>s+1)
    setResults(prev=>[...prev,{msg:forgeMsg,tag:forgeTag,...data}])
  }

  // Length extension demo
  const [leKey]=useState('secret_key_1234!')
  const [leMsg,setLeMsg]=useState('48656c6c6f')
  const [leResult,setLeResult]=useState(null)
  const runLE = async () => {
    const original = await post('mac/compute',{key_hex:'00112233445566778899aabbccddeeff',message_hex:leMsg})
    const extended = await post('mac/compute',{key_hex:'00112233445566778899aabbccddeeff',message_hex:leMsg+'616464656420646174612121'})
    setLeResult({original,extended,appended:'616464656420646174612121'})
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🔐 PA#5: MAC — Forgery Game</div>
        <div style={{display:'flex',gap:'4px',marginBottom:'0.75rem'}}>
          <button className={`btn ${tab==='forge'?'btn-primary':'btn-secondary'}`} onClick={()=>setTab('forge')}>Forgery Game</button>
          <button className={`btn ${tab==='length'?'btn-primary':'btn-secondary'}`} onClick={()=>setTab('length')}>Length Extension</button>
        </div>
      </div>

      {tab === 'forge' && (
        <div>
          <div className="panel">
            <div className="panel-subtitle">You see signed messages (m, t). Try to forge a valid tag on a NEW message.</div>
            {!gameId && <button className="btn btn-primary" onClick={initGame}>🎮 Start Game</button>}
            {gameId && (
              <div>
                <div style={{maxHeight:'180px',overflowY:'auto',marginBottom:'0.5rem',fontSize:'0.75rem'}}>
                  {signed.map((s,i)=>(
                    <div key={i} style={{display:'flex',gap:'1rem',padding:'2px 0',borderBottom:'1px solid var(--surface-2)',fontFamily:'monospace'}}>
                      <span style={{color:'var(--text-muted)'}}>#{i+1}</span>
                      <span>m={s.message_hex?.slice(0,16)}...</span>
                      <span style={{color:'var(--accent-blue)'}}>t={s.tag_hex?.slice(0,16)}...</span>
                    </div>
                  ))}
                </div>
                <div className="form-row">
                  <div className="form-group"><label className="form-label">New message m* (hex)</label>
                    <input className="form-input mono" value={forgeMsg} onChange={e=>setForgeMsg(e.target.value)} /></div>
                  <div className="form-group"><label className="form-label">Forged tag t* (hex)</label>
                    <input className="form-input mono" value={forgeTag} onChange={e=>setForgeTag(e.target.value)} /></div>
                </div>
                <div style={{display:'flex',gap:'0.5rem'}}>
                  <button className="btn btn-primary" onClick={submitForgery}>🔨 Submit Forgery</button>
                  <button className="btn btn-secondary" onClick={queryOracle}>📝 Query Oracle</button>
                </div>
                <div style={{marginTop:'0.5rem',fontSize:'0.85rem'}}>
                  Attempts: <strong>{attempts}</strong> | Successes: <strong style={{color:successes>0?'var(--accent-red)':'var(--accent-green)'}}>{successes}</strong>
                </div>
              </div>
            )}
          </div>
          {results.length > 0 && (
            <div className="terminal">
              {results.map((r,i)=>(
                <div key={i} style={{padding:'2px 0',fontSize:'0.8rem'}}>
                  <span style={{color:r.valid_forgery?'var(--accent-red)':'var(--accent-green)'}}>
                    {r.valid_forgery?'✓ FORGERY ACCEPTED!':'✗ Rejected'}
                  </span>
                  <span className="mono" style={{marginLeft:'0.5rem'}}>{r.msg?.slice(0,12)}... → {r.tag?.slice(0,12)}...</span>
                  {r.reason && <span style={{color:'var(--text-muted)',marginLeft:'0.5rem'}}>{r.reason}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {tab === 'length' && (
        <div className="panel">
          <div className="panel-title">⚠ Length Extension Attack on H(k||m)</div>
          <div className="panel-subtitle">Naive MAC t=H(k||m) allows appending data without knowing k. HMAC's double-hash structure prevents this.</div>
          <div className="form-row">
            <div className="form-group"><label className="form-label">Message (hex)</label>
              <input className="form-input mono" value={leMsg} onChange={e=>setLeMsg(e.target.value)} /></div>
            <button className="btn btn-primary" onClick={runLE} style={{alignSelf:'flex-end'}}>▶ Demonstrate</button>
          </div>
          {leResult && (
            <div className="terminal" style={{marginTop:'0.5rem'}}>
              <div>Original MAC(m): <span className="mono" style={{color:'var(--accent-green)'}}>{leResult.original.tag_hex}</span></div>
              <div>MAC(m||pad||m'): <span className="mono" style={{color:'var(--accent-red)'}}>{leResult.extended.tag_hex}</span></div>
              <div style={{marginTop:'0.3rem',fontSize:'0.8rem',color:'var(--text-muted)'}}>
                In a naive H(k||m) scheme, the attacker can compute the extended tag from the original tag alone, without knowing k.
                HMAC prevents this with its double-hash: HMAC_k(m) = H((k⊕opad) || H((k⊕ipad) || m))
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
