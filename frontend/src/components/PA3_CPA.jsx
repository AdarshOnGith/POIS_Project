import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA3_CPA() {
  const [m0,setM0]=useState('48656c6c6f20776f726c6421')  // "Hello world!"
  const [m1,setM1]=useState('476f6f646279652121212121')  // "Goodbye!!!!!"
  const [nonceReuse,setNonceReuse]=useState(false)
  const [gameId,setGameId]=useState(null)
  const [challenge,setChallenge]=useState(null)
  const [rounds,setRounds]=useState([])
  const [loading,setLoading]=useState(false)

  const advantage = rounds.length > 0
    ? Math.abs(rounds.filter(r=>r.correct).length / rounds.length - 0.5)
    : 0

  const startRound = async () => {
    setLoading(true)
    try {
      const data = await post('cpa/game_start',{m0_hex:m0,m1_hex:m1,nonce_reuse:nonceReuse})
      setGameId(data.game_id)
      setChallenge(data)
    } catch(e) { setChallenge({error:e.message}) }
    setLoading(false)
  }

  const guess = async (g) => {
    if (!gameId) return
    const data = await post('cpa/game_guess',{game_id:gameId,guess:g})
    setRounds(prev=>[...prev,data])
    setGameId(null)
    setChallenge(null)
  }

  const reset = () => { setRounds([]); setGameId(null); setChallenge(null) }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🎮 PA#3: IND-CPA Security Game</div>
        <div className="panel-subtitle">You are the adversary. Submit two messages, get C* = Enc(m_b), guess b. Advantage should be ≈0 in secure mode.</div>
        <div className="form-row">
          <div className="form-group"><label className="form-label">m₀ (hex)</label>
            <input className="form-input mono" value={m0} onChange={e=>setM0(e.target.value)} /></div>
          <div className="form-group"><label className="form-label">m₁ (hex, same length)</label>
            <input className="form-input mono" value={m1} onChange={e=>setM1(e.target.value)} /></div>
        </div>
        <div style={{display:'flex',gap:'1rem',alignItems:'center',marginTop:'0.5rem',flexWrap:'wrap'}}>
          <button className="btn btn-primary" onClick={startRound} disabled={loading||!!gameId}>
            {loading?'⏳...':'🔐 Encrypt (new round)'}
          </button>
          <label style={{display:'flex',alignItems:'center',gap:'0.4rem',cursor:'pointer',fontSize:'0.85rem'}}>
            <input type="checkbox" checked={nonceReuse} onChange={e=>{setNonceReuse(e.target.checked);reset()}}
              style={{accentColor:'var(--accent-red)'}} />
            <span style={{color:nonceReuse?'var(--accent-red)':'var(--text-muted)'}}>⚠ Nonce Reuse (broken)</span>
          </label>
          <button className="btn btn-secondary" onClick={reset} style={{marginLeft:'auto'}}>Reset</button>
        </div>
      </div>

      {challenge && !challenge.error && (
        <div className="panel fade-in">
          <div className="panel-title">Challenge Ciphertext C*</div>
          <div className="terminal" style={{marginBottom:'0.5rem'}}>
            <div><strong>r:</strong> <span className="mono">{challenge.r_hex}</span></div>
            <div><strong>ct:</strong> <span className="mono" style={{wordBreak:'break-all'}}>{challenge.ciphertext_hex}</span></div>
            {challenge.hint && <div style={{color:'var(--accent-red)',marginTop:'0.3rem'}}>💡 {challenge.hint}</div>}
            {challenge.m0_ct_hex && <div><strong>Enc(m₀):</strong> <span className="mono">{challenge.m0_ct_hex}</span></div>}
          </div>
          <div style={{display:'flex',gap:'0.5rem'}}>
            <button className="btn btn-primary" onClick={()=>guess(0)}>Guess b=0 (m₀)</button>
            <button className="btn btn-success" onClick={()=>guess(1)}>Guess b=1 (m₁)</button>
          </div>
        </div>
      )}

      {rounds.length > 0 && (
        <div className="panel fade-in">
          <div className="panel-title">Game Results — {rounds.length} round(s)</div>
          <div style={{display:'flex',gap:'2rem',marginBottom:'0.5rem',fontSize:'0.9rem'}}>
            <div>Correct: <strong>{rounds.filter(r=>r.correct).length}</strong>/{rounds.length}</div>
            <div>Win rate: <strong>{(rounds.filter(r=>r.correct).length/rounds.length*100).toFixed(0)}%</strong></div>
            <div>Advantage: <strong style={{color: advantage > 0.2 ? 'var(--accent-red)' : 'var(--accent-green)'}}>
              {advantage.toFixed(3)}</strong>
              {advantage <= 0.1 ? ' ✓ negligible' : advantage >= 0.4 ? ' ⚠ BROKEN!' : ''}
            </div>
          </div>
          <div style={{maxHeight:'150px',overflowY:'auto',fontSize:'0.75rem'}}>
            {rounds.map((r,i)=>(
              <div key={i} style={{display:'flex',gap:'1rem',padding:'2px 0',borderBottom:'1px solid var(--surface-2)'}}>
                <span>Round {i+1}</span>
                <span>Actual b={r.actual_b}</span>
                <span>Guess={r.your_guess}</span>
                <span style={{color:r.correct?'var(--accent-green)':'var(--accent-red)'}}>{r.correct?'✓':'✗'}</span>
              </div>
            ))}
          </div>
          <div style={{marginTop:'0.5rem',height:'6px',background:'var(--surface-2)',borderRadius:'3px',overflow:'hidden'}}>
            <div style={{height:'100%',width:`${(advantage)*200}%`,maxWidth:'100%',
              background: advantage > 0.2 ? 'var(--accent-red)' : 'var(--accent-green)',transition:'width 0.3s'}} />
          </div>
          <div style={{fontSize:'0.7rem',color:'var(--text-muted)',marginTop:'0.2rem'}}>
            Advantage bar (0 = secure, 0.5 = completely broken)
          </div>
        </div>
      )}
    </div>
  )
}
