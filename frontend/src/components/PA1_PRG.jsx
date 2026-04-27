import { useState, useEffect, useCallback } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA1_PRG() {
  const [seed,setSeed]=useState('deadbeef')
  const [nBits,setNBits]=useState(64)
  const [output,setOutput]=useState(null)
  const [nist,setNist]=useState(null)
  const [loading,setLoading]=useState(false)

  const generate = useCallback(async () => {
    setLoading(true)
    try { setOutput(await post('prg/next_bits',{seed_hex:seed,n_bits:nBits})) }
    catch(e) { setOutput({error:e.message}) }
    setLoading(false)
  },[seed,nBits])

  // Live update with debounce
  useEffect(()=>{
    const t = setTimeout(generate, 300)
    return ()=>clearTimeout(t)
  },[seed,nBits])

  const runNIST = async () => {
    try { setNist(await post('prg/nist_test',{seed_hex:seed,n_bits:Math.max(nBits,128)})) }
    catch(e) { setNist({error:e.message}) }
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🔑 PA#1: OWF & PRG — Live Output</div>
        <div className="panel-subtitle">HILL PRG: iterates DLP OWF with Goldreich-Levin hard-core bit. Toy params: ~30-bit DLP group for instant demos.</div>
        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Seed (Hex)</label>
            <input className="form-input mono" value={seed} onChange={e=>setSeed(e.target.value)} />
          </div>
          <div className="form-group" style={{minWidth:'200px'}}>
            <label className="form-label">Output Length: {nBits} bits</label>
            <input type="range" min={8} max={256} value={nBits} onChange={e=>setNBits(Number(e.target.value))}
              style={{width:'100%',accentColor:'var(--accent-blue)'}} />
          </div>
          <button className="btn btn-success" onClick={runNIST} style={{alignSelf:'flex-end'}}>🧪 Randomness Test</button>
        </div>
      </div>

      {output && !output.error && (
        <div>
          <div className="terminal-label">G(s) — {output.output_bits} bits</div>
          <div className="terminal">
            <div style={{marginBottom:'0.3rem'}}><strong>Hex:</strong> <span style={{color:'var(--accent-green)',wordBreak:'break-all'}}>{output.output_hex}</span></div>
            <div style={{marginBottom:'0.3rem'}}><strong>Bits:</strong> <span style={{fontSize:'0.75rem',wordBreak:'break-all',letterSpacing:'1px'}}>{output.bit_string}</span></div>
            <div style={{display:'flex',gap:'1rem',fontSize:'0.8rem'}}>
              <span>1s: {output.ones}</span><span>0s: {output.zeros}</span>
              <span>Ratio: {(output.ratio*100).toFixed(1)}%</span>
            </div>
            {/* Bit ratio bar */}
            <div style={{height:'8px',background:'var(--surface-2)',borderRadius:'4px',marginTop:'0.4rem',overflow:'hidden'}}>
              <div style={{height:'100%',width:`${output.ratio*100}%`,background: output.ratio > 0.45 && output.ratio < 0.55 ? 'var(--accent-green)' : 'var(--accent-red)',transition:'width 0.3s',borderRadius:'4px'}} />
            </div>
            <div style={{fontSize:'0.7rem',color:'var(--text-muted)',marginTop:'0.2rem'}}>
              {output.ratio > 0.45 && output.ratio < 0.55 ? '✓ Near 50% — looks pseudorandom' : '⚠ Skewed ratio'}
            </div>
          </div>
        </div>
      )}

      {nist && !nist.error && (
        <div style={{marginTop:'0.75rem'}}>
          <div className="terminal-label">NIST SP 800-22 Test Results ({nist.n_bits} bits)</div>
          <div className="terminal">
            <div style={{display:'flex',gap:'2rem',flexWrap:'wrap'}}>
              <div>
                <span className={`badge ${nist.frequency_test.pass ? 'badge-info' : ''}`} style={!nist.frequency_test.pass?{background:'var(--accent-red)'}:{}}>
                  {nist.frequency_test.pass ? '✓ PASS' : '✗ FAIL'}
                </span>
                <span style={{marginLeft:'0.5rem'}}>Frequency (p={nist.frequency_test.p_value})</span>
              </div>
              <div>
                <span className={`badge ${nist.runs_test.pass ? 'badge-info' : ''}`} style={!nist.runs_test.pass?{background:'var(--accent-red)'}:{}}>
                  {nist.runs_test.pass ? '✓ PASS' : '✗ FAIL'}
                </span>
                <span style={{marginLeft:'0.5rem'}}>Runs (p={nist.runs_test.p_value})</span>
              </div>
            </div>
            <div style={{marginTop:'0.5rem',fontSize:'0.8rem'}}>
              Ones: {nist.ones} | Zeros: {nist.zeros} | Ratio: {(nist.ratio*100).toFixed(1)}%
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
