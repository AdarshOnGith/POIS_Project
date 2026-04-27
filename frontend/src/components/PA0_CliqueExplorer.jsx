import { useState, useEffect } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => { const r = await fetch(`${API}/${p}`, {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA0_CliqueExplorer() {
  const [nodes,setNodes]=useState([])
  const [foundation,setFoundation]=useState('AES')
  const [srcPrim,setSrcPrim]=useState('PRG')
  const [tgtPrim,setTgtPrim]=useState('PRF')
  const [keyHex,setKeyHex]=useState('00112233445566778899aabbccddeeff')
  const [queryHex,setQueryHex]=useState('48656c6c6f')
  const [buildResult,setBuildResult]=useState(null)
  const [reduceResult,setReduceResult]=useState(null)
  const [proofOpen,setProofOpen]=useState(false)
  const [bidir,setBidir]=useState(false)
  const [error,setError]=useState(null)

  useEffect(()=>{
    fetch(`${API}/graph/schema`).then(r=>r.json()).then(d=>setNodes(d.nodes||[]))
      .catch(()=>setError('Backend not running'))
  },[])

  const runBuild = async () => {
    try { setError(null); setBuildResult(await post('clique/build',{foundation,source_primitive:srcPrim,key_hex:keyHex})) }
    catch(e){setError(e.message)}
  }
  const runReduce = async () => {
    try {
      setError(null)
      const s = bidir ? tgtPrim : srcPrim, t = bidir ? srcPrim : tgtPrim
      setReduceResult(await post('clique/reduce',{foundation,source_primitive:s,target_primitive:t,key_hex:keyHex,query_hex:queryHex}))
    } catch(e){setError(e.message)}
  }
  const runBoth = () => { runBuild(); runReduce() }

  return (
    <div className="fade-in">
      {/* Foundation Toggle */}
      <div className="panel" style={{marginBottom:'0.75rem'}}>
        <div style={{display:'flex',alignItems:'center',gap:'1rem',flexWrap:'wrap'}}>
          <span className="form-label" style={{margin:0}}>Foundation:</span>
          <div className="foundation-toggle">
            <button className={`foundation-btn ${foundation==='AES'?'active':''}`} onClick={()=>setFoundation('AES')}>AES-128 (PRP)</button>
            <button className={`foundation-btn ${foundation==='DLP'?'active':''}`} onClick={()=>setFoundation('DLP')}>DLP (g^x mod p)</button>
          </div>
          <label style={{display:'flex',alignItems:'center',gap:'0.4rem',fontSize:'0.8rem',color:'var(--text-muted)',cursor:'pointer'}}>
            <input type="checkbox" checked={bidir} onChange={e=>setBidir(e.target.checked)} />
            Bidirectional (B→A)
          </label>
        </div>
      </div>

      {/* Two columns */}
      <div className="two-col">
        {/* Column 1: Build */}
        <div className="panel">
          <div className="panel-title">Column 1: Build — {foundation} → {srcPrim}</div>
          <div className="panel-subtitle">Leg 1: Instantiate source primitive from foundation</div>
          <div className="form-group"><label className="form-label">Source Primitive A</label>
            <select className="form-select" value={srcPrim} onChange={e=>setSrcPrim(e.target.value)}>
              {nodes.map(n=><option key={n}>{n}</option>)}
            </select>
          </div>
          <div className="form-group"><label className="form-label">Key / Seed (hex)</label>
            <input className="form-input mono" value={keyHex} onChange={e=>setKeyHex(e.target.value)} />
          </div>
          <button className="btn btn-primary" onClick={runBoth} style={{marginTop:'0.5rem'}}>▶ Build & Reduce</button>
          {buildResult && (
            <div style={{marginTop:'0.75rem'}}>
              {buildResult.steps?.map((s,i)=>(
                <div key={i} className="edge-card" style={{animationDelay:`${i*0.1}s`}}>
                  <div className="edge-label">Step {i+1}</div>
                  <div className="edge-from-to">{s.step || s.fn}</div>
                  {s.fn && <div className="edge-proof" style={{fontFamily:'monospace'}}>{s.fn}</div>}
                </div>
              ))}
              {buildResult.intermediates?.map((v,i)=>(
                <div key={`int-${i}`} style={{background:'var(--surface-2)',padding:'0.5rem',borderRadius:'6px',marginTop:'0.4rem',fontSize:'0.8rem',fontFamily:'monospace'}}>
                  <div style={{color:'var(--accent-blue)'}}>{v.step}</div>
                  {v.input && <div>Input: {v.input}</div>}
                  <div style={{color:'var(--accent-green)',wordBreak:'break-all'}}>Output: {v.output}</div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Column 2: Reduce */}
        <div className="panel">
          <div className="panel-title">Column 2: Reduce — {bidir?tgtPrim:srcPrim} → {bidir?srcPrim:tgtPrim}</div>
          <div className="panel-subtitle">Leg 2: Apply abstract reduction (A used as black box)</div>
          <div className="form-group"><label className="form-label">Target Primitive B</label>
            <select className="form-select" value={tgtPrim} onChange={e=>setTgtPrim(e.target.value)}>
              {nodes.map(n=><option key={n}>{n}</option>)}
            </select>
          </div>
          <div className="form-group"><label className="form-label">Query / Message (hex)</label>
            <input className="form-input mono" value={queryHex} onChange={e=>setQueryHex(e.target.value)} />
          </div>
          {reduceResult?.possible && (
            <div style={{marginTop:'0.75rem'}}>
              <div className="reduction-path">
                {reduceResult.path?.map((n,i)=>(
                  <span key={i} style={{display:'inline-flex',alignItems:'center',gap:'0.3rem'}}>
                    <span className="path-node">{n}</span>
                    {i<reduceResult.path.length-1&&<span className="path-arrow">→</span>}
                  </span>
                ))}
              </div>
              {reduceResult.edges?.map((e,i)=>(
                <div key={i} className="edge-card"><div className="edge-label">Step {i+1} (PA#{e.pa})</div>
                  <div className="edge-from-to">{e.from} → {e.to}</div><div className="edge-proof">{e.proof}</div></div>
              ))}
              {reduceResult.intermediates?.map((v,i)=>(
                <div key={`ri-${i}`} style={{background:'var(--surface-2)',padding:'0.5rem',borderRadius:'6px',marginTop:'0.4rem',fontSize:'0.8rem',fontFamily:'monospace'}}>
                  <div style={{color:'var(--accent-blue)'}}>{v.step}</div>
                  <div style={{color:'var(--accent-green)',wordBreak:'break-all'}}>Output: {v.output}</div>
                </div>
              ))}
            </div>
          )}
          {reduceResult && !reduceResult.possible && <div className="stub" style={{color:'var(--accent-red)'}}>No reduction path: {reduceResult.error}</div>}
        </div>
      </div>

      {error && <div className="panel" style={{borderColor:'var(--accent-red)'}}><span style={{color:'var(--accent-red)'}}>⚠ {error}</span></div>}

      {/* Proof Panel */}
      <div className="panel" style={{marginTop:'0.75rem',cursor:'pointer'}} onClick={()=>setProofOpen(!proofOpen)}>
        <div className="panel-title">{proofOpen?'▼':'▶'} Reduction Proof Summary</div>
        {proofOpen && reduceResult?.edges && (
          <div style={{marginTop:'0.5rem',fontSize:'0.85rem',lineHeight:'1.6'}}>
            <div><strong>Chain:</strong> {foundation} → {reduceResult.path?.join(' → ')}</div>
            {reduceResult.edges.map((e,i)=>(
              <div key={i} style={{marginTop:'0.3rem',padding:'0.3rem 0.5rem',background:'var(--surface-2)',borderRadius:'4px'}}>
                <strong>Step {i+1} (PA#{e.pa}):</strong> {e.proof}
              </div>
            ))}
            <div style={{marginTop:'0.5rem',color:'var(--text-muted)'}}>
              Security: If adversary breaks {reduceResult.path?.[reduceResult.path.length-1]} with advantage ε, 
              it breaks {reduceResult.path?.[0]} with advantage ε' ≥ ε/q.
            </div>
          </div>
        )}
        {proofOpen && !reduceResult && <div className="stub">Select primitives and click "Build & Reduce" to see the proof chain.</div>}
      </div>
    </div>
  )
}
