import { useState, useEffect, useCallback } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

export default function PA2_PRF() {
  const [keyInt,setKeyInt]=useState(12345)
  const [query,setQuery]=useState('1011')
  const [depth,setDepth]=useState(4)
  const [tree,setTree]=useState(null)

  const loadTree = useCallback(async () => {
    try { setTree(await post('prf/tree',{key_int:keyInt,query_bits:query,depth})) }
    catch(e) { console.error(e) }
  },[keyInt,query,depth])

  useEffect(()=>{ const t=setTimeout(loadTree,300); return ()=>clearTimeout(t) },[keyInt,query,depth])

  const pathSet = new Set(tree?.path?.map(p=>p.level+'_'+p.path)||[])

  const renderTree = () => {
    if (!tree?.nodes) return null
    const levels = Object.keys(tree.nodes).map(Number).sort((a,b)=>a-b)
    return (
      <div style={{overflowX:'auto',padding:'1rem 0'}}>
        {levels.map(lvl => {
          const nodesAtLevel = Object.entries(tree.nodes[lvl]).sort(([a],[b])=>a.localeCompare(b))
          return (
            <div key={lvl} style={{display:'flex',justifyContent:'center',gap:'4px',marginBottom:'6px'}}>
              {nodesAtLevel.map(([path,val])=>{
                const isActive = pathSet.has(lvl+'_'+path)
                return (
                  <div key={path} style={{
                    padding:'3px 6px', borderRadius:'4px', fontSize:'0.65rem', fontFamily:'monospace',
                    textAlign:'center', minWidth:'40px', transition:'all 0.2s',
                    background: isActive ? 'var(--accent-blue)' : 'var(--surface-2)',
                    color: isActive ? '#fff' : 'var(--text-muted)',
                    border: isActive ? '1px solid var(--accent-blue)' : '1px solid transparent',
                    opacity: isActive ? 1 : 0.5
                  }}>
                    <div style={{fontSize:'0.55rem',opacity:0.7}}>{path||'root'}</div>
                    <div>{val.toString(16).slice(0,4)}</div>
                  </div>
                )
              })}
            </div>
          )
        })}
      </div>
    )
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🌳 PA#2: GGM Tree Visualiser</div>
        <div className="panel-subtitle">GGM PRF: Fk(b₁...bₙ) = Gbₙ(...Gb₁(k)). Highlighted path shows the query traversal. Change any bit to see uncorrelated output.</div>
        <div className="form-row">
          <div className="form-group" style={{maxWidth:'120px'}}>
            <label className="form-label">Key (int)</label>
            <input className="form-input mono" type="number" value={keyInt} onChange={e=>setKeyInt(Number(e.target.value))} />
          </div>
          <div className="form-group" style={{maxWidth:'120px'}}>
            <label className="form-label">Query (bits)</label>
            <input className="form-input mono" value={query} onChange={e=>setQuery(e.target.value.replace(/[^01]/g,''))} maxLength={8} />
          </div>
          <div className="form-group" style={{maxWidth:'100px'}}>
            <label className="form-label">Depth: {depth}</label>
            <input type="range" min={2} max={6} value={depth} onChange={e=>setDepth(Number(e.target.value))}
              style={{width:'100%',accentColor:'var(--accent-blue)'}} />
          </div>
        </div>
        {/* Bit toggle buttons */}
        <div style={{display:'flex',gap:'4px',marginTop:'0.5rem',alignItems:'center'}}>
          <span style={{fontSize:'0.75rem',color:'var(--text-muted)'}}>Toggle bits:</span>
          {query.split('').map((b,i)=>(
            <button key={i} className="btn btn-secondary" style={{padding:'2px 10px',fontSize:'0.85rem',fontFamily:'monospace',
              background: b==='1' ? 'var(--accent-blue)' : 'var(--surface-2)'}}
              onClick={()=>{const q=query.split('');q[i]=q[i]==='0'?'1':'0';setQuery(q.join(''))}}>
              {b}
            </button>
          ))}
        </div>
      </div>

      {tree && (
        <div>
          <div className="terminal-label">GGM Tree (depth={tree.depth}, query={tree.query})</div>
          <div className="terminal" style={{textAlign:'center'}}>
            {renderTree()}
            <div style={{marginTop:'0.5rem',padding:'0.5rem',background:'var(--accent-blue)',borderRadius:'6px',display:'inline-block'}}>
              <strong>F<sub>k</sub>({tree.query}) = </strong>
              <span style={{fontFamily:'monospace',fontSize:'1.1rem'}}>{tree.output?.toString(16)}</span>
              <span style={{fontSize:'0.8rem',marginLeft:'0.5rem'}}>({tree.output})</span>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
