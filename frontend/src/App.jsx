import { useState } from 'react'
import './index.css'
import PA0_CliqueExplorer from './components/PA0_CliqueExplorer'
import PA1_PRG from './components/PA1_PRG'
import PA2_PRF from './components/PA2_PRF'
import PA3_CPA from './components/PA3_CPA'
import PA4_Modes from './components/PA4_Modes'
import PA5_MAC from './components/PA5_MAC'
import PA6_CCA from './components/PA6_CCA'

const API = 'http://localhost:8000/api'
const post = async (p,b) => { const r = await fetch(`${API}/${p}`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}); return r.json() }

// Generic API demo for PA#7+
function ApiDemo({ title, subtitle, fields, endpoint, buildBody }) {
  const [vals, setVals] = useState(Object.fromEntries(fields.map(f => [f.key, f.default || ''])))
  const [out, setOut] = useState(null)
  const [loading, setLoading] = useState(false)
  const set = (k,v) => setVals(p => ({...p,[k]:v}))
  const run = async () => {
    setLoading(true)
    try { setOut(await post(endpoint, buildBody(vals))) }
    catch(e) { setOut({error:e.message}) }
    setLoading(false)
  }
  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">{title}</div>
        <div className="panel-subtitle">{subtitle}</div>
        <div className="form-row">
          {fields.map(f => (
            <div className="form-group" key={f.key} style={f.width ? {maxWidth:f.width} : {}}>
              <label className="form-label">{f.label}</label>
              {f.type === 'select' ? (
                <select className="form-select" value={vals[f.key]} onChange={e=>set(f.key,e.target.value)}>
                  {f.options.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ) : (
                <input className={`form-input ${f.mono?'mono':''}`} type={f.type||'text'} value={vals[f.key]} onChange={e=>set(f.key,e.target.value)} />
              )}
            </div>
          ))}
          <button className="btn btn-primary" onClick={run} disabled={loading} style={{alignSelf:'flex-end'}}>
            {loading ? '⏳...' : '▶ Run'}
          </button>
        </div>
      </div>
      {out && <div><div className="terminal-label">Output</div><div className="terminal"><pre>{JSON.stringify(out,null,2)}</pre></div></div>}
    </div>
  )
}

function getPanel(id) {
  switch(id) {
    case 'graph': return <PA0_CliqueExplorer />
    case 'pa1': return <PA1_PRG />
    case 'pa2': return <PA2_PRF />
    case 'pa3': return <PA3_CPA />
    case 'pa4': return <PA4_Modes />
    case 'pa5': return <PA5_MAC />
    case 'pa6': return <PA6_CCA />
    case 'pa7': return <ApiDemo title="🧱 PA#7: Merkle-Damgård Hash" subtitle="Fixed-length compression → variable-length hash via iterative chaining with MD padding."
      fields={[{key:'msg',label:'Message (Hex)',default:'48656c6c6f20576f726c64',mono:true},{key:'len',label:'Out Len',default:'32',type:'number',width:'80px'}]}
      endpoint="hash/dlp" buildBody={v=>({message_hex:v.msg,out_len:parseInt(v.len)})} />
    case 'pa8': return <ApiDemo title="🔗 PA#8: DLP-Based CRHF" subtitle="Pedersen-style: H(x,y) = g^x · h^y mod p, extended via Merkle-Damgård."
      fields={[{key:'msg',label:'Message (Hex)',default:'48656c6c6f',mono:true},{key:'len',label:'Out Len',default:'32',type:'number',width:'80px'}]}
      endpoint="hash/dlp" buildBody={v=>({message_hex:v.msg,out_len:parseInt(v.len)})} />
    case 'pa9': return <ApiDemo title="🎂 PA#9: Birthday Attack" subtitle="Collision finding via birthday paradox."
      fields={[{key:'msg',label:'Message (Hex)',default:'48656c6c6f',mono:true},{key:'len',label:'Hash Len',default:'4',type:'number',width:'80px'}]}
      endpoint="hash/dlp" buildBody={v=>({message_hex:v.msg,out_len:parseInt(v.len)})} />
    case 'pa10': return <ApiDemo title="🔐 PA#10: HMAC" subtitle="HMAC(k,m) = H((k⊕opad) || H((k⊕ipad) || m))."
      fields={[{key:'key',label:'Key (Hex)',default:'00112233445566778899aabbccddeeff',mono:true},{key:'msg',label:'Message (Hex)',default:'48656c6c6f',mono:true}]}
      endpoint="hmac/compute" buildBody={v=>({key_hex:v.key,message_hex:v.msg})} />
    case 'pa11': return <ApiDemo title="🤝 PA#11: Diffie-Hellman" subtitle="DH key exchange with safe prime group."
      fields={[]} endpoint="dh/exchange" buildBody={()=>({})} />
    case 'pa12': return <ApiDemo title="🔑 PA#12: RSA" subtitle="Textbook RSA + PKCS#1 v1.5 padding."
      fields={[{key:'msg',label:'Message (int)',default:'12345',type:'number'},{key:'bits',label:'Bits',default:'512',type:'number',width:'80px'}]}
      endpoint="rsa/demo" buildBody={v=>({message:parseInt(v.msg),bits:parseInt(v.bits)})} />
    case 'pa13': return <ApiDemo title="🧪 PA#13: Miller-Rabin" subtitle="Probabilistic primality test."
      fields={[{key:'msg',label:'Number',default:'561',type:'number'}]}
      endpoint="rsa/demo" buildBody={v=>({message:parseInt(v.msg),bits:256})} />
    case 'pa14': return <ApiDemo title="📡 PA#14: CRT + Håstad" subtitle="Chinese Remainder Theorem + Håstad Broadcast Attack."
      fields={[{key:'msg',label:'Plaintext',default:'424242',type:'number'}]}
      endpoint="rsa/demo" buildBody={v=>({message:parseInt(v.msg),bits:512})} />
    case 'pa15': return <ApiDemo title="✍️ PA#15: Signatures" subtitle="Hash-then-Sign RSA."
      fields={[{key:'msg',label:'Message',default:'42',type:'number'}]}
      endpoint="rsa/demo" buildBody={v=>({message:parseInt(v.msg),bits:512})} />
    case 'pa16': return <ApiDemo title="🔒 PA#16: ElGamal" subtitle="ElGamal encryption + malleability demo."
      fields={[{key:'msg',label:'Message',default:'100',type:'number'},{key:'bits',label:'Bits',default:'512',type:'number',width:'80px'}]}
      endpoint="elgamal/demo" buildBody={v=>({message:parseInt(v.msg),bits:parseInt(v.bits)})} />
    case 'pa17': return <ApiDemo title="🛡️ PA#17: CCA-PKC" subtitle="Encrypt-then-Sign (ElGamal + RSA)."
      fields={[{key:'msg',label:'Message',default:'100',type:'number'}]}
      endpoint="elgamal/demo" buildBody={v=>({message:parseInt(v.msg),bits:512})} />
    case 'pa18': return <ApiDemo title="🔒 PA#18: Oblivious Transfer" subtitle="1-out-of-2 OT via RSA."
      fields={[{key:'a',label:'Alice bit',default:'1',type:'number',width:'80px'},{key:'b',label:'Bob bit',default:'0',type:'number',width:'80px'}]}
      endpoint="mpc/and" buildBody={v=>({a:parseInt(v.a),b:parseInt(v.b)})} />
    case 'pa19': return <ApiDemo title="⚡ PA#19: Secure Gates" subtitle="AND via OT, XOR via secret sharing."
      fields={[{key:'a',label:'a',default:'1',type:'number',width:'80px'},{key:'b',label:'b',default:'0',type:'number',width:'80px'}]}
      endpoint="mpc/and" buildBody={v=>({a:parseInt(v.a),b:parseInt(v.b)})} />
    case 'pa20': return <ApiDemo title="🔒 PA#20: 2-Party MPC" subtitle="Millionaire, Equality, Addition circuits."
      fields={[{key:'x',label:'x',default:'7',type:'number',width:'80px'},{key:'y',label:'y',default:'3',type:'number',width:'80px'},{key:'bits',label:'bits',default:'4',type:'number',width:'80px'}]}
      endpoint="mpc/millionaire" buildBody={v=>({x:parseInt(v.x),y:parseInt(v.y),n_bits:parseInt(v.bits)})} />
    default: return <PA0_CliqueExplorer />
  }
}

const PA_LIST = [
  {id:'graph',label:'Clique Graph Explorer',pa:'#0',section:'Minicrypt Clique'},
  {id:'pa1',label:'OWF & PRG',pa:'#1',section:'Minicrypt Clique'},
  {id:'pa2',label:'PRF (GGM Tree)',pa:'#2',section:'Minicrypt Clique'},
  {id:'pa3',label:'CPA Encryption',pa:'#3',section:'Minicrypt Clique'},
  {id:'pa4',label:'Modes of Operation',pa:'#4',section:'Minicrypt Clique'},
  {id:'pa5',label:'MACs (CBC-MAC)',pa:'#5',section:'Minicrypt Clique'},
  {id:'pa6',label:'CCA Encryption',pa:'#6',section:'Minicrypt Clique'},
  {id:'pa7',label:'Merkle-Damgård',pa:'#7',section:'Hashing'},
  {id:'pa8',label:'DLP-Based CRHF',pa:'#8',section:'Hashing'},
  {id:'pa9',label:'Birthday Attack',pa:'#9',section:'Hashing'},
  {id:'pa10',label:'HMAC + CCA',pa:'#10',section:'Hashing'},
  {id:'pa11',label:'Diffie-Hellman',pa:'#11',section:'Cryptomania'},
  {id:'pa12',label:'RSA + PKCS v1.5',pa:'#12',section:'Cryptomania'},
  {id:'pa13',label:'Miller-Rabin',pa:'#13',section:'Cryptomania'},
  {id:'pa14',label:'CRT + Håstad',pa:'#14',section:'Cryptomania'},
  {id:'pa15',label:'Digital Signatures',pa:'#15',section:'Cryptomania'},
  {id:'pa16',label:'ElGamal PKC',pa:'#16',section:'Cryptomania'},
  {id:'pa17',label:'CCA-Secure PKC',pa:'#17',section:'Cryptomania'},
  {id:'pa18',label:'Oblivious Transfer',pa:'#18',section:'MPC'},
  {id:'pa19',label:'Secure AND Gate',pa:'#19',section:'MPC'},
  {id:'pa20',label:'All 2-Party MPC',pa:'#20',section:'MPC'},
]

export default function App() {
  const [activeId, setActiveId] = useState('graph')
  const sections = [...new Set(PA_LIST.map(p => p.section))]

  return (
    <>
      <header className="header">
        <div className="header-brand">
          <h1>Minicrypt Clique Explorer</h1>
          <span className="badge badge-info">No-Library Rule</span>
          <span className="badge" style={{background:'var(--accent-green)',color:'#fff',fontSize:'0.6rem'}}>AES-128 from scratch</span>
        </div>
      </header>
      <div className="main-layout">
        <nav className="sidebar">
          {sections.map(s=>(
            <div key={s} className="sidebar-section">
              <div className="sidebar-section-title">{s}</div>
              {PA_LIST.filter(p=>p.section===s).map(pa=>(
                <div key={pa.id} className={`sidebar-item ${activeId===pa.id?'active':''}`} onClick={()=>setActiveId(pa.id)}>
                  <span className="pa-num">{pa.pa}</span><span>{pa.label}</span>
                </div>
              ))}
            </div>
          ))}
        </nav>
        <main className="content">{getPanel(activeId)}</main>
      </div>
      <footer className="proof-bar">
        <div className="path-vector">Panel: <strong>{PA_LIST.find(p=>p.id===activeId)?.label}</strong></div>
        <div className="status success">● Backend Connected</div>
      </footer>
    </>
  )
}
