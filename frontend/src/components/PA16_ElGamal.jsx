import { useState } from 'react'

const API = 'http://localhost:8000/api'
const post = async (p, b) => {
  const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
  return r.json()
}

const PRESETS = [
  { label: 'm=100, k=2', msg: 100, factor: 2 },
  { label: 'm=7, k=3', msg: 7, factor: 3 },
  { label: 'm=50, k=4', msg: 50, factor: 4 },
]

function parseMsgInt(raw) {
  const n = Number.parseInt(String(raw), 10)
  return Number.isFinite(n) && n >= 1 ? n : null
}

// Lowercase helpers = plain render functions, not React components → no PropTypes needed

function ciphertextPanel(encState, showDecrypt) {
  return (
    <div className="panel" style={{ marginTop: '0.5rem', borderColor: 'var(--accent-blue)' }}>
      <div className="panel-title" style={{ color: 'var(--accent-blue)', fontSize: '0.85rem' }}>
        Ciphertext C = (c₁, c₂)
      </div>
      <div className="terminal" style={{ fontSize: '0.75rem' }}>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>p = {encState.p}</div>
        <div style={{ marginTop: '0.2rem' }}>
          public h = g^x: <span className="mono">{encState.public_h}</span>
        </div>
        <div style={{ color: 'var(--accent-orange)', fontSize: '0.7rem', marginTop: '0.1rem' }}>
          private x = {encState.private_x} (shown for demo only)
        </div>
        <div style={{ marginTop: '0.5rem' }}>
          <div>c₁ = g^r mod p = <span className="mono">{encState.c1}</span></div>
          <div style={{ marginTop: '0.2rem' }}>c₂ = m·h^r mod p = <span className="mono">{encState.c2}</span></div>
        </div>
        {showDecrypt && (
          <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.4rem',
            color: 'var(--accent-green)', fontWeight: 'bold' }}>
            Dec(c₁, c₂) = c₂ / c₁^x mod p = <span style={{ fontSize: '1.1rem' }}>{encState.decrypted}</span>
            {encState.correct ? ' ✓' : ' ✗'}
          </div>
        )}
      </div>
    </div>
  )
}

function malleabilityTrace(malState, malStep, factor) {
  return (
    <div className="terminal" style={{ fontSize: '0.75rem' }}>
      <div>Original c₂ = <span className="mono">{malState.c2}</span></div>
      <div style={{ marginTop: '0.3rem', color: 'var(--accent-orange)' }}>
        {factor}·c₂ mod p = <span className="mono">{malState.c2_modified}</span>
      </div>
      {malStep >= 2 && (
        <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.4rem' }}>
          <div>Dec(c₁, c₂) = <strong>{malState.decrypted_original}</strong></div>
          <div style={{ marginTop: '0.3rem' }}>
            Dec(c₁, {factor}·c₂) = <strong style={{ color: 'var(--accent-red)', fontSize: '1.1rem' }}>
              {malState.decrypted_modified}
            </strong>
            <span style={{ color: 'var(--text-muted)', marginLeft: '0.5rem', fontSize: '0.8rem' }}>
              (= {factor}×{malState.message} = {malState.expected_modified})
            </span>
          </div>
          {malState.malleable && (
            <div style={{ marginTop: '0.4rem', color: 'var(--accent-red)', fontWeight: 'bold', fontSize: '0.85rem' }}>
              {malState.explanation}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function cpaGameTrace(cpaState) {
  return (
    <div className="terminal" style={{ fontSize: '0.75rem', marginTop: '0.75rem' }}>
      <div style={{ fontWeight: 'bold', marginBottom: '0.4rem', color: 'var(--accent-blue)' }}>
        Challenger ({cpaState.p_bits}-bit group):
      </div>
      <div>Hidden m = <strong style={{ color: 'var(--accent-blue)' }}>{cpaState.challenge_m}</strong></div>
      <div style={{ marginTop: '0.2rem' }}>
        Encrypts → (c₁, c₂) = <span className="mono">{cpaState.c1}</span>, <span className="mono">{cpaState.c2}</span>
      </div>
      <div style={{ fontWeight: 'bold', marginTop: '0.6rem', color: 'var(--accent-orange)' }}>Adversary:</div>
      <div style={{ marginTop: '0.2rem' }}>
        Submits (c₁, 2·c₂) to oracle: <span className="mono">{cpaState.c2_modified}</span>
      </div>
      <div style={{ marginTop: '0.2rem' }}>
        Oracle returns: <strong style={{ color: 'var(--accent-orange)' }}>{cpaState.oracle_response}</strong>
        <span style={{ color: 'var(--text-muted)', marginLeft: '0.4rem', fontSize: '0.7rem' }}>
          (= 2×{cpaState.challenge_m} = {cpaState.expected_2m})
        </span>
      </div>
      <div style={{ marginTop: '0.2rem' }}>
        Divide by 2 mod p → m = <strong style={{ color: 'var(--accent-red)', fontSize: '1rem' }}>
          {cpaState.recovered_m}
        </strong>
      </div>
      <div style={{ marginTop: '0.5rem', padding: '0.35rem 0.6rem', borderRadius: '6px',
        background: cpaState.attack_success ? 'rgba(255,60,60,0.1)' : 'rgba(0,200,100,0.1)',
        color: cpaState.attack_success ? 'var(--accent-red)' : 'var(--accent-green)', fontWeight: 'bold' }}>
        {cpaState.attack_success
          ? `🚨 CCA2 attack succeeded — adversary learned m = ${cpaState.recovered_m}`
          : '✓ Attack did not succeed'}
      </div>
      <div style={{ marginTop: '0.3rem', color: 'var(--text-muted)', fontSize: '0.72rem' }}>
        Fix: PA#17 Encrypt-then-Sign — oracle rejects tampered ciphertext (signature verification fails).
      </div>
    </div>
  )
}

export default function PA16_ElGamal() {
  const [message, setMessage] = useState('100')
  const [factor, setFactor] = useState(2)
  const [encState, setEncState] = useState(null)
  const [showDecrypt, setShowDecrypt] = useState(false)
  const [malState, setMalState] = useState(null)
  const [malStep, setMalStep] = useState(0)
  const [successCount, setSuccessCount] = useState(0)
  const [totalCount, setTotalCount] = useState(0)
  const [cpaState, setCpaState] = useState(null)
  const [loading, setLoading] = useState(false)
  const [loadingCpa, setLoadingCpa] = useState(false)

  const encrypt = async (overrides = {}) => {
    const m = parseMsgInt(overrides.msg ?? message)
    if (m === null) return
    setLoading(true)
    setEncState(null); setShowDecrypt(false); setMalState(null); setMalStep(0)
    try { setEncState(await post('elgamal/encrypt', { message: m, bits: 256 })) }
    catch (e) { setEncState({ error: e.message }) }
    setLoading(false)
  }

  const multiplyC2 = async () => {
    const m = parseMsgInt(message)
    if (m === null) return
    setLoading(true); setMalState(null); setMalStep(0)
    try {
      setMalState(await post('elgamal/malleable', { message: m, bits: 256, factor }))
      setMalStep(1)
    } catch (e) { setMalState({ error: e.message }) }
    setLoading(false)
  }

  const decryptModified = () => {
    setMalStep(2)
    setTotalCount(t => t + 1)
    if (malState?.malleable) setSuccessCount(s => s + 1)
  }

  const runCpaGame = async () => {
    setLoadingCpa(true); setCpaState(null)
    try { setCpaState(await post('elgamal/cpa_game', { bits: 256 })) }
    catch (e) { setCpaState({ error: e.message }) }
    setLoadingCpa(false)
  }

  const loadPreset = (ex) => { setMessage(String(ex.msg)); setFactor(ex.factor); encrypt(ex) }

  const hasEncrypted = !!(encState && !encState.error)
  const malStateOk = !!(malState && !malState.error)   // shared by two derived flags
  const canDecryptModified = malStep === 1 && malStateOk
  const showMalTrace = malStep >= 1 && malStateOk
  const hasCpaResult = !!(cpaState && !cpaState.error)
  const rate = totalCount > 0 ? Math.round(successCount / totalCount * 100) : 0
  const decryptBtnActive = hasEncrypted && !showDecrypt
  const decryptBtnStyle = {
    background: decryptBtnActive ? 'var(--accent-green)' : 'var(--surface-2)',
    color: decryptBtnActive ? '#fff' : 'var(--text-muted)',
    opacity: decryptBtnActive ? 1 : 0.4,
  }
  const malBtnStyle = {
    background: canDecryptModified ? 'var(--accent-red)' : 'var(--surface-2)',
    color: canDecryptModified ? '#fff' : 'var(--text-muted)',
    opacity: canDecryptModified ? 1 : 0.4,
  }

  return (
    <div className="fade-in">

      {/* ── Controls ── */}
      <div className="panel">
        <div className="panel-title">🔒 PA#16: ElGamal Public-Key Cryptosystem</div>
        <div className="panel-subtitle">
          Enc: C = (g^r mod p, m·h^r mod p). Dec: m = c₂/c₁^x mod p.
          ElGamal is CPA-secure under DDH, but <em>malleable</em>: (c₁, k·c₂) decrypts to k·m.
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Try:</span>
          {PRESETS.map(ex => (
            <button key={ex.label} onClick={() => loadPreset(ex)} disabled={loading}
              style={{ padding: '0.25rem 0.6rem', fontSize: '0.74rem', borderRadius: '4px',
                border: '1px solid var(--border)', background: 'var(--surface-2)', color: 'var(--text)', cursor: 'pointer' }}>
              {ex.label}
            </button>
          ))}
        </div>

        <div className="form-row">
          <div className="form-group">
            <label className="form-label" htmlFor="elg-msg">Message m (integer, &lt; group order)</label>
            <input id="elg-msg" className="form-input mono" type="number" min={1} value={message}
              onChange={e => setMessage(e.target.value)} style={{ maxWidth: '130px' }} />
          </div>
          <div className="form-group">
            <label className="form-label" htmlFor="elg-factor">Factor k</label>
            <input id="elg-factor" className="form-input mono" type="number" min={2} max={100} value={factor}
              onChange={e => setFactor(Number.parseInt(e.target.value, 10) || 2)} style={{ maxWidth: '80px' }} />
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignSelf: 'flex-end', flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={() => encrypt()} disabled={loading}>
              {loading ? '⏳' : '🔒 Encrypt'}
            </button>
            <button className="btn" onClick={() => setShowDecrypt(true)}
              disabled={!decryptBtnActive} style={decryptBtnStyle}>
              🔓 Decrypt
            </button>
          </div>
        </div>
        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
          Toy parameters: 256-bit safe prime group. Confirm Dec(c₁, k·c₂) = k·m for any k.
        </div>
      </div>

      {hasEncrypted && ciphertextPanel(encState, showDecrypt)}

      {/* ── Malleability attack ── */}
      <div className="panel" style={{ marginTop: '0.5rem', borderColor: 'var(--accent-red)' }}>
        <div className="panel-title" style={{ color: 'var(--accent-red)', fontSize: '0.85rem' }}>
          Malleability Attack: Multiply c₂ by k
        </div>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
          (c₁, k·c₂) is a valid encryption of k·m — without knowing m or the private key x.
        </div>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
          <button className="btn" onClick={multiplyC2} disabled={loading}
            style={{ background: 'var(--accent-orange)', color: '#fff', borderColor: 'var(--accent-orange)' }}>
            {loading ? '⏳' : `×${factor} Multiply c₂ by ${factor}`}
          </button>
          <button className="btn" onClick={decryptModified}
            disabled={!canDecryptModified} style={malBtnStyle}>
            🔓 Decrypt Modified
          </button>
        </div>
        {showMalTrace && malleabilityTrace(malState, malStep, factor)}
        {totalCount > 0 && (
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
            marginTop: '0.5rem', padding: '0.3rem 0.6rem',
            background: 'rgba(255,60,60,0.08)', borderRadius: '6px', fontSize: '0.82rem' }}>
            <span style={{ color: 'var(--text-muted)' }}>Malleability success rate:</span>
            <strong style={{ color: 'var(--accent-red)' }}>{successCount}/{totalCount} = {rate}%</strong>
          </div>
        )}
      </div>

      {/* ── CPA game ── */}
      <div className="panel" style={{ marginTop: '0.5rem', borderColor: 'var(--accent-blue)' }}>
        <div className="panel-title" style={{ color: 'var(--accent-blue)', fontSize: '0.85rem' }}>
          CPA Game — Why ElGamal Fails CCA
        </div>
        <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
          Adversary submits modified (c₁, 2·c₂) to the decryption oracle, gets 2m back, divides by 2 → learns m.
        </div>
        <button className="btn btn-primary" onClick={runCpaGame} disabled={loadingCpa} style={{ fontSize: '0.82rem' }}>
          {loadingCpa ? '⏳ Running...' : '▶ Run CPA Attack Demo'}
        </button>
        {hasCpaResult && cpaGameTrace(cpaState)}
      </div>

    </div>
  )
}
