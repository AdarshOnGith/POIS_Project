import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => { const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return r.json() }

const PRESETS = [
  { label: '"Hello, World!"', msg: 'Hello, World!', mode: 'hash' },
  { label: '"vote_yes"', msg: 'vote_yes', mode: 'hash' },
  { label: '"do not alter"', msg: 'do not alter this message', mode: 'hash' },
]

const FORGERY_PRESETS = [
  { label: 'hello × world', m1: 'hello', m2: 'world' },
  { label: 'a × b', m1: 'a', m2: 'b' },
  { label: 'buy × sell', m1: 'buy', m2: 'sell' },
]

export default function PA15_Signatures() {
  const [message, setMessage] = useState('Hello, World!')
  const [mode, setMode] = useState('hash')
  const [tab, setTab] = useState('sign')

  // Three separate result states — all share the same generated key (via signState)
  const [signState, setSignState] = useState(null)    // from POST signatures/demo
  const [verifyState, setVerifyState] = useState(null) // from POST signatures/verify_detail (tamper=false)
  const [tamperState, setTamperState] = useState(null) // from POST signatures/verify_detail (tamper=true)

  const [m1, setM1] = useState('hello')
  const [m2, setM2] = useState('world')
  const [forgeryState, setForgeryState] = useState(null)

  const [loading, setLoading] = useState(false)
  const [loadingForgery, setLoadingForgery] = useState(false)

  // Step 1: Sign — generates key pair, returns sig_hex + N_str + e_int for later use
  const sign = async (overrides = {}) => {
    const msg = overrides.msg !== undefined ? overrides.msg : message
    const m = overrides.mode !== undefined ? overrides.mode : mode
    setLoading(true)
    setSignState(null); setVerifyState(null); setTamperState(null)
    try {
      const data = await post('signatures/demo', { message: msg, raw: m === 'raw', bits: 512 })
      setSignState({ ...data, usedMessage: msg })
    } catch (e) { setSignState({ error: e.message }) }
    setLoading(false)
  }

  // Step 2: Verify — uses SAME key (N_str, e_int) from signState, verifies original message
  const verify = async () => {
    if (!signState?.signature_hex) return
    setLoading(true); setVerifyState(null)
    try {
      const data = await post('signatures/verify_detail', {
        message: signState.usedMessage,
        sig_hex: signState.signature_hex,
        N_str: signState.N_str,
        e_int: signState.e_int,
        tamper: false
      })
      setVerifyState(data)
    } catch (e) { setVerifyState({ error: e.message }) }
    setLoading(false)
  }

  // Step 3: Tamper — uses SAME key from signState, flips first byte of message → verification fails
  const tamper = async () => {
    if (!signState?.signature_hex) return
    setLoading(true); setTamperState(null)
    try {
      const data = await post('signatures/verify_detail', {
        message: signState.usedMessage,
        sig_hex: signState.signature_hex,
        N_str: signState.N_str,
        e_int: signState.e_int,
        tamper: true
      })
      setTamperState(data)
    } catch (e) { setTamperState({ error: e.message }) }
    setLoading(false)
  }

  const forgery = async (overrides = {}) => {
    const fm1 = overrides.m1 !== undefined ? overrides.m1 : m1
    const fm2 = overrides.m2 !== undefined ? overrides.m2 : m2
    setLoadingForgery(true); setForgeryState(null)
    try {
      const data = await post('signatures/forgery', { m1: fm1, m2: fm2, bits: 512 })
      setForgeryState(data)
    } catch (e) { setForgeryState({ error: e.message }) }
    setLoadingForgery(false)
  }

  const hasSigned = !!(signState && !signState.error && signState.signature_hex)
  const btnStyle = (active) => ({
    background: active ? 'var(--accent-green)' : 'var(--surface-2)',
    color: active ? '#fff' : 'var(--text-muted)',
    borderColor: active ? 'var(--accent-green)' : 'var(--border)',
    opacity: active ? 1 : 0.45,
    cursor: active ? 'pointer' : 'not-allowed'
  })

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">✍️ PA#15: Digital Signatures</div>
        <div className="panel-subtitle">
          Hash-then-Sign RSA: σ = H(m)^d mod N. Verify: σ^e mod N =? H(m).
          Raw RSA (no hash) is broken by multiplicative forgery.
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
          {['sign', 'forgery'].map(t => (
            <button key={t} onClick={() => setTab(t)}
              style={{ padding: '0.3rem 0.8rem', fontSize: '0.8rem', borderRadius: '4px', border: 'none',
                background: tab === t ? 'var(--accent-blue)' : 'var(--surface-2)',
                color: tab === t ? '#fff' : 'var(--text)', cursor: 'pointer' }}>
              {t === 'sign' ? 'Sign / Verify / Tamper' : 'Multiplicative Forgery (Raw RSA)'}
            </button>
          ))}
        </div>

        {tab === 'sign' && (
          <>
            {/* Preset buttons */}
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Load:</span>
              {PRESETS.map(p => (
                <button key={p.label} onClick={() => { setMessage(p.msg); setMode(p.mode); setSignState(null); setVerifyState(null); setTamperState(null) }}
                  style={{ padding: '0.25rem 0.6rem', fontSize: '0.74rem', borderRadius: '4px',
                    border: '1px solid var(--border)', background: 'var(--surface-2)', color: 'var(--text)', cursor: 'pointer' }}>
                  {p.label}
                </button>
              ))}
            </div>

            <div className="form-row">
              <div className="form-group" style={{ flex: 3 }}>
                <label className="form-label">Message to sign</label>
                <input className="form-input" value={message}
                  onChange={e => { setMessage(e.target.value); setSignState(null); setVerifyState(null); setTamperState(null) }} />
              </div>
              <div className="form-group">
                <label className="form-label">Mode</label>
                <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem', fontSize: '0.82rem' }}>
                  <label><input type="radio" checked={mode === 'hash'} onChange={() => setMode('hash')} /> Hash-then-Sign</label>
                  <label><input type="radio" checked={mode === 'raw'} onChange={() => setMode('raw')} /> Raw RSA (no hash)</label>
                </div>
              </div>
            </div>

            {/* Three separate action buttons */}
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginTop: '0.75rem', alignItems: 'center' }}>
              <button className="btn btn-primary" onClick={() => sign()} disabled={loading}>
                {loading ? '⏳...' : '✍ Sign'}
              </button>
              <button className="btn" onClick={verify} disabled={loading || !hasSigned} style={btnStyle(hasSigned)}>
                🔍 Verify
              </button>
              <button className="btn" onClick={tamper} disabled={loading || !hasSigned}
                style={{ background: hasSigned ? 'var(--accent-orange)' : 'var(--surface-2)',
                  color: hasSigned ? '#fff' : 'var(--text-muted)',
                  borderColor: hasSigned ? 'var(--accent-orange)' : 'var(--border)',
                  opacity: hasSigned ? 1 : 0.45, cursor: hasSigned ? 'pointer' : 'not-allowed' }}>
                🔧 Tamper
              </button>
              {!hasSigned && <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>← Sign first to enable Verify and Tamper</span>}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              Toy parameters: 512-bit N, H(m) = PA#8 DLP hash. Verify and Tamper reuse the same key from Sign.
            </div>
          </>
        )}

        {tab === 'forgery' && (
          <>
            <div style={{ marginBottom: '0.6rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Raw RSA: σ(m) = m^d mod N. Because (m₁·m₂)^d = m₁^d · m₂^d, given σ₁ and σ₂
              an adversary computes σ(m₁·m₂) = σ₁·σ₂ without ever knowing d.
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              {FORGERY_PRESETS.map(p => (
                <button key={p.label} onClick={() => { setM1(p.m1); setM2(p.m2); forgery(p) }} disabled={loadingForgery}
                  style={{ padding: '0.25rem 0.6rem', fontSize: '0.74rem', borderRadius: '4px',
                    border: '1px solid var(--border)', background: 'var(--surface-2)', color: 'var(--text)', cursor: 'pointer' }}>
                  {p.label}
                </button>
              ))}
            </div>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">m₁ (have signature on this)</label>
                <input className="form-input" value={m1} onChange={e => setM1(e.target.value)} />
              </div>
              <div className="form-group">
                <label className="form-label">m₂ (have signature on this)</label>
                <input className="form-input" value={m2} onChange={e => setM2(e.target.value)} />
              </div>
              <button className="btn btn-primary" onClick={() => forgery()} disabled={loadingForgery} style={{ alignSelf: 'flex-end' }}>
                {loadingForgery ? '⏳...' : '🔨 Forge σ(m₁×m₂)'}
              </button>
            </div>
          </>
        )}
      </div>

      {/* ── Sign result ── */}
      {tab === 'sign' && signState && !signState.error && (
        <div className="panel" style={{ marginTop: '0.5rem', borderColor: 'var(--accent-blue)' }}>
          <div className="panel-title" style={{ color: 'var(--accent-blue)', fontSize: '0.85rem' }}>
            ✍ Signature Generated ({signState.N_bits}-bit N)
          </div>
          <div className="terminal" style={{ fontSize: '0.75rem' }}>
            <div>m = "<span className="mono">{signState.usedMessage}</span>"</div>
            {!signState.raw && (
              <div style={{ marginTop: '0.3rem' }}>
                H(m) = <span className="mono" style={{ color: 'var(--accent-blue)' }}>{signState.hash_hex?.slice(0, 40)}...</span>
              </div>
            )}
            <div style={{ marginTop: '0.3rem' }}>
              σ = H(m)^d mod N = <span className="mono" style={{ color: 'var(--accent-orange)' }}>{signState.signature_hex?.slice(0, 40)}...</span>
            </div>
            <div style={{ marginTop: '0.3rem', color: 'var(--text-muted)', fontSize: '0.7rem' }}>
              e = {signState.e_int} &nbsp;|&nbsp; N: {signState.N_bits}-bit (key reused for Verify and Tamper below)
            </div>
            {signState.raw && (
              <div style={{ marginTop: '0.3rem', color: 'var(--accent-orange)', fontSize: '0.72rem' }}>{signState.note}</div>
            )}
          </div>
        </div>
      )}

      {/* ── Verify result ── */}
      {tab === 'sign' && verifyState && !verifyState.error && (
        <div className="panel" style={{ marginTop: '0.5rem', borderColor: verifyState.valid ? 'var(--accent-green)' : 'var(--accent-red)' }}>
          <div className="panel-title" style={{ color: verifyState.valid ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '0.85rem' }}>
            🔍 Verify — {verifyState.valid ? '✓ SIGNATURE VALID' : '✗ SIGNATURE INVALID'}
          </div>
          <div className="terminal" style={{ fontSize: '0.75rem' }}>
            <div>Check: σ^e mod N  =?  H(m)</div>
            <div style={{ marginTop: '0.4rem' }}>
              H(m) &nbsp;&nbsp;= <span className="mono" style={{ color: 'var(--accent-blue)' }}>{verifyState.hash_of_message}</span>
            </div>
            <div style={{ marginTop: '0.2rem' }}>
              σ^e mod N = <span className="mono" style={{ color: verifyState.match ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                {verifyState.sigma_e_mod_N}
              </span>
            </div>
            <div style={{ marginTop: '0.4rem', fontWeight: 'bold',
              color: verifyState.match ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              {verifyState.match ? 'Equal ✓ — signature is valid' : 'Not equal ✗ — signature is invalid'}
            </div>
          </div>
        </div>
      )}

      {/* ── Tamper result ── */}
      {tab === 'sign' && tamperState && !tamperState.error && (
        <div className="panel" style={{ marginTop: '0.5rem', borderColor: 'var(--accent-red)' }}>
          <div className="panel-title" style={{ color: 'var(--accent-red)', fontSize: '0.85rem' }}>
            🔧 Tamper — ✗ VERIFICATION FAILS (as expected)
          </div>
          <div className="terminal" style={{ fontSize: '0.75rem' }}>
            <div style={{ color: 'var(--accent-orange)' }}>First byte of m flipped: m′ ≠ m</div>
            <div style={{ marginTop: '0.4rem' }}>
              H(m) &nbsp;&nbsp;&nbsp;= <span className="mono" style={{ color: 'var(--accent-blue)' }}>{signState?.hash_hex?.slice(0, 40)}...</span>
              <span style={{ color: 'var(--text-muted)', marginLeft: '0.4rem', fontSize: '0.7rem' }}>(original)</span>
            </div>
            <div style={{ marginTop: '0.2rem' }}>
              H(m′) &nbsp;&nbsp;= <span className="mono" style={{ color: 'var(--accent-red)' }}>{tamperState.hash_of_message}</span>
              <span style={{ color: 'var(--text-muted)', marginLeft: '0.4rem', fontSize: '0.7rem' }}>(tampered)</span>
            </div>
            <div style={{ marginTop: '0.2rem' }}>
              σ^e mod N = <span className="mono" style={{ color: 'var(--accent-red)' }}>{tamperState.sigma_e_mod_N}</span>
            </div>
            <div style={{ marginTop: '0.4rem', fontWeight: 'bold', color: 'var(--accent-red)' }}>
              σ^e mod N ≠ H(m′) — tampering detected immediately!
            </div>
            <div style={{ marginTop: '0.3rem', color: 'var(--text-muted)', fontSize: '0.72rem' }}>
              The signature σ was made for the original m. Any change to m produces a different hash → verification fails.
            </div>
          </div>
        </div>
      )}

      {/* ── Forgery result ── */}
      {tab === 'forgery' && forgeryState && !forgeryState.error && (
        <div className="panel" style={{ marginTop: '0.5rem', borderColor: forgeryState.forgery_valid ? 'var(--accent-red)' : 'var(--accent-green)' }}>
          <div className="panel-title" style={{ color: forgeryState.forgery_valid ? 'var(--accent-red)' : 'var(--text-muted)' }}>
            {forgeryState.forgery_valid ? '🚨 Forgery Succeeded! (Raw RSA is broken)' : '✓ Forgery Failed'}
          </div>
          <div className="terminal" style={{ fontSize: '0.74rem' }}>
            <div style={{ color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
              Known signatures on m₁ and m₂ (obtained from a signing oracle):
            </div>
            <div>σ(m₁) = "{forgeryState.m1}"^d = <span className="mono">{forgeryState.sig1}</span></div>
            <div style={{ marginTop: '0.2rem' }}>σ(m₂) = "{forgeryState.m2}"^d = <span className="mono">{forgeryState.sig2}</span></div>
            <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem', color: 'var(--accent-red)' }}>
              <strong>Forged:</strong> σ(m₁) × σ(m₂) mod N = <span className="mono">{forgeryState.forged_sig}</span>
              <div style={{ marginTop: '0.3rem' }}>→ valid signature on m₁×m₂ = <span className="mono">{forgeryState.forged_m}</span></div>
            </div>
            <div style={{ marginTop: '0.4rem', color: 'var(--text-muted)', fontSize: '0.72rem' }}>{forgeryState.explanation}</div>
            <div style={{ marginTop: '0.3rem', color: 'var(--accent-green)', fontSize: '0.72rem' }}>
              Fix: Hash-then-Sign — H destroys the multiplicative structure, forgery fails.
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
