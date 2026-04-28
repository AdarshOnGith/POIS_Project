import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => { const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return r.json() }

const EXAMPLES = [
  { label: 'm = 42 (normal)', msg: 42, tamper: false },
  { label: 'm = 42, tamper C_E', msg: 42, tamper: true },
  { label: 'm = 7, tamper C_E', msg: 7, tamper: true },
]

export default function PA17_CCAPKC() {
  const [message, setMessage] = useState('42')
  const [encResult, setEncResult] = useState(null)
  const [tamperResult, setTamperResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const runDemo = async (msg, tamper) => {
    const m = parseInt(msg !== undefined ? msg : message)
    if (isNaN(m) || m < 1) return
    setLoading(true)
    if (!tamper) { setEncResult(null); setTamperResult(null) }
    else setTamperResult(null)
    try {
      const data = await post('cca_pkc/demo', { message: m, tamper: tamper || false, bits: 256 })
      if (!tamper) setEncResult(data)
      else setTamperResult(data)
    } catch (e) {
      const err = { error: e.message }
      if (!tamper) setEncResult(err); else setTamperResult(err)
    }
    setLoading(false)
  }

  const loadExample = (ex) => {
    setMessage(String(ex.msg))
    if (!ex.tamper) runDemo(ex.msg, false)
    else runDemo(ex.msg, true)
  }

  const m = parseInt(message) || 42

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🛡️ PA#17: CCA-Secure PKC (Encrypt-then-Sign)</div>
        <div className="panel-subtitle">
          Combines PA#16 ElGamal (CPA-secure) + PA#15 RSA signatures:
          C_E ← ElGamal_Enc(m), σ ← RSA_Sign(C_E). Decrypt: verify σ first, then decrypt.
          Any modification to C_E invalidates σ → decryption oracle is useless to adversary.
        </div>

        {/* Toy example buttons */}
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Try:</span>
          {EXAMPLES.map(ex => (
            <button key={ex.label} onClick={() => loadExample(ex)} disabled={loading}
              style={{ padding: '0.25rem 0.7rem', fontSize: '0.75rem', borderRadius: '4px',
                border: '1px solid var(--border)', background: 'var(--surface-2)', color: 'var(--text)', cursor: 'pointer' }}>
              {ex.label}
            </button>
          ))}
        </div>

        <div className="form-row">
          <div className="form-group">
            <label className="form-label">Message m (integer)</label>
            <input className="form-input mono" type="number" min={1} value={message}
              onChange={e => setMessage(e.target.value)} style={{ maxWidth: '120px' }} />
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', alignSelf: 'flex-end', flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={() => runDemo(m, false)} disabled={loading}>
              {loading ? '⏳...' : '🔒 Encrypt-then-Sign'}
            </button>
            <button className="btn" onClick={() => runDemo(m, true)} disabled={loading}
              style={{ background: 'var(--accent-red)', color: '#fff', borderColor: 'var(--accent-red)' }}>
              🔧 Tamper C_E → Decryption Oracle
            </button>
          </div>
        </div>

        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
          Toy parameters: 256-bit group. Expected: untampered → decrypts correctly; tampered → ⊥.
        </div>
      </div>

      {/* Normal encryption result */}
      {encResult && !encResult.error && !encResult.tampered && (
        <div className="panel" style={{ marginTop: '0.5rem', borderColor: 'var(--accent-green)' }}>
          <div className="panel-title" style={{ color: 'var(--accent-green)' }}>✓ Encrypt-then-Sign Package (C_E, σ)</div>
          <div className="terminal" style={{ fontSize: '0.75rem' }}>
            <div>m = {encResult.message}</div>
            <div style={{ marginTop: '0.4rem' }}>
              C_E = (c₁, c₂):
              <div className="mono" style={{ marginTop: '0.2rem' }}>c₁ = {encResult.c1}</div>
              <div className="mono">c₂ = {encResult.c2}</div>
            </div>
            <div style={{ marginTop: '0.4rem' }}>σ = RSA_Sign(C_E) = <span className="mono">{encResult.signature}</span></div>
            <div style={{ marginTop: '0.5rem', color: 'var(--accent-green)' }}>
              Decrypted (after verifying σ): {encResult.decrypted} {encResult.correct ? '✓' : '✗'}
            </div>
          </div>
        </div>
      )}

      {/* Tamper demo — the key side-by-side panel */}
      {tamperResult && !tamperResult.error && (
        <div className="two-col" style={{ gap: '0.75rem', marginTop: '0.5rem' }}>
          <div className="panel" style={{ borderColor: 'var(--accent-green)' }}>
            <div className="panel-title" style={{ color: 'var(--accent-green)' }}>🛡 PA#17 CCA-Secure (Encrypt-then-Sign)</div>
            <div className="terminal" style={{ fontSize: '0.74rem' }}>
              <div>Original c₂: <span className="mono">{tamperResult.c2_original}</span></div>
              <div style={{ marginTop: '0.3rem', color: 'var(--accent-red)' }}>
                Tampered 2×c₂: <span className="mono">{tamperResult.c2_tampered}</span>
              </div>
              <div style={{ marginTop: '0.3rem' }}>σ (on original): <span className="mono">{tamperResult.signature}</span></div>
              <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                <div style={{ fontWeight: 'bold', color: tamperResult.cca_rejected ? 'var(--accent-green)' : 'var(--accent-red)', fontSize: '0.95rem' }}>
                  {tamperResult.cca_rejected ? '✓ ' : '✗ '}{tamperResult.cca_message}
                </div>
                <div style={{ marginTop: '0.4rem', color: 'var(--text-muted)', fontSize: '0.71rem' }}>
                  Step 1: Vrfy(σ, tampered C_E) → fails (σ was on original).
                  Decryption aborted. Oracle useless to adversary.
                </div>
              </div>
            </div>
          </div>

          <div className="panel" style={{ borderColor: 'var(--accent-red)' }}>
            <div className="panel-title" style={{ color: 'var(--accent-red)' }}>🚨 Plain ElGamal (PA#16, no signature)</div>
            <div className="terminal" style={{ fontSize: '0.74rem' }}>
              <div>Same tampered 2×c₂: <span className="mono">{tamperResult.c2_tampered}</span></div>
              <div style={{ color: 'var(--text-muted)', marginTop: '0.2rem' }}>No signature → no integrity check</div>
              <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                <div style={{ fontWeight: 'bold', color: 'var(--accent-red)', fontSize: '0.95rem' }}>
                  🚨 Returns: {tamperResult.plain_elgamal_result}
                </div>
                <div style={{ marginTop: '0.3rem', color: 'var(--accent-red)', fontSize: '0.8rem' }}>
                  {tamperResult.plain_elgamal_note}
                </div>
                <div style={{ marginTop: '0.4rem', color: 'var(--text-muted)', fontSize: '0.71rem' }}>
                  Adversary submits tampered ciphertext and learns 2m — CCA2 attack on plain ElGamal.
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {(tamperResult || encResult) && (
        <div className="panel" style={{ marginTop: '0.5rem', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
          <strong>Full lineage:</strong> PA#17 → PA#15 RSA Sign/Verify + PA#16 ElGamal Enc/Dec → PA#12 RSA keygen + PA#11 DH group → PA#13 Miller-Rabin primes. No library substitutions.
        </div>
      )}
    </div>
  )
}
