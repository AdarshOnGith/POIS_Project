import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => { const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return r.json() }

const EXAMPLES = [
  { label: '"yes" vote (textbook)', msg: 'yes', mode: 'textbook' },
  { label: '"no" vote (textbook)', msg: 'no', mode: 'textbook' },
  { label: '"yes" vote (PKCS)', msg: 'yes', mode: 'pkcs' },
  { label: '"vote_alice" (PKCS)', msg: 'vote_alice', mode: 'pkcs' },
]

export default function PA12_RSA() {
  const [message, setMessage] = useState('yes')
  const [mode, setMode] = useState('textbook')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const runDemo = async (overrides = {}) => {
    const msg = overrides.msg !== undefined ? overrides.msg : message
    const m = overrides.mode !== undefined ? overrides.mode : mode
    setLoading(true); setResult(null)
    try {
      const data = await post('rsa/encrypt_twice', { message: msg || 'vote', mode: m, bits: 512 })
      setResult(data)
    } catch (e) { setResult({ error: e.message }) }
    setLoading(false)
  }

  const loadExample = (ex) => {
    setMessage(ex.msg); setMode(ex.mode)
    runDemo(ex)
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🔑 PA#12: Textbook RSA Determinism Attack</div>
        <div className="panel-subtitle">
          Textbook RSA is deterministic — the same plaintext always produces the same ciphertext,
          breaking CPA security. PKCS#1 v1.5 injects random padding (PS ≥ 8 bytes) to fix this.
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
          <div className="form-group" style={{ flex: 2 }}>
            <label className="form-label">Message (short string, e.g. a vote)</label>
            <input className="form-input" value={message} onChange={e => setMessage(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">RSA Mode</label>
            <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem', fontSize: '0.85rem' }}>
              <label><input type="radio" checked={mode === 'textbook'} onChange={() => setMode('textbook')} /> Textbook RSA</label>
              <label><input type="radio" checked={mode === 'pkcs'} onChange={() => setMode('pkcs')} /> PKCS#1 v1.5</label>
            </div>
          </div>
          <button className="btn btn-primary" onClick={() => runDemo()} disabled={loading} style={{ alignSelf: 'flex-end' }}>
            {loading ? '⏳ Encrypting...' : '🔒 Encrypt Twice'}
          </button>
        </div>

        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
          Toy parameters: 512-bit N. Graders do not need 2048-bit keys for this demo.
        </div>
      </div>

      {result && !result.error && (
        <>
          <div className="panel" style={{
            borderColor: result.identical ? 'var(--accent-red)' : 'var(--accent-green)',
            background: result.identical ? 'rgba(255,60,60,0.07)' : 'rgba(0,200,100,0.07)',
            textAlign: 'center', padding: '1rem', marginTop: '0.5rem'
          }}>
            <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: result.identical ? 'var(--accent-red)' : 'var(--accent-green)' }}>
              {result.identical ? '🚨 ' : '✓ '}{result.banner}
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              {result.mode === 'textbook'
                ? 'An adversary who sees both ciphertexts are equal immediately knows which message was sent.'
                : 'Random PS bytes make each padded plaintext unique → ciphertexts differ every run.'}
            </div>
          </div>

          <div className="two-col" style={{ gap: '0.75rem', marginTop: '0.5rem' }}>
            <div className="panel">
              <div className="panel-title" style={{ fontSize: '0.85rem' }}>Encryption 1</div>
              <div className="terminal" style={{ fontSize: '0.7rem', wordBreak: 'break-all' }}>
                <span className="mono" style={{ color: result.identical ? 'var(--accent-red)' : 'var(--text)' }}>{result.ct1}</span>
              </div>
            </div>
            <div className="panel">
              <div className="panel-title" style={{ fontSize: '0.85rem' }}>Encryption 2</div>
              <div className="terminal" style={{ fontSize: '0.7rem', wordBreak: 'break-all' }}>
                <span className="mono" style={{ color: result.identical ? 'var(--accent-red)' : 'var(--text)' }}>{result.ct2}</span>
              </div>
            </div>
          </div>

          {result.mode === 'pkcs' && result.ps1_hex && (
            <div className="panel" style={{ marginTop: '0.5rem' }}>
              <div className="panel-title" style={{ fontSize: '0.85rem', color: 'var(--accent-green)' }}>Random Padding Bytes PS (≥ 8 nonzero bytes each)</div>
              <div className="terminal" style={{ fontSize: '0.73rem' }}>
                <div>Format: <span className="mono">0x00 ‖ 0x02 ‖ PS ‖ 0x00 ‖ message</span></div>
                <div style={{ marginTop: '0.4rem' }}>PS₁: <span className="mono" style={{ color: 'var(--accent-green)' }}>{result.ps1_hex}...</span></div>
                <div style={{ marginTop: '0.2rem' }}>PS₂: <span className="mono" style={{ color: 'var(--accent-blue)' }}>{result.ps2_hex}...</span></div>
              </div>
            </div>
          )}

          <div className="panel" style={{ marginTop: '0.5rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
            <strong>{result.N_bits}-bit RSA</strong> &nbsp;|&nbsp; e = 65537 &nbsp;|&nbsp;
            {result.mode === 'pkcs'
              ? 'PKCS#1 v1.5 is CPA-secure but NOT CCA-secure (Bleichenbacher 1998 padding oracle attack).'
              : 'Textbook RSA is deterministic → neither CPA nor CCA secure.'}
          </div>
        </>
      )}

      {result?.error && (
        <div className="panel" style={{ borderColor: 'var(--accent-red)', color: 'var(--accent-red)' }}>⚠ {result.error}</div>
      )}
    </div>
  )
}
