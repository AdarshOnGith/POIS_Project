import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => { const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return r.json() }

const EXAMPLES = [
  { label: 'Random keys', alicePriv: '', bobPriv: '', eve: false, bits: 64 },
  { label: 'Fixed keys (a=3, b=7)', alicePriv: '3', bobPriv: '7', eve: false, bits: 64 },
  { label: 'With MITM Eve', alicePriv: '', bobPriv: '', eve: true, bits: 64 },
]

export default function PA11_DH() {
  const [alicePriv, setAlicePriv] = useState('')
  const [bobPriv, setBobPriv] = useState('')
  const [eveEnabled, setEveEnabled] = useState(false)
  const [result, setResult] = useState(null)
  const [mitmResult, setMitmResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const runExchange = async (overrides = {}) => {
    const ap = overrides.alicePriv !== undefined ? overrides.alicePriv : alicePriv
    const bp = overrides.bobPriv !== undefined ? overrides.bobPriv : bobPriv
    const eve = overrides.eve !== undefined ? overrides.eve : eveEnabled
    const bits = overrides.bits || 64
    setLoading(true); setResult(null); setMitmResult(null)
    try {
      const body = { bits }
      if (ap) body.alice_private = parseInt(ap)
      if (bp) body.bob_private = parseInt(bp)
      const data = await post('dh/full_exchange', body)
      setResult(data)
      if (eve) {
        const mitm = await post('dh/mitm_demo', { bits })
        setMitmResult(mitm)
      }
    } catch (e) { setResult({ error: e.message }) }
    setLoading(false)
  }

  const loadExample = (ex) => {
    setAlicePriv(ex.alicePriv); setBobPriv(ex.bobPriv); setEveEnabled(ex.eve)
    runExchange(ex)
  }

  const highlight = (ok) => ({ color: ok ? 'var(--accent-green)' : 'var(--accent-red)', fontWeight: 'bold' })

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🤝 PA#11: Diffie-Hellman Key Exchange</div>
        <div className="panel-subtitle">
          Two parties establish a shared secret over a public channel using g^a mod p and g^b mod p.
          Security relies on the hardness of CDH. Basic DH is unauthenticated — vulnerable to MITM.
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
            <label className="form-label">Alice's private a (optional, leave blank = random)</label>
            <input className="form-input mono" placeholder="random" value={alicePriv} onChange={e => setAlicePriv(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Bob's private b (optional, leave blank = random)</label>
            <input className="form-input mono" placeholder="random" value={bobPriv} onChange={e => setBobPriv(e.target.value)} />
          </div>
          <div className="form-group" style={{ justifyContent: 'flex-end' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
              <input type="checkbox" checked={eveEnabled} onChange={e => setEveEnabled(e.target.checked)} />
              Enable Eve (MITM attack)
            </label>
          </div>
          <button className="btn btn-primary" onClick={() => runExchange()} disabled={loading} style={{ alignSelf: 'flex-end' }}>
            {loading ? '⏳ Exchanging...' : '↔ Exchange'}
          </button>
        </div>

        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
          Toy parameters: 64-bit safe prime (p ≈ 2^64). Instant computation. Values shown in hex.
        </div>
      </div>

      {result && !result.error && (
        <>
          {/* Group parameters */}
          <div className="panel" style={{ borderColor: 'var(--accent-blue)', marginBottom: '0.75rem' }}>
            <div className="panel-title" style={{ color: 'var(--accent-blue)', fontSize: '0.9rem' }}>
              Public Group Parameters ({result.p_bits}-bit safe prime)
            </div>
            <div className="terminal" style={{ fontSize: '0.75rem' }}>
              <div>p = <span className="mono">{result.p}</span></div>
              <div>g = <span className="mono">{result.g}</span></div>
            </div>
          </div>

          {/* Alice / Bob panels */}
          <div className="two-col" style={{ gap: '0.75rem' }}>
            <div className="panel" style={{ borderColor: 'var(--accent-blue)' }}>
              <div className="panel-title" style={{ color: 'var(--accent-blue)' }}>👩 Alice</div>
              <div className="terminal" style={{ fontSize: '0.75rem' }}>
                <div>Private: a = <span className="mono" style={{ color: 'var(--accent-orange)' }}>{result.alice_private}</span></div>
                <div style={{ marginTop: '0.3rem' }}>Sends: A = g^a mod p = <span className="mono">{result.alice_public}</span></div>
                <div style={{ marginTop: '0.4rem' }}>Receives B → K = B^a mod p</div>
                <div style={{ marginTop: '0.3rem', ...highlight(result.shared_match) }}>K = {result.shared_alice}</div>
              </div>
            </div>

            <div className="panel" style={{ borderColor: 'var(--accent-green)' }}>
              <div className="panel-title" style={{ color: 'var(--accent-green)' }}>👨 Bob</div>
              <div className="terminal" style={{ fontSize: '0.75rem' }}>
                <div>Private: b = <span className="mono" style={{ color: 'var(--accent-orange)' }}>{result.bob_private}</span></div>
                <div style={{ marginTop: '0.3rem' }}>Sends: B = g^b mod p = <span className="mono">{result.bob_public}</span></div>
                <div style={{ marginTop: '0.4rem' }}>Receives A → K = A^b mod p</div>
                <div style={{ marginTop: '0.3rem', ...highlight(result.shared_match) }}>K = {result.shared_bob}</div>
              </div>
            </div>
          </div>

          {result.shared_match && (
            <div className="panel" style={{ borderColor: 'var(--accent-green)', background: 'rgba(0,200,100,0.05)', marginTop: '0.5rem', textAlign: 'center' }}>
              <div style={{ color: 'var(--accent-green)', fontWeight: 'bold' }}>
                ✓ Shared secrets match! K = g^(ab) mod p established securely.
              </div>
              <div style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginTop: '0.3rem' }}>
                Eve sees only A = g^a and B = g^b. Computing g^(ab) requires solving CDH — computationally infeasible.
              </div>
            </div>
          )}

          {/* MITM Eve panel */}
          {eveEnabled && mitmResult && (
            <div className="panel" style={{ borderColor: 'var(--accent-red)', marginTop: '0.75rem' }}>
              <div className="panel-title" style={{ color: 'var(--accent-red)' }}>🕵️ Eve — Man-in-the-Middle Attack</div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                Eve intercepts the channel, substitutes her public value g^e for both parties. Each establishes a secret with Eve instead of each other.
              </div>
              <div className="two-col" style={{ gap: '0.5rem' }}>
                <div className="terminal" style={{ fontSize: '0.73rem' }}>
                  <div style={{ color: 'var(--accent-red)', fontWeight: 'bold', marginBottom: '0.3rem' }}>Alice ↔ Eve channel</div>
                  <div>Alice sends A = <span className="mono">{mitmResult.alice_public}</span></div>
                  <div>Eve sends fake g^e = <span className="mono">{mitmResult.eve_public}</span></div>
                  <div style={{ marginTop: '0.3rem' }}>Alice K_AE = <span className="mono" style={{ color: 'var(--accent-red)' }}>{mitmResult.alice_thinks_K}</span></div>
                  <div>Eve K_AE = <span className="mono" style={{ color: 'var(--accent-red)' }}>{mitmResult.eve_key_with_alice}</span></div>
                  <div style={{ marginTop: '0.3rem', color: 'var(--accent-red)', fontWeight: 'bold' }}>
                    {mitmResult.alice_eve_match ? '✓ Match — Eve reads Alice\'s traffic!' : '✗ Mismatch'}
                  </div>
                </div>
                <div className="terminal" style={{ fontSize: '0.73rem' }}>
                  <div style={{ color: 'var(--accent-red)', fontWeight: 'bold', marginBottom: '0.3rem' }}>Bob ↔ Eve channel</div>
                  <div>Bob sends B = <span className="mono">{mitmResult.bob_public}</span></div>
                  <div>Eve sends fake g^e = <span className="mono">{mitmResult.eve_public}</span></div>
                  <div style={{ marginTop: '0.3rem' }}>Bob K_BE = <span className="mono" style={{ color: 'var(--accent-red)' }}>{mitmResult.bob_thinks_K}</span></div>
                  <div>Eve K_BE = <span className="mono" style={{ color: 'var(--accent-red)' }}>{mitmResult.eve_key_with_bob}</span></div>
                  <div style={{ marginTop: '0.3rem', color: 'var(--accent-red)', fontWeight: 'bold' }}>
                    {mitmResult.bob_eve_match ? '✓ Match — Eve reads Bob\'s traffic!' : '✗ Mismatch'}
                  </div>
                </div>
              </div>
              <div style={{ marginTop: '0.75rem', padding: '0.5rem', background: 'rgba(255,60,60,0.08)', borderRadius: '6px', fontSize: '0.78rem', color: 'var(--accent-red)' }}>
                ⚠ Fix: authenticate A and B using Digital Signatures (PA#15) — prevents substitution.
              </div>
            </div>
          )}
        </>
      )}

      {result?.error && (
        <div className="panel" style={{ borderColor: 'var(--accent-red)', color: 'var(--accent-red)' }}>⚠ {result.error}</div>
      )}
    </div>
  )
}
