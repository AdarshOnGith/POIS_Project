import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => { const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return r.json() }

const EXAMPLES = [
  { label: 'm = 42 (no padding)', msg: '42', pkcs: false },
  { label: 'm = 7 (no padding)', msg: '7', pkcs: false },
  { label: 'm = 100 (no padding)', msg: '100', pkcs: false },
  { label: 'm = 42 + PKCS (blocked)', msg: '42', pkcs: true },
]

export default function PA14_CRT() {
  const [message, setMessage] = useState('42')
  const [usePkcs, setUsePkcs] = useState(false)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [showCubeRoot, setShowCubeRoot] = useState(false)

  const runAttack = async (overrides = {}) => {
    const m = parseInt(overrides.msg !== undefined ? overrides.msg : message)
    const pkcs = overrides.pkcs !== undefined ? overrides.pkcs : usePkcs
    if (isNaN(m) || m < 1 || m > 999) return
    setLoading(true); setResult(null); setShowCubeRoot(false)
    try {
      // bits=64 → 64-bit Nᵢ (spec toy parameter)
      const data = await post('hastad/demo', { message: m, bits: 64, use_pkcs: pkcs })
      setResult(data)
    } catch (e) { setResult({ error: e.message }) }
    setLoading(false)
  }

  const loadExample = (ex) => {
    setMessage(ex.msg); setUsePkcs(ex.pkcs)
    runAttack(ex)
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">📡 PA#14: CRT + Håstad Broadcast Attack</div>
        <div className="panel-subtitle">
          Broadcasting the same short message m to 3 recipients with e = 3 lets an attacker recover m
          via CRT + integer cube root — no factoring, no private key needed.
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
            <label className="form-label">Message m (small integer 1–999)</label>
            <input className="form-input mono" type="number" min={1} max={999} value={message}
              onChange={e => setMessage(e.target.value)} style={{ maxWidth: '120px' }} />
          </div>
          <div className="form-group" style={{ justifyContent: 'flex-end' }}>
            <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer', fontSize: '0.85rem' }}>
              <input type="checkbox" checked={usePkcs} onChange={e => setUsePkcs(e.target.checked)} />
              Use PKCS#1 padding (defeats attack)
            </label>
          </div>
          <button className="btn btn-primary" onClick={() => runAttack()} disabled={loading} style={{ alignSelf: 'flex-end' }}>
            {loading ? '⏳ Computing...' : '⚔ Launch Attack'}
          </button>
        </div>

        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
          Toy parameters: 64-bit Nᵢ (instant computation). Message must satisfy m &lt; min(Nᵢ).
        </div>
      </div>

      {result && !result.error && (
        <>
          {/* Three recipient panels */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginTop: '0.5rem' }}>
            {result.recipients?.map(r => (
              <div className="panel" key={r.index} style={{ borderColor: 'var(--accent-blue)' }}>
                <div className="panel-title" style={{ fontSize: '0.8rem', color: 'var(--accent-blue)' }}>Recipient {r.index}</div>
                <div className="terminal" style={{ fontSize: '0.7rem' }}>
                  <div>N_{r.index} ({r.N_bits}-bit): <span className="mono">{r.N}</span></div>
                  <div style={{ marginTop: '0.2rem' }}>e = {r.e}</div>
                  <div style={{ marginTop: '0.3rem' }}>
                    c_{r.index} = m^3 mod N_{r.index}:
                    <div className="mono" style={{ color: 'var(--accent-orange)', marginTop: '0.2rem', wordBreak: 'break-all' }}>
                      {r.ciphertext}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          {/* Attacker panel */}
          <div className="panel" style={{ marginTop: '0.5rem', borderColor: result.use_pkcs ? 'var(--accent-green)' : 'var(--accent-red)' }}>
            <div className="panel-title" style={{ color: result.use_pkcs ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              {result.use_pkcs ? '🛡 Attack Blocked (PKCS padding)' : '🕵️ Attacker — CRT Reconstruction'}
            </div>

            {result.use_pkcs ? (
              <div className="terminal" style={{ fontSize: '0.78rem' }}>
                <div style={{ color: 'var(--accent-green)', fontWeight: 'bold', marginBottom: '0.5rem' }}>✓ PKCS#1 defeats the attack!</div>
                <div style={{ color: 'var(--text-muted)' }}>{result.note}</div>
              </div>
            ) : (
              <div className="terminal" style={{ fontSize: '0.78rem' }}>
                <div style={{ color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                  Apply CRT to (c₁ mod N₁, c₂ mod N₂, c₃ mod N₃):
                </div>
                <div>m³ mod (N₁·N₂·N₃) = <span className="mono" style={{ color: 'var(--accent-orange)' }}>{result.crt_result}</span></div>

                <div style={{ marginTop: '0.75rem' }}>
                  <button className="btn" style={{ background: 'var(--accent-red)', color: '#fff', borderColor: 'var(--accent-red)', fontSize: '0.8rem' }}
                    onClick={() => setShowCubeRoot(true)}>
                    ∛ Compute Integer Cube Root → reveal m
                  </button>
                </div>

                {showCubeRoot && (
                  <div style={{ marginTop: '0.75rem' }}>
                    <div style={{ fontSize: '1.1rem', fontWeight: 'bold', color: result.attack_success ? 'var(--accent-red)' : 'var(--text-muted)' }}>
                      ∛(m³) = <span style={{ fontSize: '1.5rem' }}>{result.cube_root}</span>
                    </div>
                    {result.attack_success && (
                      <div style={{ marginTop: '0.4rem', color: 'var(--accent-red)', fontWeight: 'bold' }}>
                        🚨 Attack succeeded! Recovered m = {result.cube_root} (original = {result.original_message})
                      </div>
                    )}
                    <div style={{ marginTop: '0.5rem', color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                      No factoring needed. The small exponent e = 3 means m³ &lt; N₁N₂N₃ as a plain integer,
                      so the integer cube root is exact.
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="panel" style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
            <strong>Why it works:</strong> m &lt; Nᵢ → m³ &lt; N₁N₂N₃ → CRT gives m³ exactly → ∛ gives m. &nbsp;|&nbsp;
            <strong>Fix:</strong> PKCS#1 pads m with ≥ 8 random bytes → three recipients encrypt different padded values → CRT gives garbage.
          </div>
        </>
      )}

      {result?.error && (
        <div className="panel" style={{ borderColor: 'var(--accent-red)', color: 'var(--accent-red)' }}>⚠ {result.error}</div>
      )}
    </div>
  )
}
