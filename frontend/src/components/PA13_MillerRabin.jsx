import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => { const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return r.json() }

const PRESETS = [
  { label: '561 (Carmichael)', value: '561', rounds: 1, note: 'Fools Fermat, caught by Miller-Rabin' },
  { label: '1729 (Carmichael-2)', value: '1729', rounds: 5, note: '1729 = 7×13×19, smallest absolute Carmichael with 3 factors' },
  { label: '7 (prime)', value: '7', rounds: 40, note: 'Trivially prime' },
  { label: '104729 (prime)', value: '104729', rounds: 20, note: 'Known prime' },
  { label: '100 (composite)', value: '100', rounds: 1, note: 'Even — caught immediately' },
  { label: '2^31−1 (Mersenne)', value: '2147483647', rounds: 20, note: 'Known Mersenne prime' },
]

export default function PA13_MillerRabin() {
  const [number, setNumber] = useState('561')
  const [rounds, setRounds] = useState(1)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)

  const runTest = async (overrides = {}) => {
    const n = parseInt(overrides.value !== undefined ? overrides.value : number)
    const k = overrides.rounds !== undefined ? overrides.rounds : rounds
    if (isNaN(n) || n < 1) return
    setLoading(true); setResult(null)
    try {
      const data = await post('miller_rabin/test', { n, k })
      setResult(data)
    } catch (e) { setResult({ error: e.message }) }
    setLoading(false)
  }

  const loadPreset = (p) => {
    setNumber(p.value); setRounds(p.rounds)
    runTest(p)
  }

  const isPrime = result?.result === 'PROBABLY_PRIME'

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🧪 PA#13: Miller-Rabin Primality Test</div>
        <div className="panel-subtitle">
          Probabilistic primality test: COMPOSITE is definitive; PROBABLY_PRIME has error ≤ 4^(-k).
          For k = 40: probability of error ≈ 10^(-24). Used by PA#11 and PA#12 for key generation.
        </div>

        {/* Preset buttons */}
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
          {PRESETS.map(p => (
            <button key={p.value} onClick={() => loadPreset(p)} disabled={loading}
              style={{ padding: '0.25rem 0.6rem', fontSize: '0.74rem', borderRadius: '4px',
                border: '1px solid var(--border)',
                background: number === p.value ? 'var(--accent-blue)' : 'var(--surface-2)',
                color: number === p.value ? '#fff' : 'var(--text)', cursor: 'pointer' }}
              title={p.note}>{p.label}</button>
          ))}
        </div>

        <div className="form-row">
          <div className="form-group" style={{ flex: 3 }}>
            <label className="form-label">Integer to test (up to 20 digits)</label>
            <input className="form-input mono" value={number} onChange={e => setNumber(e.target.value)} maxLength={20} />
          </div>
          <div className="form-group" style={{ flex: 1 }}>
            <label className="form-label">Rounds k = {rounds}</label>
            <input type="range" min={1} max={40} value={rounds} onChange={e => setRounds(Number(e.target.value))}
              style={{ width: '100%', marginTop: '0.5rem', accentColor: 'var(--accent-blue)' }} />
          </div>
          <button className="btn btn-primary" onClick={() => runTest()} disabled={loading} style={{ alignSelf: 'flex-end' }}>
            {loading ? '⏳...' : '▶ Test'}
          </button>
        </div>
      </div>

      {result && !result.error && (
        <>
          <div className="panel" style={{
            borderColor: isPrime ? 'var(--accent-green)' : 'var(--accent-red)',
            background: isPrime ? 'rgba(0,200,100,0.06)' : 'rgba(255,60,60,0.06)',
            textAlign: 'center', padding: '1.2rem', marginTop: '0.5rem'
          }}>
            <div style={{ fontSize: '1.5rem', fontWeight: 'bold', color: isPrime ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              {isPrime ? '✓ PROBABLY PRIME' : '✗ COMPOSITE'}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
              n = {result.n} ({result.n_bits}-bit) &nbsp;|&nbsp; {result.rounds_run} round{result.rounds_run !== 1 ? 's' : ''} run &nbsp;|&nbsp; {result.time_ms} ms
            </div>
            {result.reason && <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>{result.reason}</div>}
          </div>

          {result.r !== undefined && (
            <div className="panel" style={{ marginTop: '0.5rem' }}>
              <div className="panel-title" style={{ fontSize: '0.85rem' }}>Algorithm: n−1 = 2^r · d</div>
              <div className="terminal" style={{ fontSize: '0.75rem' }}>
                <div>r = <span className="mono">{result.r}</span> &nbsp;&nbsp; d = <span className="mono">{result.d}</span></div>
                <div style={{ marginTop: '0.3rem', color: 'var(--text-muted)' }}>
                  For each witness a: compute x = a^d mod n, then square up to r−1 times.
                  If x never reaches n−1, a is a witness → n is COMPOSITE.
                </div>
              </div>
            </div>
          )}

          {result.witnesses && result.witnesses.length > 0 && (
            <div className="panel" style={{ marginTop: '0.5rem' }}>
              <div className="panel-title" style={{ fontSize: '0.85rem' }}>Witnesses ({result.witnesses.length} tested)</div>
              <div style={{ maxHeight: '180px', overflowY: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.74rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      <th style={{ textAlign: 'left', padding: '0.25rem 0.5rem', color: 'var(--text-muted)' }}>#</th>
                      <th style={{ textAlign: 'left', padding: '0.25rem 0.5rem', color: 'var(--text-muted)' }}>a</th>
                      <th style={{ textAlign: 'left', padding: '0.25rem 0.5rem', color: 'var(--text-muted)' }}>Verdict</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.witnesses.map((w, i) => (
                      <tr key={i} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                        <td style={{ padding: '0.2rem 0.5rem', color: 'var(--text-muted)' }}>{i + 1}</td>
                        <td style={{ padding: '0.2rem 0.5rem', fontFamily: 'monospace' }}>{w.a.slice(0, 24)}{w.a.length > 24 ? '…' : ''}</td>
                        <td style={{ padding: '0.2rem 0.5rem', fontWeight: 'bold',
                          color: w.verdict.startsWith('WITNESS') ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                          {w.verdict}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {number === '561' && result.result === 'COMPOSITE' && (
            <div className="panel" style={{ marginTop: '0.5rem', borderColor: 'var(--accent-orange)', fontSize: '0.78rem' }}>
              <strong style={{ color: 'var(--accent-orange)' }}>Carmichael note:</strong> 561 = 3 × 11 × 17.
              Passes Fermat's test for all bases coprime to it but Miller-Rabin correctly identifies it as composite — even in a single round.
            </div>
          )}
          {number === '1729' && result.result === 'COMPOSITE' && (
            <div className="panel" style={{ marginTop: '0.5rem', borderColor: 'var(--accent-orange)', fontSize: '0.78rem' }}>
              <strong style={{ color: 'var(--accent-orange)' }}>Taxicab number:</strong> 1729 = 7 × 13 × 19.
              Also a Carmichael number — it passes the naive Fermat test for every base coprime to 1729.
              Miller-Rabin catches it.
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
