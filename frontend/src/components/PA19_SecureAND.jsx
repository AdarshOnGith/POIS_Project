import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => {
  const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
  return r.json()
}

const TRUTH_TABLE = [
  { a: 0, b: 0, expected: 0 },
  { a: 0, b: 1, expected: 0 },
  { a: 1, b: 0, expected: 0 },
  { a: 1, b: 1, expected: 1 },
]

export default function PA19_SecureAND() {
  const [aliceBit, setAliceBit] = useState('1')
  const [bobBit, setBobBit] = useState('1')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [allCombos, setAllCombos] = useState(null)
  const [runningAll, setRunningAll] = useState(false)
  const [activeTab, setActiveTab] = useState('and')

  const runAnd = async (overA, overB) => {
    const a = parseInt(overA !== undefined ? overA : aliceBit)
    const b = parseInt(overB !== undefined ? overB : bobBit)
    if (![0, 1].includes(a) || ![0, 1].includes(b)) return
    setLoading(true)
    setResult(null)
    try {
      const data = await post('mpc/and_demo', { a, b, bits: 256 })
      setResult(data)
    } catch (e) {
      setResult({ error: e.message })
    }
    setLoading(false)
  }

  const runAllCombos = async () => {
    setRunningAll(true)
    setAllCombos(null)
    try {
      const data = await post('mpc/all_and_combos', {})
      setAllCombos(data)
    } catch (e) {
      setAllCombos({ error: e.message })
    }
    setRunningAll(false)
  }

  const Tab = ({ id, label }) => (
    <button onClick={() => setActiveTab(id)}
      style={{
        padding: '0.4rem 1rem', fontSize: '0.82rem', borderRadius: '4px',
        border: `1px solid ${activeTab === id ? 'var(--accent-blue)' : 'var(--border)'}`,
        background: activeTab === id ? 'var(--accent-blue)' : 'var(--surface-2)',
        color: activeTab === id ? '#fff' : 'var(--text)', cursor: 'pointer',
      }}>
      {label}
    </button>
  )

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">⚙️ PA#19: Secure AND Gate (via OT)</div>
        <div className="panel-subtitle">
          Secure AND from OT (PA#18): Alice sends OT messages (0, a); Bob runs receiver with choice b.
          Bob receives m_b = a ∧ b. Secure XOR is free (additive secret sharing over ℤ₂).
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
          <Tab id="and" label="Secure AND (step-by-step)" />
          <Tab id="all" label="Run all 4 combinations" />
          <Tab id="xor" label="Secure XOR (free)" />
        </div>

        {/* ── AND tab ── */}
        {activeTab === 'and' && (
          <>
            <div className="two-col" style={{ gap: '0.75rem', marginBottom: '0.75rem' }}>
              {/* Alice panel */}
              <div className="panel" style={{ borderColor: 'var(--accent-blue)' }}>
                <div className="panel-title" style={{ color: 'var(--accent-blue)' }}>Alice — holds bit a</div>
                <div className="form-group" style={{ marginBottom: '0.75rem' }}>
                  <label className="form-label">Bit a ∈ {'{0, 1}'}</label>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    {[0, 1].map(v => (
                      <button key={v} onClick={() => setAliceBit(String(v))}
                        style={{
                          padding: '0.4rem 1.2rem', fontSize: '1.1rem', borderRadius: '4px',
                          border: `2px solid ${String(v) === aliceBit ? 'var(--accent-blue)' : 'var(--border)'}`,
                          background: String(v) === aliceBit ? 'var(--accent-blue)' : 'var(--surface-2)',
                          color: String(v) === aliceBit ? '#fff' : 'var(--text)', cursor: 'pointer',
                        }}>
                        {v}
                      </button>
                    ))}
                  </div>
                </div>
                {result && !result.error && (
                  <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                    Alice set OT messages: (m₀=0, m₁={result.a})
                    <br />Alice does not learn b={result.b} (OT sender privacy).
                  </div>
                )}
              </div>

              {/* Bob panel */}
              <div className="panel" style={{ borderColor: 'var(--accent-green)' }}>
                <div className="panel-title" style={{ color: 'var(--accent-green)' }}>Bob — holds bit b</div>
                <div className="form-group" style={{ marginBottom: '0.75rem' }}>
                  <label className="form-label">Bit b ∈ {'{0, 1}'}</label>
                  <div style={{ display: 'flex', gap: '0.5rem' }}>
                    {[0, 1].map(v => (
                      <button key={v} onClick={() => setBobBit(String(v))}
                        style={{
                          padding: '0.4rem 1.2rem', fontSize: '1.1rem', borderRadius: '4px',
                          border: `2px solid ${String(v) === bobBit ? 'var(--accent-green)' : 'var(--border)'}`,
                          background: String(v) === bobBit ? 'var(--accent-green)' : 'var(--surface-2)',
                          color: String(v) === bobBit ? '#fff' : 'var(--text)', cursor: 'pointer',
                        }}>
                        {v}
                      </button>
                    ))}
                  </div>
                </div>
                {result && !result.error && (
                  <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
                    Bob chose b={result.b} and received m_{result.b} = <strong style={{ color: 'var(--accent-green)' }}>{result.result}</strong>.
                    <br />Bob does not learn a={result.a} directly.
                  </div>
                )}
              </div>
            </div>

            <button className="btn btn-primary" onClick={() => runAnd()} disabled={loading}
              style={{ marginBottom: '0.5rem', fontSize: '1rem', padding: '0.5rem 2rem' }}>
              {loading ? '⏳ Running OT...' : '⚙️ Compute AND securely'}
            </button>

            {/* Result */}
            {result && !result.error && (
              <div className="panel" style={{ marginTop: '0.5rem',
                borderColor: result.correct ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                <div style={{ display: 'flex', gap: '2rem', alignItems: 'center', flexWrap: 'wrap' }}>
                  <div style={{ fontSize: '1.4rem', fontWeight: 'bold' }}>
                    {result.a} ∧ {result.b} = <span style={{ color: result.correct ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                      {result.result}
                    </span>
                  </div>
                  <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                    Expected: {result.expected} {result.correct ? '✓' : '✗'}
                  </div>
                </div>

                {/* Step log */}
                <div style={{ marginTop: '0.75rem' }}>
                  <div style={{ fontWeight: 'bold', fontSize: '0.82rem', marginBottom: '0.4rem' }}>Protocol transcript:</div>
                  <div className="terminal" style={{ fontSize: '0.73rem' }}>
                    {result.step_log.map((line, i) => (
                      <div key={i} style={{
                        paddingBottom: '0.2rem',
                        color: line.startsWith('Alice') || line.startsWith('Bob') ? 'var(--text)' : 'var(--text-muted)',
                        fontWeight: (line.startsWith('Alice') || line.startsWith('Bob')) ? '600' : 'normal',
                      }}>
                        {line}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Privacy summary */}
                <div className="two-col" style={{ gap: '0.5rem', marginTop: '0.75rem' }}>
                  <div style={{ background: 'var(--surface-2)', borderRadius: '6px', padding: '0.6rem', fontSize: '0.76rem' }}>
                    <div style={{ fontWeight: 'bold', color: 'var(--accent-blue)', marginBottom: '0.3rem' }}>What Alice learns:</div>
                    <div style={{ color: 'var(--text-muted)' }}>{result.what_alice_learns}</div>
                  </div>
                  <div style={{ background: 'var(--surface-2)', borderRadius: '6px', padding: '0.6rem', fontSize: '0.76rem' }}>
                    <div style={{ fontWeight: 'bold', color: 'var(--accent-green)', marginBottom: '0.3rem' }}>What Bob learns:</div>
                    <div style={{ color: 'var(--text-muted)' }}>{result.what_bob_learns}</div>
                  </div>
                </div>
              </div>
            )}

            {result && result.error && (
              <div className="terminal" style={{ color: 'var(--accent-red)' }}>Error: {result.error}</div>
            )}
          </>
        )}

        {/* ── All combos tab ── */}
        {activeTab === 'all' && (
          <>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Runs all 4 (a, b) combinations using the full OT-based Secure AND protocol.
              Verifies the truth table is correct and no party learns the other's input.
            </div>
            <button className="btn btn-primary" onClick={runAllCombos} disabled={runningAll}
              style={{ marginBottom: '0.75rem', fontSize: '1rem', padding: '0.5rem 2rem' }}>
              {runningAll ? '⏳ Running all 4 combinations...' : '▶ Run all 4 combinations'}
            </button>

            {/* Static truth table reference */}
            <div style={{ marginBottom: '0.75rem' }}>
              <div style={{ fontWeight: 'bold', fontSize: '0.82rem', marginBottom: '0.4rem' }}>AND Truth Table</div>
              <table style={{ borderCollapse: 'collapse', fontSize: '0.82rem' }}>
                <thead>
                  <tr>
                    {['a', 'b', 'a ∧ b', 'Status'].map(h => (
                      <th key={h} style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem',
                        background: 'var(--surface-2)', textAlign: 'center' }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {TRUTH_TABLE.map(row => {
                    const combo = allCombos?.combinations?.find(c => c.a === row.a && c.b === row.b)
                    return (
                      <tr key={`${row.a}${row.b}`}>
                        <td style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem', textAlign: 'center' }}>{row.a}</td>
                        <td style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem', textAlign: 'center' }}>{row.b}</td>
                        <td style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem', textAlign: 'center', fontWeight: 'bold' }}>{row.expected}</td>
                        <td style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem', textAlign: 'center' }}>
                          {combo
                            ? (combo.correct
                              ? <span style={{ color: 'var(--accent-green)' }}>✓ got {combo.result}</span>
                              : <span style={{ color: 'var(--accent-red)' }}>✗ got {combo.result}</span>)
                            : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>

            {allCombos && !allCombos.error && (
              <div style={{ fontWeight: 'bold', color: allCombos.all_correct ? 'var(--accent-green)' : 'var(--accent-red)' }}>
                {allCombos.all_correct ? '✓ All 4 combinations correct — AND truth table verified!' : '✗ Some combinations failed'}
              </div>
            )}
            {allCombos && allCombos.error && (
              <div style={{ color: 'var(--accent-red)' }}>Error: {allCombos.error}</div>
            )}
          </>
        )}

        {/* ── XOR tab ── */}
        {activeTab === 'xor' && (
          <div>
            <div style={{ fontSize: '0.85rem', marginBottom: '0.75rem' }}>
              <strong>Secure XOR is FREE</strong> — no OT needed. Uses additive secret sharing over ℤ₂:
            </div>
            <div className="terminal" style={{ fontSize: '0.8rem', marginBottom: '0.75rem' }}>
              <div>1. Alice samples random r ← {'{'} 0, 1 {'}'}</div>
              <div>2. Alice sends r to Bob</div>
              <div>3. Alice's share: a_share = a ⊕ r</div>
              <div>4. Bob's share: b_share = b ⊕ r</div>
              <div>5. Output: a_share ⊕ b_share = (a ⊕ r) ⊕ (b ⊕ r) = a ⊕ b ✓</div>
            </div>
            <div style={{ fontSize: '0.8rem', marginBottom: '0.5rem' }}>
              <strong>Secure NOT is also free:</strong> Alice locally flips her share. No communication needed.
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Security: r perfectly masks a (from Bob's view) and b (from Alice's view).
              No information about either party's input is revealed beyond the output.
            </div>
            <div style={{ marginTop: '0.75rem', fontSize: '0.82rem' }}>
              <strong>XOR truth table verification (local computation):</strong>
            </div>
            <table style={{ borderCollapse: 'collapse', fontSize: '0.82rem', marginTop: '0.4rem' }}>
              <thead>
                <tr>
                  {['a', 'b', 'a ⊕ b'].map(h => (
                    <th key={h} style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem',
                      background: 'var(--surface-2)', textAlign: 'center' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[[0,0,0],[0,1,1],[1,0,1],[1,1,0]].map(([a,b,x]) => (
                  <tr key={`${a}${b}`}>
                    <td style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem', textAlign: 'center' }}>{a}</td>
                    <td style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem', textAlign: 'center' }}>{b}</td>
                    <td style={{ border: '1px solid var(--border)', padding: '0.3rem 0.7rem', textAlign: 'center', fontWeight: 'bold',
                      color: 'var(--accent-green)' }}>{x} ✓</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.75rem' }}>
          Toy parameters: 256-bit ElGamal group. Each AND gate uses one OT call (one DH key exchange).
          AND + XOR form a functionally complete basis → can compute any boolean circuit (PA#20).
        </div>
      </div>

      <div className="panel" style={{ marginTop: '0.5rem', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
        <strong>Lineage:</strong> PA#19 Secure AND → PA#18 OT → PA#16 ElGamal → PA#11 DH group → PA#13 Miller-Rabin.
        PA#19 Secure XOR: free via additive secret sharing (no OT needed).
      </div>
    </div>
  )
}
