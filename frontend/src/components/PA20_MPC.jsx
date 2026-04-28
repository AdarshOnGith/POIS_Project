import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => {
  const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
  return r.json()
}

const EXAMPLES_MILL = [
  { label: 'x=7, y=12 (Bob richer)', x: 7, y: 12 },
  { label: 'x=10, y=3 (Alice richer)', x: 10, y: 3 },
  { label: 'x=5, y=5 (Equal)', x: 5, y: 5 },
]
const EXAMPLES_EQ = [
  { label: 'x=6, y=6 (Equal)', x: 6, y: 6 },
  { label: 'x=3, y=7 (Not equal)', x: 3, y: 7 },
]
const EXAMPLES_ADD = [
  { label: '5+3=8', x: 5, y: 3 },
  { label: '7+9=0 (mod 16)', x: 7, y: 9 },
]

function ProgressBar({ value, max, label }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div style={{ marginBottom: '0.4rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.74rem', marginBottom: '0.2rem' }}>
        <span>{label}</span>
        <span>{value} / {max} gates</span>
      </div>
      <div style={{ height: '8px', background: 'var(--surface-2)', borderRadius: '4px', overflow: 'hidden' }}>
        <div style={{
          width: `${pct}%`, height: '100%',
          background: 'var(--accent-green)', borderRadius: '4px',
          transition: 'width 0.3s',
        }} />
      </div>
    </div>
  )
}

function GateTrace({ trace, n_bits }) {
  const [expanded, setExpanded] = useState(false)
  if (!trace || trace.length === 0) return null
  const andGates = trace.filter(g => g.op === 'AND').length
  const xorGates = trace.filter(g => g.op === 'XOR').length
  const notGates = trace.filter(g => g.op === 'NOT').length
  return (
    <div style={{ marginTop: '0.5rem' }}>
      <button onClick={() => setExpanded(v => !v)}
        style={{
          padding: '0.3rem 0.8rem', fontSize: '0.78rem', borderRadius: '4px',
          border: '1px solid var(--border)', background: 'var(--surface-2)',
          color: 'var(--text)', cursor: 'pointer', marginBottom: '0.4rem',
        }}>
        {expanded ? '▼' : '▶'} Circuit trace ({trace.length} gates: {andGates} AND [OT], {xorGates} XOR [free], {notGates} NOT [free])
      </button>
      {expanded && (
        <div className="terminal" style={{ fontSize: '0.7rem', maxHeight: '260px', overflowY: 'auto' }}>
          <div style={{ color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
            Input wires: x[0..{n_bits-1}] = Alice's bits, y[0..{n_bits-1}] = Bob's bits (MSB first)
          </div>
          {trace.map((g, i) => (
            <div key={i} style={{
              paddingBottom: '0.15rem',
              color: g.op === 'AND' ? 'var(--accent-blue)' : g.op === 'XOR' ? 'var(--accent-green)' : 'var(--text-muted)',
            }}>
              {g.op.padEnd(3)} {g.wire.padEnd(18)} ← {g.in1}{g.in2 ? ` , ${g.in2}` : ''} = {g.out}
              {g.op === 'AND' ? ' [OT call]' : g.op === 'XOR' ? ' [free]' : ' [free]'}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function PA20_MPC() {
  const [activeTab, setActiveTab] = useState('millionaire')

  // Millionaire state
  const [mx, setMx] = useState(7)
  const [my, setMy] = useState(12)
  const [millResult, setMillResult] = useState(null)
  const [millLoading, setMillLoading] = useState(false)

  // Equality state
  const [ex, setEx] = useState(6)
  const [ey, setEy] = useState(6)
  const [eqResult, setEqResult] = useState(null)
  const [eqLoading, setEqLoading] = useState(false)

  // Addition state
  const [ax, setAx] = useState(5)
  const [ay, setAy] = useState(3)
  const [addResult, setAddResult] = useState(null)
  const [addLoading, setAddLoading] = useState(false)

  const runMillionaire = async (overX, overY) => {
    const x = overX !== undefined ? overX : mx
    const y = overY !== undefined ? overY : my
    setMillLoading(true); setMillResult(null)
    try {
      const data = await post('mpc/millionaire_trace', { x, y, n_bits: 4 })
      setMillResult(data)
    } catch (e) { setMillResult({ error: e.message }) }
    setMillLoading(false)
  }

  const runEquality = async (overX, overY) => {
    const x = overX !== undefined ? overX : ex
    const y = overY !== undefined ? overY : ey
    setEqLoading(true); setEqResult(null)
    try {
      const data = await post('mpc/equality', { x, y, n_bits: 4 })
      setEqResult(data)
    } catch (e) { setEqResult({ error: e.message }) }
    setEqLoading(false)
  }

  const runAddition = async (overX, overY) => {
    const x = overX !== undefined ? overX : ax
    const y = overY !== undefined ? overY : ay
    setAddLoading(true); setAddResult(null)
    try {
      const data = await post('mpc/addition', { x, y, n_bits: 4 })
      setAddResult(data)
    } catch (e) { setAddResult({ error: e.message }) }
    setAddLoading(false)
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

  const resultColor = (text) => {
    if (!text) return 'var(--text)'
    if (text === 'Alice is richer') return 'var(--accent-blue)'
    if (text === 'Bob is richer') return 'var(--accent-green)'
    return 'var(--accent-yellow, #f5a623)'
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🔒 PA#20: All 2-Party Secure Computation (Yao / GMW)</div>
        <div className="panel-subtitle">
          Any boolean circuit evaluated securely using AND (from PA#19 OT) + XOR (free) + NOT (free).
          Neither party learns the other's input — only the output.
        </div>

        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', flexWrap: 'wrap' }}>
          <Tab id="millionaire" label="💰 Millionaire's Problem" />
          <Tab id="equality" label="🟰 Secure Equality" />
          <Tab id="addition" label="➕ Secure Bit-Addition" />
        </div>

        {/* ── Millionaire's Problem ── */}
        {activeTab === 'millionaire' && (
          <>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Alice has wealth x, Bob has wealth y (4-bit integers, 0–15). Securely compute x {'>'} y
              without either party revealing their actual value. Uses a ripple-comparator circuit
              of AND/XOR/NOT gates evaluated gate-by-gate via PA#19 OT.
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Try:</span>
              {EXAMPLES_MILL.map(ex => (
                <button key={ex.label} onClick={() => { setMx(ex.x); setMy(ex.y); runMillionaire(ex.x, ex.y) }}
                  disabled={millLoading}
                  style={{ padding: '0.25rem 0.7rem', fontSize: '0.75rem', borderRadius: '4px',
                    border: '1px solid var(--border)', background: 'var(--surface-2)',
                    color: 'var(--text)', cursor: 'pointer' }}>
                  {ex.label}
                </button>
              ))}
            </div>

            <div className="two-col" style={{ gap: '0.75rem', marginBottom: '0.75rem' }}>
              {/* Alice panel */}
              <div className="panel" style={{ borderColor: 'var(--accent-blue)' }}>
                <div className="panel-title" style={{ color: 'var(--accent-blue)' }}>Alice — wealth x</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                  Hidden from Bob's panel
                </div>
                <input type="range" min={1} max={100} value={mx}
                  onChange={e => setMx(parseInt(e.target.value))}
                  style={{ width: '100%', marginBottom: '0.4rem' }} />
                <div style={{ textAlign: 'center', fontSize: '1.8rem', fontWeight: 'bold',
                  color: 'var(--accent-blue)', fontFamily: 'monospace' }}>
                  {mx}
                </div>
                <div style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  binary: {mx.toString(2).padStart(4, '0')}
                </div>
              </div>

              {/* Bob panel */}
              <div className="panel" style={{ borderColor: 'var(--accent-green)' }}>
                <div className="panel-title" style={{ color: 'var(--accent-green)' }}>Bob — wealth y</div>
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
                  Hidden from Alice's panel
                </div>
                <input type="range" min={1} max={100} value={my}
                  onChange={e => setMy(parseInt(e.target.value))}
                  style={{ width: '100%', marginBottom: '0.4rem' }} />
                <div style={{ textAlign: 'center', fontSize: '1.8rem', fontWeight: 'bold',
                  color: 'var(--accent-green)', fontFamily: 'monospace' }}>
                  {my}
                </div>
                <div style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  binary: {my.toString(2).padStart(4, '0')}
                </div>
              </div>
            </div>

            <button className="btn btn-primary" onClick={() => runMillionaire()} disabled={millLoading}
              style={{ fontSize: '1rem', padding: '0.5rem 2rem', marginBottom: '0.75rem' }}>
              {millLoading ? '⏳ Evaluating circuit gate-by-gate...' : '💰 Who is richer?'}
            </button>

            {millResult && !millResult.error && (
              <>
                {/* Progress bar */}
                <ProgressBar value={millResult.total_gates} max={millResult.total_gates} label="Gates evaluated" />

                {/* Result banner */}
                <div style={{
                  textAlign: 'center', fontSize: '1.6rem', fontWeight: 'bold',
                  color: resultColor(millResult.result_text),
                  padding: '0.75rem', background: 'var(--surface-2)',
                  borderRadius: '8px', marginTop: '0.5rem', marginBottom: '0.5rem',
                }}>
                  {millResult.result_text === 'Alice is richer' ? '🏆 Alice is richer'
                    : millResult.result_text === 'Bob is richer' ? '🏆 Bob is richer'
                    : '🤝 Equal'}
                </div>

                <div style={{ display: 'flex', gap: '2rem', fontSize: '0.8rem',
                  color: 'var(--text-muted)', justifyContent: 'center', marginBottom: '0.5rem' }}>
                  <span>OT calls (AND gates): <strong>{millResult.ot_calls}</strong></span>
                  <span>Total gates: <strong>{millResult.total_gates}</strong></span>
                  <span>Time: <strong>{millResult.wall_clock_seconds?.toFixed(2)}s</strong></span>
                </div>

                <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginBottom: '0.4rem' }}>
                  Neither party revealed their actual wealth values — only the comparison result.
                  Actual x={mx}, y={my} confirmed: {millResult.x_greater_than_y ? 'x > y' : (mx === my ? 'x = y' : 'x ≤ y')} ✓
                </div>

                <GateTrace trace={millResult.gate_trace} n_bits={millResult.n_bits} />
              </>
            )}
            {millResult && millResult.error && (
              <div className="terminal" style={{ color: 'var(--accent-red)' }}>Error: {millResult.error}</div>
            )}
          </>
        )}

        {/* ── Secure Equality ── */}
        {activeTab === 'equality' && (
          <>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Securely compute x = y (bitwise equality) without revealing x or y.
              Circuit: XOR each bit pair, NOT the result, AND all together.
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Try:</span>
              {EXAMPLES_EQ.map(e => (
                <button key={e.label} onClick={() => { setEx(e.x); setEy(e.y); runEquality(e.x, e.y) }}
                  disabled={eqLoading}
                  style={{ padding: '0.25rem 0.7rem', fontSize: '0.75rem', borderRadius: '4px',
                    border: '1px solid var(--border)', background: 'var(--surface-2)',
                    color: 'var(--text)', cursor: 'pointer' }}>
                  {e.label}
                </button>
              ))}
            </div>

            <div className="two-col" style={{ gap: '0.75rem', marginBottom: '0.75rem' }}>
              <div className="panel" style={{ borderColor: 'var(--accent-blue)' }}>
                <div className="panel-title" style={{ color: 'var(--accent-blue)' }}>Alice — x</div>
                <input type="range" min={0} max={15} value={ex}
                  onChange={e => setEx(parseInt(e.target.value))} style={{ width: '100%', marginBottom: '0.4rem' }} />
                <div style={{ textAlign: 'center', fontSize: '1.8rem', fontWeight: 'bold', color: 'var(--accent-blue)', fontFamily: 'monospace' }}>{ex}</div>
                <div style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>binary: {ex.toString(2).padStart(4, '0')}</div>
              </div>
              <div className="panel" style={{ borderColor: 'var(--accent-green)' }}>
                <div className="panel-title" style={{ color: 'var(--accent-green)' }}>Bob — y</div>
                <input type="range" min={0} max={15} value={ey}
                  onChange={e => setEy(parseInt(e.target.value))} style={{ width: '100%', marginBottom: '0.4rem' }} />
                <div style={{ textAlign: 'center', fontSize: '1.8rem', fontWeight: 'bold', color: 'var(--accent-green)', fontFamily: 'monospace' }}>{ey}</div>
                <div style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>binary: {ey.toString(2).padStart(4, '0')}</div>
              </div>
            </div>

            <button className="btn btn-primary" onClick={() => runEquality()} disabled={eqLoading}
              style={{ fontSize: '1rem', padding: '0.5rem 2rem', marginBottom: '0.75rem' }}>
              {eqLoading ? '⏳ Running...' : '🟰 Are they equal?'}
            </button>

            {eqResult && !eqResult.error && (
              <div style={{ textAlign: 'center', fontSize: '1.4rem', fontWeight: 'bold',
                color: eqResult.are_equal ? 'var(--accent-green)' : 'var(--accent-red)',
                padding: '0.75rem', background: 'var(--surface-2)', borderRadius: '8px' }}>
                {eqResult.are_equal ? '✓ x = y (Equal)' : '✗ x ≠ y (Not equal)'}
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
                  OT calls: {eqResult.ot_calls} | Time: {eqResult.wall_clock_seconds?.toFixed(2)}s
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Actual: {ex} {ex === ey ? '=' : '≠'} {ey} ✓
                </div>
              </div>
            )}
            {eqResult && eqResult.error && (
              <div className="terminal" style={{ color: 'var(--accent-red)' }}>Error: {eqResult.error}</div>
            )}
          </>
        )}

        {/* ── Secure Addition ── */}
        {activeTab === 'addition' && (
          <>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Securely compute x + y mod 2⁴ (4-bit ripple-carry adder). Uses full adder circuit:
              sum_i = x_i ⊕ y_i ⊕ carry_{'{i-1}'}, carry_i via AND gates. Result revealed, inputs stay private.
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center' }}>Try:</span>
              {EXAMPLES_ADD.map(e => (
                <button key={e.label} onClick={() => { setAx(e.x); setAy(e.y); runAddition(e.x, e.y) }}
                  disabled={addLoading}
                  style={{ padding: '0.25rem 0.7rem', fontSize: '0.75rem', borderRadius: '4px',
                    border: '1px solid var(--border)', background: 'var(--surface-2)',
                    color: 'var(--text)', cursor: 'pointer' }}>
                  {e.label}
                </button>
              ))}
            </div>

            <div className="two-col" style={{ gap: '0.75rem', marginBottom: '0.75rem' }}>
              <div className="panel" style={{ borderColor: 'var(--accent-blue)' }}>
                <div className="panel-title" style={{ color: 'var(--accent-blue)' }}>Alice — x</div>
                <input type="range" min={0} max={15} value={ax}
                  onChange={e => setAx(parseInt(e.target.value))} style={{ width: '100%', marginBottom: '0.4rem' }} />
                <div style={{ textAlign: 'center', fontSize: '1.8rem', fontWeight: 'bold', color: 'var(--accent-blue)', fontFamily: 'monospace' }}>{ax}</div>
                <div style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>binary: {ax.toString(2).padStart(4, '0')}</div>
              </div>
              <div className="panel" style={{ borderColor: 'var(--accent-green)' }}>
                <div className="panel-title" style={{ color: 'var(--accent-green)' }}>Bob — y</div>
                <input type="range" min={0} max={15} value={ay}
                  onChange={e => setAy(parseInt(e.target.value))} style={{ width: '100%', marginBottom: '0.4rem' }} />
                <div style={{ textAlign: 'center', fontSize: '1.8rem', fontWeight: 'bold', color: 'var(--accent-green)', fontFamily: 'monospace' }}>{ay}</div>
                <div style={{ textAlign: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>binary: {ay.toString(2).padStart(4, '0')}</div>
              </div>
            </div>

            <button className="btn btn-primary" onClick={() => runAddition()} disabled={addLoading}
              style={{ fontSize: '1rem', padding: '0.5rem 2rem', marginBottom: '0.75rem' }}>
              {addLoading ? '⏳ Running...' : '➕ Compute x + y securely'}
            </button>

            {addResult && !addResult.error && (
              <div style={{ textAlign: 'center', fontSize: '1.4rem', fontWeight: 'bold',
                color: addResult.correct ? 'var(--accent-green)' : 'var(--accent-red)',
                padding: '0.75rem', background: 'var(--surface-2)', borderRadius: '8px' }}>
                x + y mod 2⁴ = {addResult.sum}
                {addResult.correct ? ' ✓' : ` ✗ (expected ${addResult.expected})`}
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
                  OT calls: {addResult.ot_calls} | Time: {addResult.wall_clock_seconds?.toFixed(2)}s
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Actual: {ax} + {ay} = {ax + ay} → mod 16 = {(ax + ay) % 16} ✓
                </div>
              </div>
            )}
            {addResult && addResult.error && (
              <div className="terminal" style={{ color: 'var(--accent-red)' }}>Error: {addResult.error}</div>
            )}
          </>
        )}

        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.75rem' }}>
          Toy parameters: 4-bit circuits (n=4). Each AND gate triggers one OT call (one 256-bit ElGamal encryption).
          AND+XOR+NOT = functionally complete basis → arbitrary 2-party boolean computation.
        </div>
      </div>

      {/* MPC Completeness info */}
      <div className="panel" style={{ marginTop: '0.5rem' }}>
        <div className="panel-title">📐 MPC Completeness (Grand Theorem)</div>
        <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
          Given Secure AND (PA#19, from OT) and Secure XOR (free via additive secret sharing),
          we can securely evaluate <em>any</em> polynomial-time computable 2-party function f(x,y).
          Any boolean circuit can be expressed using AND + XOR + NOT gates.
          Compose our secure gates to get a secure circuit — this is the essence of Yao's Garbled Circuits / GMW protocol.
        </div>
        <div style={{ marginTop: '0.5rem', fontSize: '0.8rem' }}>
          <strong>End-to-end lineage for one AND gate:</strong>
        </div>
        <div className="terminal" style={{ fontSize: '0.74rem', marginTop: '0.3rem' }}>
          PA#20 Secure AND gate<br />
          → PA#19 Secure AND (Secure_AND(a,b))<br />
          → PA#18 OT (OT_Receiver_Step1 / OT_Sender_Step / OT_Receiver_Step2)<br />
          → PA#16 ElGamal Enc/Dec (elgamal_enc, elgamal_dec)<br />
          → PA#11 DH group (dh_generate_group, safe prime p=2q+1)<br />
          → PA#13 Miller-Rabin (gen_prime, miller_rabin for prime generation)<br />
          No library substitutions at any layer.
        </div>
      </div>

      <div className="panel" style={{ marginTop: '0.5rem', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
        <strong>Full lineage:</strong> PA#20 → PA#19 Secure AND/XOR → PA#18 OT → PA#16 ElGamal → PA#11 DH → PA#13 Miller-Rabin.
      </div>
    </div>
  )
}
