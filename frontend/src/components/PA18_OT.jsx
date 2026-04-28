import { useState } from 'react'
const API = 'http://localhost:8000/api'
const post = async (p, b) => {
  const r = await fetch(`${API}/${p}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) })
  return r.json()
}

const EXAMPLES = [
  { label: 'Choose m_0=42', m0: 42, m1: 99, choice: 0 },
  { label: 'Choose m_1=99', m0: 42, m1: 99, choice: 1 },
  { label: 'Choose m_0=7', m0: 7, m1: 13, choice: 0 },
  { label: 'Choose m_1=13', m0: 7, m1: 13, choice: 1 },
]

export default function PA18_OT() {
  const [m0, setM0] = useState('42')
  const [m1, setM1] = useState('99')
  const [choice, setChoice] = useState(null)
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [showCheat, setShowCheat] = useState(false)
  const [protocolRan, setProtocolRan] = useState(false)

  const run = async (c, overM0, overM1) => {
    setLoading(true)
    setChoice(c)
    setResult(null)
    setShowCheat(false)
    setProtocolRan(false)
    try {
      const data = await post('ot/demo', {
        m0: parseInt(overM0 !== undefined ? overM0 : m0),
        m1: parseInt(overM1 !== undefined ? overM1 : m1),
        choice: c,
        bits: 256,
      })
      setResult(data)
      setProtocolRan(true)
    } catch (e) {
      setResult({ error: e.message })
    }
    setLoading(false)
  }

  const loadExample = (ex) => {
    setM0(String(ex.m0))
    setM1(String(ex.m1))
    run(ex.choice, ex.m0, ex.m1)
  }

  return (
    <div className="fade-in">
      <div className="panel">
        <div className="panel-title">🔀 PA#18: Oblivious Transfer (1-out-of-2 OT)</div>
        <div className="panel-subtitle">
          Bellare-Micali OT from PA#16 ElGamal. Receiver learns exactly one of Alice's two messages
          without Alice learning which was chosen. Receiver cannot decrypt the other message.
        </div>

        {/* Toy examples */}
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

        {/* Two-panel layout: Alice (sender) | Bob (receiver) */}
        <div className="two-col" style={{ gap: '0.75rem', marginBottom: '0.75rem' }}>
          {/* Alice panel */}
          <div className="panel" style={{
            opacity: protocolRan ? 0.65 : 1,
            borderColor: 'var(--accent-blue)',
            transition: 'opacity 0.4s'
          }}>
            <div className="panel-title" style={{ color: 'var(--accent-blue)' }}>
              Alice (Sender) — holds m₀, m₁
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
              Alice's messages are visible here (demo). In real OT, Bob never sees both.
            </div>
            <div className="form-row">
              <div className="form-group">
                <label className="form-label">m₀ (message 0)</label>
                <input className="form-input mono" type="number" value={m0}
                  onChange={e => { setM0(e.target.value); setProtocolRan(false) }} style={{ maxWidth: '100px' }} />
              </div>
              <div className="form-group">
                <label className="form-label">m₁ (message 1)</label>
                <input className="form-input mono" type="number" value={m1}
                  onChange={e => { setM1(e.target.value); setProtocolRan(false) }} style={{ maxWidth: '100px' }} />
              </div>
            </div>
            {protocolRan && result && !result.error && (
              <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Alice sent C₀ = Enc(pk₀, m₀) and C₁ = Enc(pk₁, m₁).
                She does NOT know Bob chose b={result.choice}.
              </div>
            )}
          </div>

          {/* Bob panel */}
          <div className="panel" style={{ borderColor: 'var(--accent-green)' }}>
            <div className="panel-title" style={{ color: 'var(--accent-green)' }}>
              Bob (Receiver) — chooses b ∈ {'{0,1}'}
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              Bob clicks his choice. He'll receive m_b and learn nothing about m_{'{1-b}'}.
            </div>
            <div style={{ display: 'flex', gap: '1rem', marginBottom: '0.75rem' }}>
              <button className="btn btn-primary" onClick={() => run(0)} disabled={loading}
                style={{ flex: 1, fontSize: '1rem', padding: '0.6rem',
                  background: (!loading && choice === 0 && protocolRan) ? 'var(--accent-green)' : undefined }}>
                {loading && choice === 0 ? '⏳ Running...' : '📩 Choose 0 (get m₀)'}
              </button>
              <button className="btn btn-primary" onClick={() => run(1)} disabled={loading}
                style={{ flex: 1, fontSize: '1rem', padding: '0.6rem',
                  background: (!loading && choice === 1 && protocolRan) ? 'var(--accent-green)' : undefined }}>
                {loading && choice === 1 ? '⏳ Running...' : '📩 Choose 1 (get m₁)'}
              </button>
            </div>

            {/* Result box */}
            {protocolRan && result && !result.error && (
              <div style={{ background: 'var(--surface-2)', borderRadius: '6px', padding: '0.75rem', marginTop: '0.25rem' }}>
                <div style={{ fontSize: '1rem', fontWeight: 'bold', color: 'var(--accent-green)', marginBottom: '0.4rem' }}>
                  Bob received: m_{result.choice} = {result.received_m_b} ✓
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
                  The other message m_{1 - result.choice} = <strong style={{ color: 'var(--text)' }}>??</strong> (hidden — Bob has no key for it)
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Toy params note */}
        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          Toy parameters: 256-bit ElGamal group. Receiver generates honest pk_b + fake pk_{'{1-b}'} (no trapdoor).
          Sender encrypts under both; receiver decrypts only C_b.
        </div>
      </div>

      {/* Step-by-step protocol log */}
      {result && !result.error && (
        <div className="panel" style={{ marginTop: '0.5rem' }}>
          <div className="panel-title">📋 OT Protocol Step Log</div>
          <div className="terminal" style={{ fontSize: '0.74rem' }}>
            {result.step_log.map((line, i) => (
              <div key={i} style={{
                paddingBottom: '0.2rem',
                color: line.startsWith('Step') ? 'var(--text)' : 'var(--text-muted)',
                fontWeight: line.startsWith('Step') ? '600' : 'normal',
              }}>
                {line}
              </div>
            ))}
          </div>

          {/* Key / Ciphertext summary */}
          <div className="two-col" style={{ gap: '0.5rem', marginTop: '0.75rem' }}>
            <div style={{ fontSize: '0.76rem' }}>
              <div style={{ fontWeight: 'bold', marginBottom: '0.2rem' }}>Public Keys (sent to Sender)</div>
              <div className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                pk₀.h = {result.pk0_h_prefix}...
              </div>
              <div className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                pk₁.h = {result.pk1_h_prefix}...
              </div>
            </div>
            <div style={{ fontSize: '0.76rem' }}>
              <div style={{ fontWeight: 'bold', marginBottom: '0.2rem' }}>Ciphertexts (sent to Receiver)</div>
              <div className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                C₀.c₁ = {result.C0_c1_prefix}...
              </div>
              <div className="mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)', wordBreak: 'break-all' }}>
                C₁.c₁ = {result.C1_c1_prefix}...
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Cheat attempt */}
      {result && !result.error && (
        <div className="panel" style={{ marginTop: '0.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
            <div className="panel-title" style={{ margin: 0 }}>🚨 Cheat Attempt</div>
            <button onClick={() => setShowCheat(v => !v)}
              style={{ padding: '0.25rem 0.7rem', fontSize: '0.75rem', borderRadius: '4px',
                border: '1px solid var(--accent-red)', background: 'transparent',
                color: 'var(--accent-red)', cursor: 'pointer' }}>
              {showCheat ? 'Hide' : 'Try to decrypt C_{1-b}'}
            </button>
          </div>
          {showCheat && (
            <div className="terminal" style={{ marginTop: '0.5rem', fontSize: '0.76rem' }}>
              <div>Bob tries to decrypt C_{result.cheat_attempt.target_index} using a random guessed sk...</div>
              <div style={{ marginTop: '0.4rem' }}>
                Guessed decrypt → <span className="mono">{result.cheat_attempt.guessed_decrypt}</span>
              </div>
              <div>Correct value → <span className="mono">{result.cheat_attempt.correct_value}</span></div>
              <div style={{ marginTop: '0.5rem', fontWeight: 'bold',
                color: result.cheat_attempt.success ? 'var(--accent-red)' : 'var(--accent-green)' }}>
                {result.cheat_attempt.success
                  ? '⚠️ Lucky guess (negligible probability — group too small for demo)'
                  : '✓ Cheat failed — wrong decryption without the trapdoor key'}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginTop: '0.3rem' }}>
                Without sk_{result.cheat_attempt.target_index}, solving ElGamal requires solving DLP (PA#8/PA#11).
                Sender privacy: pk_{1 - result.choice} was constructed with no private key.
              </div>
            </div>
          )}
        </div>
      )}

      {/* Error display */}
      {result && result.error && (
        <div className="terminal" style={{ marginTop: '0.5rem', color: 'var(--accent-red)' }}>
          Error: {result.error}
        </div>
      )}

      {/* Lineage */}
      <div className="panel" style={{ marginTop: '0.5rem', fontSize: '0.74rem', color: 'var(--text-muted)' }}>
        <strong>Lineage:</strong> PA#18 OT → PA#16 ElGamal Enc/Dec → PA#11 DH group → PA#13 Miller-Rabin primes.
        No library substitutions at any layer.
      </div>
    </div>
  )
}
