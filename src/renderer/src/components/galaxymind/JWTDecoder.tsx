import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function JWTDecoder() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [jwt, setJwt] = useState('')
  const [decoded, setDecoded] = useState<{
    header: unknown
    payload: unknown
    signature: string
  } | null>(null)
  const [error, setError] = useState('')

  const decodeJWT = () => {
    setError('')
    setDecoded(null)

    if (!jwt.trim()) {
      setError('Please enter a JWT token')
      return
    }

    try {
      const parts = jwt.split('.')
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format')
      }

      const header = JSON.parse(atob(parts[0]))
      const payload = JSON.parse(atob(parts[1]))
      const signature = parts[2]

      setDecoded({ header, payload, signature })
    } catch (err) {
      setError('Invalid JWT token. Please check your input.')
    }
  }

  const handleClear = () => {
    setJwt('')
    setDecoded(null)
    setError('')
  }

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🎫</span>
          JWT Decoder
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>JWT Token</div>
            <textarea
              className={styles.textarea}
              value={jwt}
              onChange={(e) => setJwt(e.target.value)}
              placeholder="Paste JWT token here (e.g., eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)"
              rows={4}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className={styles.sendButton} onClick={decodeJWT}>
              Decode JWT
            </button>
            <button className={styles.addButton} onClick={handleClear}>
              Clear
            </button>
          </div>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        {decoded && (
          <div className={styles.results}>
            <div className={styles.resultItem}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '0.5rem'
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Header
                </div>
                <button
                  className={styles.addButton}
                  onClick={() => handleCopy(JSON.stringify(decoded.header, null, 2))}
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                >
                  📋 Copy
                </button>
              </div>
              <pre className={styles.responseBody}>{JSON.stringify(decoded.header, null, 2)}</pre>
            </div>

            <div className={styles.resultItem}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '0.5rem'
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Payload
                </div>
                <button
                  className={styles.addButton}
                  onClick={() => handleCopy(JSON.stringify(decoded.payload, null, 2))}
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                >
                  📋 Copy
                </button>
              </div>
              <pre className={styles.responseBody}>{JSON.stringify(decoded.payload, null, 2)}</pre>
            </div>

            <div className={styles.resultItem}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '0.5rem'
                }}
              >
                <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Signature
                </div>
                <button
                  className={styles.addButton}
                  onClick={() => handleCopy(decoded.signature)}
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                >
                  📋 Copy
                </button>
              </div>
              <div
                style={{
                  fontFamily: 'var(--font-mono)',
                  fontSize: '0.75rem',
                  wordBreak: 'break-all',
                  color: 'var(--color-text-secondary)',
                  padding: 'var(--spacing-md)',
                  background: 'var(--color-bg-tertiary)',
                  borderRadius: '4px'
                }}
              >
                {decoded.signature}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
