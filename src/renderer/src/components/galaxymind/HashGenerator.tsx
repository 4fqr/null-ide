import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function HashGenerator() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [input, setInput] = useState('')
  const [hashes, setHashes] = useState<Record<string, string>>({})
  const [error, setError] = useState('')

  const generateHashes = async () => {
    setError('')
    setHashes({})

    if (!input.trim()) {
      setError('Please enter text to hash')
      return
    }

    try {
      const encoder = new TextEncoder()
      const data = encoder.encode(input)

      const results: Record<string, string> = {}

      // SHA-256
      const sha256Buffer = await crypto.subtle.digest('SHA-256', data)
      results['SHA-256'] = bufferToHex(sha256Buffer)

      // SHA-384
      const sha384Buffer = await crypto.subtle.digest('SHA-384', data)
      results['SHA-384'] = bufferToHex(sha384Buffer)

      // SHA-512
      const sha512Buffer = await crypto.subtle.digest('SHA-512', data)
      results['SHA-512'] = bufferToHex(sha512Buffer)

      // SHA-1 (legacy)
      const sha1Buffer = await crypto.subtle.digest('SHA-1', data)
      results['SHA-1'] = bufferToHex(sha1Buffer)

      setHashes(results)
    } catch (err) {
      setError('Failed to generate hashes. Please try again.')
    }
  }

  const bufferToHex = (buffer: ArrayBuffer): string => {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
  }

  const handleCopy = (hash: string) => {
    navigator.clipboard.writeText(hash)
  }

  const handleClear = () => {
    setInput('')
    setHashes({})
    setError('')
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔒</span>
          Hash Generator
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Input Text</div>
            <textarea
              className={styles.textarea}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Enter text to hash..."
              rows={4}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className={styles.sendButton} onClick={generateHashes}>
              Generate Hashes
            </button>
            <button className={styles.addButton} onClick={handleClear}>
              Clear
            </button>
          </div>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        {Object.keys(hashes).length > 0 && (
          <div className={styles.results}>
            <div className={styles.sectionTitle}>Generated Hashes</div>
            {Object.entries(hashes).map(([algorithm, hash]) => (
              <div key={algorithm} className={styles.resultItem}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginBottom: '0.5rem'
                  }}
                >
                  <div style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    {algorithm}
                  </div>
                  <button
                    className={styles.addButton}
                    onClick={() => handleCopy(hash)}
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
                    color: 'var(--color-text-secondary)'
                  }}
                >
                  {hash}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
