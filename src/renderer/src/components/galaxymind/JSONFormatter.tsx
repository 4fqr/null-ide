import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function JSONFormatter() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [mode, setMode] = useState<'format' | 'minify'>('format')
  const [error, setError] = useState('')
  const [stats, setStats] = useState<{ valid: boolean; size: number } | null>(null)

  const handleProcess = () => {
    setError('')
    setOutput('')
    setStats(null)

    if (!input.trim()) {
      setError('Please enter JSON to process')
      return
    }

    try {
      const parsed = JSON.parse(input)
      const processed = mode === 'format' ? JSON.stringify(parsed, null, 2) : JSON.stringify(parsed)
      setOutput(processed)
      setStats({
        valid: true,
        size: new Blob([processed]).size
      })
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Invalid JSON'
      setError(`JSON Parse Error: ${errorMessage}`)
    }
  }

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(output)
    }
  }

  const handleClear = () => {
    setInput('')
    setOutput('')
    setError('')
    setStats(null)
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>📋</span>
          JSON Formatter
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Mode</div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                className={`${styles.sendButton} ${mode === 'format' ? '' : styles.secondaryButton}`}
                onClick={() => setMode('format')}
                style={{ flex: 1 }}
              >
                Format (Pretty)
              </button>
              <button
                className={`${styles.sendButton} ${mode === 'minify' ? '' : styles.secondaryButton}`}
                onClick={() => setMode('minify')}
                style={{ flex: 1 }}
              >
                Minify
              </button>
            </div>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Input JSON</div>
            <textarea
              className={styles.textarea}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder='{"name":"John","age":30,"city":"New York"}'
              rows={8}
              style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem' }}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className={styles.sendButton} onClick={handleProcess}>
              {mode === 'format' ? 'Format' : 'Minify'}
            </button>
            <button className={styles.addButton} onClick={handleClear}>
              Clear
            </button>
          </div>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        {output && stats && (
          <div className={styles.results}>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                marginBottom: '1rem'
              }}
            >
              <div>
                <div className={styles.sectionTitle}>Output</div>
                <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)' }}>
                  Size: {stats.size} bytes
                </div>
              </div>
              <button className={styles.addButton} onClick={handleCopy}>
                📋 Copy
              </button>
            </div>
            <pre className={styles.responseBody} style={{ maxHeight: '500px', overflow: 'auto' }}>
              {output}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}
