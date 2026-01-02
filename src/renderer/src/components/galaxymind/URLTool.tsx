import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function URLTool() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [mode, setMode] = useState<'encode' | 'decode'>('encode')
  const [error, setError] = useState('')

  const handleProcess = () => {
    setError('')
    setOutput('')

    if (!input.trim()) {
      setError('Please enter text to process')
      return
    }

    try {
      if (mode === 'encode') {
        const encoded = encodeURIComponent(input)
        setOutput(encoded)
      } else {
        const decoded = decodeURIComponent(input)
        setOutput(decoded)
      }
    } catch (err) {
      setError('Invalid input. Please check your text.')
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
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔗</span>
          URL Encoder/Decoder
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Mode</div>
            <div style={{ display: 'flex', gap: '0.5rem' }}>
              <button
                className={`${styles.sendButton} ${mode === 'encode' ? '' : styles.secondaryButton}`}
                onClick={() => setMode('encode')}
                style={{ flex: 1 }}
              >
                Encode
              </button>
              <button
                className={`${styles.sendButton} ${mode === 'decode' ? '' : styles.secondaryButton}`}
                onClick={() => setMode('decode')}
                style={{ flex: 1 }}
              >
                Decode
              </button>
            </div>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Input</div>
            <textarea
              className={styles.textarea}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={
                mode === 'encode'
                  ? 'Enter text to URL encode...'
                  : 'Enter URL encoded text to decode...'
              }
              rows={6}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className={styles.sendButton} onClick={handleProcess}>
              {mode === 'encode' ? 'Encode' : 'Decode'}
            </button>
            <button className={styles.addButton} onClick={handleClear}>
              Clear
            </button>
          </div>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        {output && (
          <div className={styles.results}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className={styles.sectionTitle}>Output</div>
              <button className={styles.addButton} onClick={handleCopy}>
                📋 Copy
              </button>
            </div>
            <div className={styles.responseBody}>
              <pre style={{ margin: 0, whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                {output}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
