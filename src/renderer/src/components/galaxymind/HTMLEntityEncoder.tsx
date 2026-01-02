import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function HTMLEntityEncoder() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [mode, setMode] = useState<'encode' | 'decode'>('encode')

  const entities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&apos;',
    '©': '&copy;',
    '®': '&reg;',
    '™': '&trade;',
    '€': '&euro;',
    '£': '&pound;',
    '¥': '&yen;'
  }

  const handleProcess = () => {
    if (!input.trim()) {
      setOutput('Please enter text')
      return
    }

    if (mode === 'encode') {
      let encoded = input
      for (const [char, entity] of Object.entries(entities)) {
        encoded = encoded.split(char).join(entity)
      }
      setOutput(encoded)
    } else {
      const div = document.createElement('div')
      div.innerHTML = input
      setOutput(div.textContent || div.innerText || '')
    }
  }

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(output)
    }
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔤</span>
          HTML Entity Encoder
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
                  ? 'Enter text with special characters: <, >, &, ", etc.'
                  : 'Enter HTML entities: &lt;, &gt;, &amp;, etc.'
              }
              rows={6}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className={styles.sendButton} onClick={handleProcess}>
              {mode === 'encode' ? 'Encode' : 'Decode'}
            </button>
            <button className={styles.addButton} onClick={() => { setInput(''); setOutput(''); }}>
              Clear
            </button>
          </div>
        </div>

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
