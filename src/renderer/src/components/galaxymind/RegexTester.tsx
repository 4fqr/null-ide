import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function RegexTester() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [pattern, setPattern] = useState('')
  const [flags, setFlags] = useState('gi')
  const [testString, setTestString] = useState('')
  const [matches, setMatches] = useState<RegExpMatchArray[]>([])
  const [error, setError] = useState('')

  const handleTest = () => {
    setError('')
    setMatches([])

    if (!pattern.trim()) {
      setError('Please enter a regex pattern')
      return
    }

    if (!testString.trim()) {
      setError('Please enter test string')
      return
    }

    try {
      const regex = new RegExp(pattern, flags)
      const foundMatches = Array.from(testString.matchAll(regex))
      setMatches(foundMatches)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Invalid regex pattern'
      setError(errorMessage)
    }
  }

  const handleClear = () => {
    setPattern('')
    setTestString('')
    setMatches([])
    setError('')
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔍</span>
          Regex Tester
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Regular Expression</div>
            <input
              type="text"
              className={styles.input}
              value={pattern}
              onChange={(e) => setPattern(e.target.value)}
              placeholder="e.g., \d{3}-\d{3}-\d{4}"
            />
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Flags</div>
            <div style={{ display: 'flex', gap: '1rem' }}>
              {[
                { flag: 'g', label: 'Global' },
                { flag: 'i', label: 'Case Insensitive' },
                { flag: 'm', label: 'Multiline' },
                { flag: 's', label: 'Dotall' }
              ].map(({ flag, label }) => (
                <label
                  key={flag}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    cursor: 'pointer'
                  }}
                >
                  <input
                    type="checkbox"
                    checked={flags.includes(flag)}
                    onChange={(e) => {
                      if (e.target.checked) {
                        setFlags(flags + flag)
                      } else {
                        setFlags(flags.replace(flag, ''))
                      }
                    }}
                  />
                  <span style={{ fontSize: '0.875rem' }}>{label} ({flag})</span>
                </label>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Test String</div>
            <textarea
              className={styles.textarea}
              value={testString}
              onChange={(e) => setTestString(e.target.value)}
              placeholder="Enter text to test against regex..."
              rows={6}
            />
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className={styles.sendButton} onClick={handleTest}>
              Test Regex
            </button>
            <button className={styles.addButton} onClick={handleClear}>
              Clear
            </button>
          </div>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        {!error && matches.length > 0 && (
          <div className={styles.success}>
            ✓ Found {matches.length} match{matches.length !== 1 ? 'es' : ''}
          </div>
        )}

        {!error && testString && matches.length === 0 && !error && pattern && (
          <div style={{ padding: '1rem', color: 'var(--color-text-secondary)' }}>
            No matches found
          </div>
        )}

        {matches.length > 0 && (
          <div className={styles.results}>
            <div className={styles.sectionTitle}>Matches ({matches.length})</div>
            {matches.map((match, index) => (
              <div key={index} className={styles.resultItem}>
                <div style={{ marginBottom: '0.5rem' }}>
                  <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                    Match {index + 1}:
                  </span>
                  <span
                    style={{
                      marginLeft: '0.5rem',
                      fontFamily: 'var(--font-mono)',
                      color: 'var(--color-accent)'
                    }}
                  >
                    {match[0]}
                  </span>
                </div>
                {match.length > 1 && (
                  <div>
                    <div
                      style={{
                        fontSize: '0.75rem',
                        color: 'var(--color-text-secondary)',
                        marginBottom: '0.25rem'
                      }}
                    >
                      Captured Groups:
                    </div>
                    {match.slice(1).map((group, gIndex) => (
                      <div
                        key={gIndex}
                        style={{
                          fontSize: '0.875rem',
                          fontFamily: 'var(--font-mono)',
                          color: 'var(--color-text-secondary)',
                          marginLeft: '1rem'
                        }}
                      >
                        ${gIndex + 1}: {group}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
