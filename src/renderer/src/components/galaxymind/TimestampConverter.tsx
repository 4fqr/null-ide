import { useState, useEffect } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function TimestampConverter() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [timestamp, setTimestamp] = useState('')
  const [currentTime, setCurrentTime] = useState(Date.now())
  const [converted, setConverted] = useState<{
    unix: number
    iso: string
    utc: string
    local: string
  } | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(Date.now())
    }, 1000)
    return () => clearInterval(interval)
  }, [])

  const handleConvert = () => {
    setError('')
    setConverted(null)

    if (!timestamp.trim()) {
      setError('Please enter a timestamp')
      return
    }

    try {
      let date: Date

      // Try parsing as Unix timestamp (seconds or milliseconds)
      const num = parseFloat(timestamp)
      if (!isNaN(num)) {
        // If less than 10000000000, assume seconds, otherwise milliseconds
        date = new Date(num < 10000000000 ? num * 1000 : num)
      } else {
        // Try parsing as ISO string or other date format
        date = new Date(timestamp)
      }

      if (isNaN(date.getTime())) {
        throw new Error('Invalid timestamp')
      }

      setConverted({
        unix: Math.floor(date.getTime() / 1000),
        iso: date.toISOString(),
        utc: date.toUTCString(),
        local: date.toLocaleString()
      })
    } catch (err) {
      setError('Invalid timestamp format. Use Unix timestamp or ISO 8601 format.')
    }
  }

  const handleUseNow = () => {
    const now = Date.now()
    setTimestamp(Math.floor(now / 1000).toString())
  }

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const handleClear = () => {
    setTimestamp('')
    setConverted(null)
    setError('')
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>⏰</span>
          Timestamp Converter
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div
            style={{
              padding: '1rem',
              background: 'var(--color-bg-tertiary)',
              borderRadius: '4px',
              marginBottom: '1rem',
              textAlign: 'center'
            }}
          >
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-secondary)', marginBottom: '0.5rem' }}>
              Current Unix Timestamp
            </div>
            <div
              style={{
                fontFamily: 'var(--font-mono)',
                fontSize: '1.5rem',
                color: 'var(--color-text-primary)',
                fontWeight: 600
              }}
            >
              {Math.floor(currentTime / 1000)}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)', marginTop: '0.25rem' }}>
              {new Date(currentTime).toLocaleString()}
            </div>
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Timestamp to Convert</div>
            <input
              type="text"
              className={styles.input}
              value={timestamp}
              onChange={(e) => setTimestamp(e.target.value)}
              placeholder="Enter Unix timestamp or ISO 8601 date..."
            />
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)', marginTop: '0.25rem' }}>
              Examples: 1704153600, 2024-01-02T00:00:00Z
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className={styles.sendButton} onClick={handleConvert}>
              Convert
            </button>
            <button className={styles.addButton} onClick={handleUseNow}>
              Use Now
            </button>
            <button className={styles.addButton} onClick={handleClear}>
              Clear
            </button>
          </div>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        {converted && (
          <div className={styles.results}>
            <div className={styles.sectionTitle}>Converted Time</div>
            
            <div className={styles.resultItem}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '0.25rem' }}>
                    Unix Timestamp (seconds)
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-text-secondary)' }}>
                    {converted.unix}
                  </div>
                </div>
                <button
                  className={styles.addButton}
                  onClick={() => handleCopy(converted.unix.toString())}
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                >
                  📋
                </button>
              </div>
            </div>

            <div className={styles.resultItem}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '0.25rem' }}>
                    ISO 8601
                  </div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>
                    {converted.iso}
                  </div>
                </div>
                <button
                  className={styles.addButton}
                  onClick={() => handleCopy(converted.iso)}
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                >
                  📋
                </button>
              </div>
            </div>

            <div className={styles.resultItem}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '0.25rem' }}>
                    UTC
                  </div>
                  <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>
                    {converted.utc}
                  </div>
                </div>
                <button
                  className={styles.addButton}
                  onClick={() => handleCopy(converted.utc)}
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                >
                  📋
                </button>
              </div>
            </div>

            <div className={styles.resultItem}>
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center'
                }}
              >
                <div>
                  <div style={{ fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '0.25rem' }}>
                    Local Time
                  </div>
                  <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>
                    {converted.local}
                  </div>
                </div>
                <button
                  className={styles.addButton}
                  onClick={() => handleCopy(converted.local)}
                  style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                >
                  📋
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
