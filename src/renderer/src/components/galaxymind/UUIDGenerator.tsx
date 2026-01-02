import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function UUIDGenerator() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [uuids, setUuids] = useState<string[]>([])
  const [count, setCount] = useState(5)

  const generateUUIDs = () => {
    const newUuids: string[] = []
    for (let i = 0; i < count; i++) {
      newUuids.push(crypto.randomUUID())
    }
    setUuids(newUuids)
  }

  const handleCopy = (uuid: string) => {
    navigator.clipboard.writeText(uuid)
  }

  const handleCopyAll = () => {
    navigator.clipboard.writeText(uuids.join('\n'))
  }

  const handleClear = () => {
    setUuids([])
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔑</span>
          UUID Generator
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Number of UUIDs</div>
            <input
              type="number"
              className={styles.input}
              value={count}
              onChange={(e) => setCount(Math.max(1, Math.min(100, parseInt(e.target.value) || 1)))}
              min="1"
              max="100"
            />
            <div style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)', marginTop: '0.25rem' }}>
              Generate 1-100 UUIDs at once
            </div>
          </div>

          <div style={{ display: 'flex', gap: '0.5rem' }}>
            <button className={styles.sendButton} onClick={generateUUIDs}>
              Generate UUIDs
            </button>
            {uuids.length > 0 && (
              <>
                <button className={styles.addButton} onClick={handleCopyAll}>
                  📋 Copy All
                </button>
                <button className={styles.addButton} onClick={handleClear}>
                  Clear
                </button>
              </>
            )}
          </div>
        </div>

        {uuids.length > 0 && (
          <div className={styles.results}>
            <div className={styles.sectionTitle}>Generated UUIDs ({uuids.length})</div>
            {uuids.map((uuid, index) => (
              <div key={index} className={styles.resultItem}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    gap: '1rem'
                  }}
                >
                  <div
                    style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: '0.875rem',
                      color: 'var(--color-text-primary)',
                      flex: 1
                    }}
                  >
                    {uuid}
                  </div>
                  <button
                    className={styles.addButton}
                    onClick={() => handleCopy(uuid)}
                    style={{ padding: '0.25rem 0.5rem', fontSize: '0.75rem' }}
                  >
                    📋
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
