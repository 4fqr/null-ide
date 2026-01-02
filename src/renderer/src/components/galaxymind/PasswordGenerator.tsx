import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function PasswordGenerator() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [password, setPassword] = useState('')
  const [length, setLength] = useState(16)
  const [options, setOptions] = useState({
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true
  })

  const generatePassword = () => {
    let charset = ''
    if (options.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz'
    if (options.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    if (options.numbers) charset += '0123456789'
    if (options.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'

    if (!charset) {
      setPassword('Please select at least one option')
      return
    }

    const array = new Uint8Array(length)
    crypto.getRandomValues(array)
    const generated = Array.from(array)
      .map((x) => charset[x % charset.length])
      .join('')
    setPassword(generated)
  }

  const handleCopy = () => {
    if (password) {
      navigator.clipboard.writeText(password)
    }
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔑</span>
          Password Generator
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Password Length: {length}</div>
            <input
              type="range"
              min="8"
              max="64"
              value={length}
              onChange={(e) => setLength(parseInt(e.target.value))}
              style={{ width: '100%' }}
            />
          </div>

          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Options</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {[
                { key: 'uppercase', label: 'Uppercase (A-Z)' },
                { key: 'lowercase', label: 'Lowercase (a-z)' },
                { key: 'numbers', label: 'Numbers (0-9)' },
                { key: 'symbols', label: 'Symbols (!@#$...)' }
              ].map(({ key, label }) => (
                <label
                  key={key}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.5rem',
                    cursor: 'pointer'
                  }}
                >
                  <input
                    type="checkbox"
                    checked={options[key as keyof typeof options]}
                    onChange={(e) =>
                      setOptions({ ...options, [key]: e.target.checked })
                    }
                  />
                  <span>{label}</span>
                </label>
              ))}
            </div>
          </div>

          <button className={styles.sendButton} onClick={generatePassword}>
            Generate Password
          </button>
        </div>

        {password && (
          <div className={styles.results}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div className={styles.sectionTitle}>Generated Password</div>
              <button className={styles.addButton} onClick={handleCopy}>
                📋 Copy
              </button>
            </div>
            <div className={styles.responseBody}>
              <pre style={{ margin: 0, fontSize: '1.2rem', userSelect: 'all' }}>{password}</pre>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
