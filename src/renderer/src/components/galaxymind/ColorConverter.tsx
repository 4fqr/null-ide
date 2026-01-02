import { useState } from 'react'
import { useStore } from '../../store/store'
import styles from './GalaxyTool.module.css'

export default function ColorConverter() {
  const setActiveGalaxyTool = useStore((state: { setActiveGalaxyTool: (tool: string | null) => void }) => state.setActiveGalaxyTool)
  const [input, setInput] = useState('#2196f3')
  const [converted, setConverted] = useState<{
    hex: string
    rgb: string
    hsl: string
    preview: string
  } | null>(null)
  const [error, setError] = useState('')

  const convertColor = () => {
    setError('')
    setConverted(null)

    try {
      // Create a temporary element to parse the color
      const div = document.createElement('div')
      div.style.color = input
      document.body.appendChild(div)
      const computed = window.getComputedStyle(div).color
      document.body.removeChild(div)

      if (!computed || computed === input) {
        throw new Error('Invalid color')
      }

      // Parse RGB
      const match = computed.match(/rgb\\((\\d+),\\s*(\\d+),\\s*(\\d+)\\)/)
      if (!match) throw new Error('Invalid color')

      const r = parseInt(match[1])
      const g = parseInt(match[2])
      const b = parseInt(match[3])

      // Convert to HEX
      const hex = '#' + [r, g, b].map(x => x.toString(16).padStart(2, '0')).join('')

      // Convert to HSL
      const rNorm = r / 255
      const gNorm = g / 255
      const bNorm = b / 255
      const max = Math.max(rNorm, gNorm, bNorm)
      const min = Math.min(rNorm, gNorm, bNorm)
      let h = 0, s = 0
      const l = (max + min) / 2

      if (max !== min) {
        const d = max - min
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min)
        switch (max) {
          case rNorm: h = ((gNorm - bNorm) / d + (gNorm < bNorm ? 6 : 0)) / 6; break
          case gNorm: h = ((bNorm - rNorm) / d + 2) / 6; break
          case bNorm: h = ((rNorm - gNorm) / d + 4) / 6; break
        }
      }

      setConverted({
        hex,
        rgb: `rgb(${r}, ${g}, ${b})`,
        hsl: `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`,
        preview: hex
      })
    } catch (err) {
      setError('Invalid color. Try hex (#fff), rgb(255,0,0), or color names')
    }
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
          <span className={styles.toolIcon}>🎨</span>
          Color Converter
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div style={{ marginBottom: '1rem' }}>
            <div className={styles.label}>Color Input</div>
            <input
              type="text"
              className={styles.input}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="#2196f3, rgb(33,150,243), or 'blue'"
            />
          </div>

          <button className={styles.sendButton} onClick={convertColor}>
            Convert Color
          </button>
        </div>

        {error && <div className={styles.error}>{error}</div>}

        {converted && (
          <div className={styles.results}>
            <div
              style={{
                width: '100%',
                height: '100px',
                background: converted.preview,
                borderRadius: '4px',
                marginBottom: '1rem',
                border: '1px solid var(--color-border)'
              }}
            />

            {[
              { label: 'HEX', value: converted.hex },
              { label: 'RGB', value: converted.rgb },
              { label: 'HSL', value: converted.hsl }
            ].map(({ label, value }) => (
              <div key={label} className={styles.resultItem}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center'
                  }}
                >
                  <div>
                    <div style={{ fontWeight: 600, marginBottom: '0.25rem' }}>{label}</div>
                    <div style={{ fontFamily: 'var(--font-mono)', fontSize: '0.875rem' }}>
                      {value}
                    </div>
                  </div>
                  <button
                    className={styles.addButton}
                    onClick={() => handleCopy(value)}
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
