import { useState } from 'react';
import { PaletteIcon, CopyIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

export default function ColorConverter() {
  const [input, setInput] = useState('#2196f3');
  const [converted, setConverted] = useState<{
    hex: string;
    rgb: string;
    hsl: string;
    preview: string;
  } | null>(null);
  const [error, setError] = useState('');

  const convertColor = () => {
    setError('');
    setConverted(null);

    try {
      const div = document.createElement('div');
      div.style.color = input;
      document.body.appendChild(div);
      const computed = window.getComputedStyle(div).color;
      document.body.removeChild(div);

      if (!computed || computed === input) {
        throw new Error('Invalid color');
      }

      const match = computed.match(/rgb\((\d+),\s*(\d+),\s*(\d+)\)/);
      if (!match) throw new Error('Invalid color');

      const r = parseInt(match[1]);
      const g = parseInt(match[2]);
      const b = parseInt(match[3]);

      const hex = '#' + [r, g, b].map((x) => x.toString(16).padStart(2, '0')).join('');

      const rNorm = r / 255;
      const gNorm = g / 255;
      const bNorm = b / 255;
      const max = Math.max(rNorm, gNorm, bNorm);
      const min = Math.min(rNorm, gNorm, bNorm);
      let h = 0,
        s = 0;
      const l = (max + min) / 2;

      if (max !== min) {
        const d = max - min;
        s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
        switch (max) {
          case rNorm:
            h = ((gNorm - bNorm) / d + (gNorm < bNorm ? 6 : 0)) / 6;
            break;
          case gNorm:
            h = ((bNorm - rNorm) / d + 2) / 6;
            break;
          case bNorm:
            h = ((rNorm - gNorm) / d + 4) / 6;
            break;
        }
      }

      setConverted({
        hex,
        rgb: `rgb(${r}, ${g}, ${b})`,
        hsl: `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`,
        preview: hex,
      });
    } catch {
      setError('Invalid color. Try hex (#fff), rgb(255,0,0), or color names');
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <ToolWrapper
      title="Color Converter"
      icon={<PaletteIcon />}
      description="Convert colors between HEX, RGB, and HSL formats"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Color Input</label>
          <input
            type="text"
            className={styles.input}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="#2196f3, rgb(33,150,243), or 'blue'"
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={convertColor}>
            Convert Color
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {converted && (
        <div className={styles.resultBox}>
          <div
            style={{
              width: '100%',
              height: '100px',
              background: converted.preview,
              borderRadius: 'var(--border-radius-md)',
              marginBottom: '16px',
              border: '1px solid var(--color-border)',
            }}
          />

          {[
            { label: 'HEX', value: converted.hex },
            { label: 'RGB', value: converted.rgb },
            { label: 'HSL', value: converted.hsl },
          ].map(({ label, value }) => (
            <div key={label} className={styles.resultItem}>
              <div
                className={styles.flexRow}
                style={{ justifyContent: 'space-between', alignItems: 'center' }}
              >
                <div>
                  <div style={{ fontWeight: 600, marginBottom: '4px' }}>{label}</div>
                  <div style={{ fontFamily: 'var(--font-mono)', fontSize: '14px' }}>{value}</div>
                </div>
                <button className={styles.copyBtn} onClick={() => handleCopy(value)}>
                  <CopyIcon /> Copy
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
