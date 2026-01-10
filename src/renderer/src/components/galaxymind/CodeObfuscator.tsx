import { useState } from 'react';
import styles from './Tool.module.css';

type ObfuscationType = 'javascript' | 'powershell';

export default function CodeObfuscator() {
  const [code, setCode] = useState('');
  const [obfuscationType, setObfuscationType] = useState<ObfuscationType>('javascript');
  const [obfuscatedCode, setObfuscatedCode] = useState('');

  const obfuscateJavaScript = (code: string): string => {
    // Simple obfuscation techniques
    let obfuscated = code;

    // 1. String encoding
    obfuscated = obfuscated.replace(/"([^"]*)"/g, (match, str) => {
      const hex = Array.from(str).map(c => 
        '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0')
      ).join('');
      return `"${hex}"`;
    });

    // 2. Variable name mangling (simple demo)
    const varMap = new Map<string, string>();
    let varCounter = 0;
    obfuscated = obfuscated.replace(/\b([a-z_][a-z0-9_]*)\b/gi, (match) => {
      if (['var', 'let', 'const', 'function', 'return', 'if', 'else', 'for', 'while', 'console', 'log'].includes(match)) {
        return match;
      }
      if (!varMap.has(match)) {
        varMap.set(match, `_0x${(varCounter++).toString(16)}`);
      }
      return varMap.get(match) || match;
    });

    // 3. Add junk code
    const junkVars = Array.from({ length: 3 }, (_, i) => 
      `var _junk${i} = ${Math.random().toString(36).slice(2)};`
    ).join('\n');

    return `${junkVars}\n${obfuscated}`;
  };

  const obfuscatePowerShell = (code: string): string => {
    // PowerShell obfuscation techniques
    let obfuscated = code;

    // 1. Base64 encoding
    const b64 = btoa(unescape(encodeURIComponent(code)));
    const decoderStub = `$b64='${b64}';[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))|iex`;

    // 2. Character substitution
    const charObfuscated = code.split('').map(c => {
      if (c.match(/[a-zA-Z]/)) {
        return `[char]${c.charCodeAt(0)}`;
      }
      return `'${c}'`;
    }).join('+');

    // 3. Tick escaping
    const tickObfuscated = code.replace(/([a-z])/gi, (match) => {
      return Math.random() < 0.3 ? `\`${match}` : match;
    });

    return `# Base64 encoded execution
${decoderStub}

# Alternative: Character concatenation
$cmd=${charObfuscated}
iex $cmd

# Alternative: Tick obfuscation
${tickObfuscated}`;
  };

  const obfuscate = () => {
    if (!code.trim()) {
      alert('Please enter code to obfuscate');
      return;
    }

    let result = '';
    if (obfuscationType === 'javascript') {
      result = obfuscateJavaScript(code);
    } else {
      result = obfuscatePowerShell(code);
    }
    setObfuscatedCode(result);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(obfuscatedCode);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🎭</span>
          Code Obfuscator
        </div>
        <div className={styles.toolSubtitle}>
          Obfuscate JavaScript and PowerShell code to evade detection
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Language</label>
          <select
            value={obfuscationType}
            onChange={(e) => setObfuscationType(e.target.value as ObfuscationType)}
          >
            <option value="javascript">JavaScript</option>
            <option value="powershell">PowerShell</option>
          </select>
        </div>

        <div className={styles.inputGroup}>
          <label>Original Code</label>
          <textarea
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder={
              obfuscationType === 'javascript'
                ? 'console.log("Hello World");\nvar secret = "password123";'
                : 'Write-Host "Hello World"\n$secret = "password123"'
            }
          />
        </div>

        <button className={styles.primaryBtn} onClick={obfuscate}>
          Obfuscate Code
        </button>

        {obfuscatedCode && (
          <div className={styles.outputSection}>
            <div className={styles.outputHeader}>
              <label>Obfuscated Code</label>
              <button className={styles.copyBtn} onClick={copyToClipboard}>
                Copy
              </button>
            </div>
            <div className={styles.output}>{obfuscatedCode}</div>
          </div>
        )}

        <div className={styles.infoBox}>
          <h3>Obfuscation Techniques</h3>
          
          <h4>JavaScript:</h4>
          <ul>
            <li>String hex encoding (\x41\x42\x43)</li>
            <li>Variable name mangling (_0x1a, _0x2b)</li>
            <li>Junk code injection</li>
            <li>Control flow flattening</li>
          </ul>

          <h4>PowerShell:</h4>
          <ul>
            <li>Base64 encoding with IEX</li>
            <li>Character concatenation ([char]72+'e'+'l'+'l'+'o')</li>
            <li>Tick escaping (I`nvo`ke-E`xpre`ssion)</li>
            <li>String reordering and joining</li>
          </ul>

          <h3>Advanced Tools:</h3>
          <ul>
            <li><strong>JavaScript:</strong> javascript-obfuscator, JSFuck, JScrambler</li>
            <li><strong>PowerShell:</strong> Invoke-Obfuscation, ISESteroids, PS-Obfuscate</li>
          </ul>

          <p className={styles.warning}>
            ⚠️ This is a basic demo obfuscator. For production-grade obfuscation, use dedicated tools. Obfuscation may be flagged by security solutions.
          </p>
        </div>
      </div>
    </div>
  );
}
