import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { MaskIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

type Language = 'javascript' | 'powershell';

export default function CodeObfuscator() {
  const [code, setCode] = useState('');
  const [language, setLanguage] = useState<Language>('javascript');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');

  const obfuscateJS = (code: string): string => {
    let result = code;
    result = result.replace(/"([^"]*)"/g, (_, str) => {
      const hex = Array.from(str as string)
        .map((c) => '\\x' + c.charCodeAt(0).toString(16).padStart(2, '0'))
        .join('');
      return `"${hex}"`;
    });
    const junk = `var _${Math.random().toString(36).slice(2)} = ${Math.random()};\n`;
    return junk + result;
  };

  const obfuscatePS = (code: string): string => {
    const b64 = btoa(unescape(encodeURIComponent(code)));
    return `$b64='${b64}';[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))|iex`;
  };

  const obfuscate = () => {
    if (!code.trim()) {
      setError('Please enter code to obfuscate');
      return;
    }
    setOutput(language === 'javascript' ? obfuscateJS(code) : obfuscatePS(code));
  };

  return (
    <ToolWrapper
      title="Code Obfuscator"
      icon={<MaskIcon />}
      description="Obfuscate code to evade detection"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Language</label>
          <select
            className={styles.select}
            value={language}
            onChange={(e) => setLanguage(e.target.value as Language)}
          >
            <option value="javascript">JavaScript</option>
            <option value="powershell">PowerShell</option>
          </select>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Original Code</label>
          <textarea
            className={styles.textarea}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder={language === 'javascript' ? 'console.log("Hello");' : 'Write-Host "Hello"'}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={obfuscate}>
            Obfuscate
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setCode('');
              setOutput('');
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {output && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Obfuscated Code</span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(output)}
            >
              Copy
            </button>
          </div>
          <pre className={styles.codeBlock}>{output}</pre>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Techniques</h3>
        <ul>
          <li>
            <strong>JavaScript:</strong> String hex encoding, variable mangling, junk injection
          </li>
          <li>
            <strong>PowerShell:</strong> Base64 encoding, IEX execution
          </li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
