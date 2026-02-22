import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { SearchIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function DirectoryFuzzer() {
  const [baseUrl, setBaseUrl] = useState('');
  const [wordlist, setWordlist] = useState('');
  const [extensions, setExtensions] = useState('.php,.html,.txt');
  const [results, setResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const commonPaths = [
    'admin',
    'login',
    'api',
    'backup',
    'config',
    'db',
    'test',
    'uploads',
    'files',
    '.git',
    '.env',
    'phpinfo.php',
    'wp-admin',
    'administrator',
  ];

  const fuzz = async () => {
    if (!baseUrl.trim()) {
      setError('Please enter base URL');
      return;
    }

    setLoading(true);
    setError('');
    setResults([]);
    setProgress(0);

    const cleanUrl = baseUrl.replace(/\/$/, '');
    const exts = extensions
      .split(',')
      .map((e) => e.trim())
      .filter((e) => e);
    const paths = wordlist.trim() ? wordlist.split('\n').filter((p) => p.trim()) : commonPaths;
    const found: string[] = [];
    let tested = 0;
    const total = paths.length * (exts.length + 1);

    for (const basePath of paths) {
      const pathsToTest = [basePath, ...exts.map((e) => basePath + e)];

      for (const path of pathsToTest) {
        tested++;
        setProgress(Math.round((tested / total) * 100));

        try {
          const response = await window.electronAPI.net.httpFetch(`${cleanUrl}/${path}`, {
            method: 'GET',
          });
          if (response.success && response.status && response.status < 400) {
            found.push(`${cleanUrl}/${path} (${response.status})`);
            setResults([...found]);
          }
        } catch {}

        await new Promise((r) => setTimeout(r, 30));
      }
    }

    setLoading(false);
    if (found.length === 0) {
      setError('No directories or files found');
    }
  };

  return (
    <ToolWrapper
      title="Directory Fuzzer"
      icon={<SearchIcon />}
      description="Discover hidden directories and files"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Base URL</label>
          <input
            type="text"
            className={styles.input}
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://example.com"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Wordlist (optional, one per line)</label>
          <textarea
            className={styles.textarea}
            value={wordlist}
            onChange={(e) => setWordlist(e.target.value)}
            placeholder="admin&#10;api&#10;backup"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Extensions (comma-separated)</label>
          <input
            type="text"
            className={styles.input}
            value={extensions}
            onChange={(e) => setExtensions(e.target.value)}
            placeholder=".php,.html,.txt"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={fuzz} disabled={loading}>
            {loading ? `Fuzzing... ${progress}%` : 'Start Fuzzing'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setBaseUrl('');
              setWordlist('');
              setResults([]);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {loading && (
        <div className={styles.resultBox}>
          <div className={styles.progressBar}>
            <div className={styles.progressFill} style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Found ({results.length})</span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(results.join('\n'))}
            >
              Copy
            </button>
          </div>
          {results.map((r, i) => (
            <div key={i} className={styles.resultItem}>
              <span className={styles.code}>{r}</span>
            </div>
          ))}
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Directory Fuzzing</h3>
        <ul>
          <li>Discovers hidden resources by testing paths</li>
          <li>Uses common paths if no wordlist provided</li>
          <li>For production, use ffuf or gobuster</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
