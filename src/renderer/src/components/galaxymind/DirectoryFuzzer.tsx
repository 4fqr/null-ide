import { useState } from 'react';
import styles from './Tool.module.css';

export default function DirectoryFuzzer() {
  const [baseUrl, setBaseUrl] = useState('');
  const [wordlist, setWordlist] = useState('');
  const [extensions, setExtensions] = useState('.php,.html,.txt,.bak');
  const [fuzzing, setFuzzing] = useState(false);
  const [results, setResults] = useState<Array<{ path: string; status: string }>>([]);
  const [summary, setSummary] = useState('');

  const commonPaths = [
    'admin',
    'login',
    'dashboard',
    'api',
    'backup',
    'config',
    'db',
    'database',
    'test',
    'temp',
    'old',
    'uploads',
    'files',
    'assets',
    'includes',
    'private',
    '.git',
    '.env',
    'phpinfo',
    'info',
    'server-status',
    'wp-admin',
    'administrator'
  ];

  const startFuzzing = async () => {
    if (!baseUrl.trim()) {
      alert('Please enter base URL');
      return;
    }

    setFuzzing(true);
    setResults([]);
    setSummary('Starting directory fuzzing...');

    const cleanUrl = baseUrl.replace(/\/$/, '');
    const exts = extensions.split(',').map(e => e.trim());
    const paths = wordlist.trim() 
      ? wordlist.split('\n').filter(p => p.trim())
      : commonPaths;

    const testResults: Array<{ path: string; status: string }> = [];
    let foundCount = 0;

    for (let i = 0; i < paths.length; i++) {
      const basePath = paths[i].trim();
      
      // Test without extension
      await testPath(basePath);
      
      // Test with each extension
      for (const ext of exts) {
        if (ext) {
          await testPath(basePath + ext);
        }
      }
    }

    async function testPath(path: string) {
      const fullUrl = `${cleanUrl}/${path}`;
      
      try {
        // In a real fuzzer, you would make HTTP requests here
        // For demo purposes, we'll simulate the fuzzing
        await new Promise(resolve => setTimeout(resolve, 50));

        // Simulate findings for demo
        const exists = Math.random() < 0.1; // 10% chance for demo
        const statusCodes = ['200 OK', '403 Forbidden', '301 Redirect', '404 Not Found'];
        const status = exists 
          ? statusCodes[Math.floor(Math.random() * 3)] 
          : '404 Not Found';

        if (exists) {
          foundCount++;
          testResults.push({ path: fullUrl, status: `✓ ${status}` });
          setResults([...testResults]);
        }

        const totalTests = paths.length * (1 + exts.filter(e => e).length);
        setSummary(`Tested ${i + 1}/${paths.length} paths - ${foundCount} found`);
      } catch (error) {
        testResults.push({ path: fullUrl, status: '✗ Error' });
      }
    }

    setSummary(`Fuzzing complete: ${testResults.length} directories/files found`);
    setFuzzing(false);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔍</span>
          Directory Fuzzer
        </div>
        <div className={styles.toolSubtitle}>
          Discover hidden directories and files on web servers
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Base URL</label>
          <input
            type="text"
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://example.com"
            disabled={fuzzing}
          />
        </div>

        <div className={styles.inputGroup}>
          <label>Wordlist (one per line, leave empty for common paths)</label>
          <textarea
            value={wordlist}
            onChange={(e) => setWordlist(e.target.value)}
            placeholder="admin&#10;api&#10;backup&#10;..."
            disabled={fuzzing}
          />
        </div>

        <div className={styles.inputGroup}>
          <label>File Extensions (comma-separated)</label>
          <input
            type="text"
            value={extensions}
            onChange={(e) => setExtensions(e.target.value)}
            placeholder=".php,.html,.txt,.bak"
            disabled={fuzzing}
          />
        </div>

        <button
          className={styles.primaryBtn}
          onClick={startFuzzing}
          disabled={fuzzing}
        >
          {fuzzing ? 'Fuzzing...' : 'Start Fuzzing'}
        </button>

        {summary && (
          <div className={styles.outputSection}>
            <label>Status</label>
            <div className={styles.output}>{summary}</div>
          </div>
        )}

        {results.length > 0 && (
          <div className={styles.outputSection}>
            <label>Discovered Paths ({results.length} found)</label>
            <div className={styles.output}>
              {results.map((result, idx) => (
                <div key={idx} style={{ marginBottom: '6px' }}>
                  {result.status} - {result.path}
                </div>
              ))}
            </div>
          </div>
        )}

        <div className={styles.infoBox}>
          <h3>Directory Fuzzing</h3>
          <p>Discovers hidden resources by testing common paths and extensions:</p>
          <ul>
            <li>Admin panels (/admin, /dashboard)</li>
            <li>Backup files (.bak, .old, .backup)</li>
            <li>Configuration files (.env, config.php)</li>
            <li>Development artifacts (.git, .svn)</li>
            <li>API endpoints (/api, /v1, /graphql)</li>
            <li>Sensitive files (phpinfo.php, server-status)</li>
          </ul>

          <h3>Recommended Tools</h3>
          <p>For production fuzzing, use dedicated tools with features like:</p>
          <ul>
            <li><strong>ffuf:</strong> Fast web fuzzer written in Go</li>
            <li><strong>dirbuster/dirb:</strong> Classic directory bruteforce tools</li>
            <li><strong>gobuster:</strong> Directory/DNS/vhost bruteforcing</li>
            <li><strong>feroxbuster:</strong> Recursive content discovery</li>
          </ul>

          <p className={styles.warning}>
            ⚠️ This is a DEMO fuzzer. Real fuzzing requires actual HTTP requests, thread management, and response analysis. Always get permission before fuzzing.
          </p>
        </div>
      </div>
    </div>
  );
}
