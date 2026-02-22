import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { UploadIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function FileUploadTester() {
  const [fileName, setFileName] = useState('test.php');
  const [fileContent, setFileContent] = useState('<?php system($_GET["cmd"]); ?>');
  const [contentType, setContentType] = useState('application/x-php');
  const [results, setResults] = useState<{ type: string; severity: string }[]>([]);
  const [error, setError] = useState('');

  const dangerousExtensions = [
    '.php',
    '.jsp',
    '.asp',
    '.aspx',
    '.exe',
    '.sh',
    '.py',
    '.pl',
    '.cgi',
  ];

  const analyze = () => {
    setError('');
    setResults([]);

    if (!fileName.trim()) {
      setError('Please enter a filename');
      return;
    }

    const vulns: { type: string; severity: string }[] = [];
    const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();

    if (dangerousExtensions.includes(ext)) {
      vulns.push({ type: 'Dangerous Extension', severity: 'Critical' });
    }

    if ((fileName.match(/\./g) || []).length > 1) {
      vulns.push({ type: 'Multiple Extensions', severity: 'High' });
    }

    if (fileName.includes('%00')) {
      vulns.push({ type: 'Null Byte Injection', severity: 'High' });
    }

    if (fileName.includes('../') || fileName.includes('..\\')) {
      vulns.push({ type: 'Path Traversal', severity: 'Critical' });
    }

    const contentLower = fileContent.toLowerCase();
    if (contentLower.includes('<?php') || contentLower.includes('<%')) {
      vulns.push({ type: 'Server-Side Code', severity: 'Critical' });
    }

    if (fileContent.startsWith('GIF89a') || fileContent.startsWith('\xFF\xD8\xFF')) {
      vulns.push({ type: 'Magic Bytes (Polyglot)', severity: 'High' });
    }

    setResults(vulns);
  };

  const loadExample = (type: string) => {
    if (type === 'php') {
      setFileName('shell.php');
      setFileContent('<?php system($_GET["cmd"]); ?>');
      setContentType('application/x-php');
    } else if (type === 'polyglot') {
      setFileName('image.gif');
      setFileContent('GIF89a<?php system($_GET["cmd"]); ?>');
      setContentType('image/gif');
    }
  };

  return (
    <ToolWrapper
      title="File Upload Tester"
      icon={<UploadIcon />}
      description="Analyze file upload security"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Filename</label>
          <input
            type="text"
            className={styles.input}
            value={fileName}
            onChange={(e) => setFileName(e.target.value)}
            placeholder="shell.php"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Content</label>
          <textarea
            className={styles.textarea}
            value={fileContent}
            onChange={(e) => setFileContent(e.target.value)}
            placeholder="File content..."
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Content-Type</label>
          <input
            type="text"
            className={styles.input}
            value={contentType}
            onChange={(e) => setContentType(e.target.value)}
            placeholder="image/jpeg"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={analyze}>
            Analyze
          </button>
          <button className={styles.secondaryBtn} onClick={() => loadExample('php')}>
            PHP Shell
          </button>
          <button className={styles.secondaryBtn} onClick={() => loadExample('polyglot')}>
            Polyglot
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setFileName('');
              setFileContent('');
              setResults([]);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Vulnerabilities ({results.length})</span>
          </div>
          {results.map((r, i) => (
            <div key={i} className={styles.resultItem}>
              <span
                className={r.severity === 'Critical' ? styles.badgeError : styles.badgeWarning}
                style={{ marginRight: '8px' }}
              >
                {r.severity}
              </span>
              {r.type}
            </div>
          ))}
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Bypass Techniques</h3>
        <ul>
          <li>
            <strong>Double Extension:</strong> shell.php.jpg
          </li>
          <li>
            <strong>Null Byte:</strong> shell.php%00.jpg
          </li>
          <li>
            <strong>Polyglot:</strong> GIF89a + PHP code
          </li>
          <li>
            <strong>Case Manipulation:</strong> shell.PhP
          </li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
