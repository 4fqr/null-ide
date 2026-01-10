import { contextBridge, ipcRenderer } from 'electron';

/**
 * Preload script - Exposes safe APIs to the renderer process
 * This maintains security by using contextIsolation
 */

// File system API
const fsAPI = {
  readFile: (filePath: string) => ipcRenderer.invoke('fs:readFile', filePath),
  writeFile: (filePath: string, content: string) =>
    ipcRenderer.invoke('fs:writeFile', filePath, content),
  readDir: (dirPath: string) => ipcRenderer.invoke('fs:readDir', dirPath),
  exists: (filePath: string) => ipcRenderer.invoke('fs:exists', filePath),
  stat: (filePath: string) => ipcRenderer.invoke('fs:stat', filePath),
};

// Dialog API
const dialogAPI = {
  openFile: () => ipcRenderer.invoke('dialog:openFile'),
  saveFile: () => ipcRenderer.invoke('dialog:saveFile'),
  openDirectory: () => ipcRenderer.invoke('dialog:openDirectory'),
  selectFolder: () => ipcRenderer.invoke('dialog:openDirectory'),
};

// App info API
const appAPI = {
  getVersion: () => ipcRenderer.invoke('app:getVersion'),
  getUserDataPath: () => ipcRenderer.invoke('app:getUserDataPath'),
  getInitialPath: () => ipcRenderer.invoke('app:getInitialPath'),
  onOpenPath: (callback: (path: string) => void) => 
    ipcRenderer.on('open-initial-path', (_event, path) => callback(path)),
};

// Config storage API
const configAPI = {
  read: () => ipcRenderer.invoke('config:read'),
  write: (config: any) => ipcRenderer.invoke('config:write', config),
};

// Crypto API
const cryptoAPI = {
  hash: (algorithm: string, data: string) => ipcRenderer.invoke('crypto:hash', algorithm, data),
};

// Network API
const netAPI = {
  scanPort: (host: string, port: number, timeout?: number) =>
    ipcRenderer.invoke('net:scanPort', host, port, timeout),
  dnsLookup: (hostname: string) => ipcRenderer.invoke('net:dnsLookup', hostname),
  reverseDns: (ip: string) => ipcRenderer.invoke('net:reverseDns', ip),
};

// DeepHat browser view control
const deephatAPI = {
  position: (bounds: { x: number; y: number; width: number; height: number }) =>
    ipcRenderer.send('position-deephat-view', bounds),
  toggle: (show: boolean) => ipcRenderer.send('toggle-deephat-view', show),
  reload: () => ipcRenderer.send('reload-deephat'),
};

// Terminal API
const terminalAPI = {
  spawn: (terminalId: string, shell?: string, cwd?: string) =>
    ipcRenderer.invoke('terminal:spawn', terminalId, shell, cwd),
  write: (terminalId: string, data: string) =>
    ipcRenderer.invoke('terminal:write', terminalId, data),
  resize: (terminalId: string, cols: number, rows: number) =>
    ipcRenderer.invoke('terminal:resize', terminalId, cols, rows),
  kill: (terminalId: string) => ipcRenderer.invoke('terminal:kill', terminalId),
  onData: (callback: (terminalId: string, data: string) => void) =>
    ipcRenderer.on('terminal:data', (event, terminalId, data) => callback(terminalId, data)),
  onExit: (callback: (terminalId: string, code: number) => void) =>
    ipcRenderer.on('terminal:exit', (event, terminalId, code) => callback(terminalId, code)),
};

// Discord RPC API
const discordAPI = {
  updateActivity: (fileName: string | null) =>
    ipcRenderer.send('discord:update-activity', fileName),
};

// Expose APIs to renderer
contextBridge.exposeInMainWorld('electronAPI', {
  fs: fsAPI,
  dialog: dialogAPI,
  app: appAPI,
  config: configAPI,
  crypto: cryptoAPI,
  net: netAPI,
  deephat: deephatAPI,
  terminal: terminalAPI,
  discord: discordAPI,
});
