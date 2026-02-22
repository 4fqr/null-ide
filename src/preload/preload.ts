import { contextBridge, ipcRenderer } from 'electron';
import type { AppConfig, HttpFetchOptions } from '../types/api';

type HashAlgorithm = 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512';

const fsAPI = {
  readFile: (filePath: string) => ipcRenderer.invoke('fs:readFile', filePath),
  writeFile: (filePath: string, content: string) =>
    ipcRenderer.invoke('fs:writeFile', filePath, content),
  readDir: (dirPath: string) => ipcRenderer.invoke('fs:readDir', dirPath),
  exists: (filePath: string) => ipcRenderer.invoke('fs:exists', filePath),
  stat: (filePath: string) => ipcRenderer.invoke('fs:stat', filePath),
  createFile: (filePath: string) => ipcRenderer.invoke('fs:createFile', filePath),
  createFolder: (folderPath: string) => ipcRenderer.invoke('fs:createFolder', folderPath),
  delete: (itemPath: string) => ipcRenderer.invoke('fs:delete', itemPath),
  rename: (oldPath: string, newPath: string) => ipcRenderer.invoke('fs:rename', oldPath, newPath),
};

const dialogAPI = {
  openFile: () => ipcRenderer.invoke('dialog:openFile'),
  saveFile: () => ipcRenderer.invoke('dialog:saveFile'),
  openDirectory: () => ipcRenderer.invoke('dialog:openDirectory'),
  selectFolder: () => ipcRenderer.invoke('dialog:openDirectory'),
};

const appAPI = {
  getVersion: () => ipcRenderer.invoke('app:getVersion'),
  getUserDataPath: () => ipcRenderer.invoke('app:getUserDataPath'),
  getInitialPath: () => ipcRenderer.invoke('app:getInitialPath'),
  onOpenPath: (callback: (path: string) => void) =>
    ipcRenderer.on('open-initial-path', (_event, path) => callback(path)),
};

const configAPI = {
  read: () => ipcRenderer.invoke('config:read'),
  write: (config: AppConfig) => ipcRenderer.invoke('config:write', config),
};

const cryptoAPI = {
  hash: (algorithm: HashAlgorithm, data: string) =>
    ipcRenderer.invoke('crypto:hash', algorithm, data),
};

const netAPI = {
  scanPort: (host: string, port: number, timeout?: number) =>
    ipcRenderer.invoke('net:scanPort', host, port, timeout),
  dnsLookup: (hostname: string) => ipcRenderer.invoke('net:dnsLookup', hostname),
  reverseDns: (ip: string) => ipcRenderer.invoke('net:reverseDns', ip),
  httpFetch: (url: string, options?: HttpFetchOptions) =>
    ipcRenderer.invoke('net:httpFetch', url, options),
};

const deephatAPI = {
  position: (bounds: { x: number; y: number; width: number; height: number }) =>
    ipcRenderer.send('position-deephat-view', bounds),
  toggle: (show: boolean) => ipcRenderer.send('toggle-deephat-view', show),
  reload: () => ipcRenderer.send('reload-deephat'),
};

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

const discordAPI = {
  updateActivity: (fileName: string | null) =>
    ipcRenderer.send('discord:update-activity', fileName),
};

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
