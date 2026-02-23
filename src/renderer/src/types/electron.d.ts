import type { AppConfig, HttpFetchOptions, HttpResponse } from '../../../types/api';

interface FileSystemAPI {
  readFile: (filePath: string) => Promise<{ success: boolean; content?: string; error?: string }>;
  writeFile: (filePath: string, content: string) => Promise<{ success: boolean; error?: string }>;
  readDir: (dirPath: string) => Promise<{
    success: boolean;
    items?: Array<{ name: string; isDirectory: boolean; path: string }>;
    error?: string;
  }>;
  exists: (filePath: string) => Promise<{ success: boolean; exists: boolean }>;
  stat: (filePath: string) => Promise<{
    success: boolean;
    stats?: { isFile: boolean; isDirectory: boolean; size: number; modified: Date };
    error?: string;
  }>;
  createFile: (filePath: string) => Promise<{ success: boolean; error?: string }>;
  createFolder: (folderPath: string) => Promise<{ success: boolean; error?: string }>;
  deleteFile: (filePath: string) => Promise<{ success: boolean; error?: string }>;
  deleteFolder: (folderPath: string) => Promise<{ success: boolean; error?: string }>;
  rename: (oldPath: string, newPath: string) => Promise<{ success: boolean; error?: string }>;
}

interface DialogAPI {
  openFile: () => Promise<{ canceled: boolean; filePaths: string[]; error?: string }>;
  saveFile: () => Promise<{ canceled: boolean; filePath?: string; error?: string }>;
  openDirectory: () => Promise<{ canceled: boolean; filePaths: string[]; error?: string }>;
  selectFolder: () => Promise<{ canceled: boolean; filePaths: string[]; error?: string }>;
}

interface AppAPI {
  getVersion: () => Promise<string>;
  getUserDataPath: () => Promise<string>;
  getInitialPath: () => Promise<string | null>;
  onOpenPath: (callback: (path: string) => void) => void;
}

interface ConfigAPI {
  read: () => Promise<{ success: boolean; config?: AppConfig; error?: string }>;
  write: (config: AppConfig) => Promise<{ success: boolean; error?: string }>;
}

interface CryptoAPI {
  hash: (
    algorithm: 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512',
    data: string
  ) => Promise<{ success: boolean; hash?: string; error?: string }>;
}

interface DNSLookupResult {
  success: boolean;
  addresses?: string[];
  ttl?: number;
  error?: string;
}

interface NetAPI {
  scanPort: (
    host: string,
    port: number,
    timeout?: number
  ) => Promise<{
    success: boolean;
    isOpen?: boolean;
    open?: boolean;
    host?: string;
    port?: number;
    error?: string;
  }>;
  dnsLookup: (hostname: string) => Promise<DNSLookupResult>;
  reverseDns: (ip: string) => Promise<{ success: boolean; hostnames?: string[]; error?: string }>;
  httpFetch: (url: string, options?: HttpFetchOptions) => Promise<HttpResponse>;
}

interface DeepHatAPI {
  position: (bounds: { x: number; y: number; width: number; height: number }) => void;
  toggle: (show: boolean) => void;
  reload: () => void;
}

interface TerminalAPI {
  spawn: (
    terminalId: string,
    shell?: string,
    cwd?: string
  ) => Promise<{ success: boolean; pid?: number; error?: string }>;
  write: (terminalId: string, data: string) => Promise<{ success: boolean; error?: string }>;
  resize: (terminalId: string, cols: number, rows: number) => Promise<{ success: boolean }>;
  kill: (terminalId: string) => Promise<{ success: boolean; error?: string }>;
  onData: (callback: (terminalId: string, data: string) => void) => void;
  onExit: (callback: (terminalId: string, code: number) => void) => void;
}

interface DiscordAPI {
  updateActivity: (fileName: string | null) => void;
}

interface LiveAPI {
  start: (content: string) => Promise<{ success: boolean; error?: string }>;
  stop: () => Promise<{ success: boolean }>;
  onStatus: (callback: (isRunning: boolean, message: string) => void) => void;
}

interface ElectronAPI {
  fs: FileSystemAPI;
  dialog: DialogAPI;
  app: AppAPI;
  config: ConfigAPI;
  crypto: CryptoAPI;
  net: NetAPI;
  deephat: DeepHatAPI;
  terminal: TerminalAPI;
  discord: DiscordAPI;
  live: LiveAPI;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}

export {};
