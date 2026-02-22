export interface HttpFetchOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS';
  headers?: Record<string, string>;
  body?: string;
  timeout?: number;
}

export interface HttpResponse {
  success: boolean;
  status?: number;
  statusText?: string;
  headers?: Record<string, string>;
  data?: string;
  error?: string;
  time?: number;
}

export interface NetworkScanResult {
  host: string;
  port: number;
  open: boolean;
  service?: string;
  banner?: string;
}

export interface DNSResult {
  type: string;
  name: string;
  data: string;
  ttl?: number;
}

export interface TestResult {
  name: string;
  payload: string;
  risk: 'Info' | 'Low' | 'Medium' | 'High' | 'Critical';
  url: string;
  responseTime: number;
  vulnerable: boolean;
  indicators: string[];
  details?: string;
}

export interface VulnerabilityReport {
  target: string;
  timestamp: number;
  vulnerabilities: TestResult[];
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

export interface XXEVulnerability {
  type: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  recommendation: string;
}

export interface XXEAnalysis {
  valid: boolean;
  rootElement: string;
  elements: number;
  vulnerabilities: XXEVulnerability[];
  recommendations: string[];
}

export interface SSTIResult {
  template: string;
  engine: string;
  vulnerable: boolean;
  payload: string;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
}

export interface FileUploadVulnerability {
  category: string;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
  recommendation: string;
}

export interface CertificateInfo {
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  version: number;
  signatureAlgorithm: string;
}

export interface AppConfig {
  theme?: 'dark' | 'light';
  fontSize?: number;
  tabSize?: number;
  wordWrap?: boolean;
  minimap?: boolean;
  autoSave?: boolean;
  discordRpc?: boolean;
  editorSettings?: EditorSettings;
}

export interface EditorSettings {
  fontSize: number;
  tabSize: number;
  wordWrap: boolean;
  minimap: boolean;
  lineNumbers?: 'on' | 'off' | 'relative';
  rulers?: number[];
}

export interface FileOperationResult {
  success: boolean;
  content?: string;
  path?: string;
  error?: string;
}

export interface DirectoryEntry {
  name: string;
  path: string;
  isDirectory: boolean;
  size?: number;
  modifiedTime?: number;
}

export interface TerminalInfo {
  id: string;
  title: string;
  shell: string;
  cwd: string;
  pid?: number;
}

export interface TerminalOptions {
  shell?: string;
  cwd?: string;
  env?: Record<string, string>;
}

export type HashAlgorithm = 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512';

export interface HashResult {
  success: boolean;
  hash?: string;
  algorithm?: HashAlgorithm;
  error?: string;
}

export interface JWTDecoded {
  header: Record<string, unknown>;
  payload: Record<string, unknown>;
  signature: string;
}

export interface ReverseShellPayload {
  language: string;
  payload: string;
  description: string;
  usage: string;
}

export interface ShellcodeParams {
  ip?: string;
  port?: string;
  command?: string;
  filename?: string;
}

export interface WebShellTemplate {
  type: string;
  language: string;
  code: string;
  usage: string;
}

export interface IPCResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: string;
}

export interface DialogResult {
  canceled: boolean;
  filePaths: string[];
  error?: string;
}

export interface DiscordActivity {
  details: string;
  state: string;
  startTimestamp: number;
  largeImageKey: string;
  largeImageText: string;
  smallImageKey: string;
  smallImageText: string;
  instance: boolean;
}

export interface UserFriendlyError {
  code: string;
  message: string;
  userMessage: string;
  recoverable: boolean;
  suggestions?: string[];
}

export interface ValidationError {
  field: string;
  message: string;
  value?: unknown;
}
