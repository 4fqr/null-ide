import React from 'react';
import { useStore } from '../../store/store';
import ToolsGrid from '../galaxymind/ToolsGrid';

// Network Tools
import APITester from '../galaxymind/APITester';
import PortScanner from '../galaxymind/PortScanner';
import SubdomainFinder from '../galaxymind/SubdomainFinder';
import DNSAnalyzer from '../galaxymind/DNSAnalyzer';
import WHOISLookup from '../galaxymind/WHOISLookup';

// Web Security Tools
import HeaderAnalyzer from '../galaxymind/HeaderAnalyzer';
import SQLInjectionTester from '../galaxymind/SQLInjectionTester';
import XSSDetector from '../galaxymind/XSSDetector';
import LFIScanner from '../galaxymind/LFIScanner';
import CSRFTester from '../galaxymind/CSRFTester';
import DirectoryFuzzer from '../galaxymind/DirectoryFuzzer';

// Payload Tools
import ReverseShellGenerator from '../galaxymind/ReverseShellGenerator';
import PayloadEncoder from '../galaxymind/PayloadEncoder';
import WebShellGenerator from '../galaxymind/WebShellGenerator';
import CodeObfuscator from '../galaxymind/CodeObfuscator';
import ShellcodeGenerator from '../galaxymind/ShellcodeGenerator';

// Crypto Tools
import HashCracker from '../galaxymind/HashCracker';
import HashGenerator from '../galaxymind/HashGenerator';
import Base64Tool from '../galaxymind/Base64Tool';
import JWTCracker from '../galaxymind/JWTCracker';

// Auth Tools
import JWTDecoder from '../galaxymind/JWTDecoder';
import PasswordGenerator from '../galaxymind/PasswordGenerator';

// Developer Tools
import JSONFormatter from '../galaxymind/JSONFormatter';
import RegexTester from '../galaxymind/RegexTester';
import UUIDGenerator from '../galaxymind/UUIDGenerator';
import TimestampConverter from '../galaxymind/TimestampConverter';
import ColorConverter from '../galaxymind/ColorConverter';
import MarkdownPreview from '../galaxymind/MarkdownPreview';
import DiffViewer from '../galaxymind/DiffViewer';

import styles from './GalaxyMind.module.css';

const GalaxyMind: React.FC = () => {
  const { activeGalaxyTool } = useStore();

  const renderTool = () => {
    switch (activeGalaxyTool) {
      // Network Tools
      case 'api-tester':
        return <APITester />;
      case 'port-scanner':
        return <PortScanner />;
      case 'subdomain-finder':
        return <SubdomainFinder />;
      case 'dns-analyzer':
        return <DNSAnalyzer />;
      case 'whois-lookup':
        return <WHOISLookup />;
      case 'reverse-dns':
        return <DNSAnalyzer />; // Reuse DNS Analyzer

      // Web Security Tools
      case 'header-analyzer':
        return <HeaderAnalyzer />;
      case 'sql-injection':
        return <SQLInjectionTester />;
      case 'xss-detector':
        return <XSSDetector />;
      case 'lfi-scanner':
        return <LFIScanner />;
      case 'csrf-tester':
        return <CSRFTester />;
      case 'directory-fuzzer':
        return <DirectoryFuzzer />;

      // Payload Tools
      case 'reverse-shell':
        return <ReverseShellGenerator />;
      case 'payload-encoder':
        return <PayloadEncoder />;
      case 'webshell-generator':
        return <WebShellGenerator />;
      case 'obfuscator':
        return <CodeObfuscator />;
      case 'shellcode-generator':
        return <ShellcodeGenerator />;

      // Crypto Tools
      case 'hash-cracker':
        return <HashCracker />;
      case 'hash-generator':
        return <HashGenerator />;
      case 'base64-tool':
        return <Base64Tool />;
      case 'jwt-cracker':
        return <JWTCracker />;
      case 'encryption-tool':
        return <Base64Tool />; // Reuse Base64Tool for now

      // API Tools (additional)
      case 'packet-analyzer':
        return <APITester />; // Reuse API Tester
      case 'request-smuggling':
        return <APITester />; // Reuse API Tester
      case 'cors-tester':
        return <APITester />; // Reuse API Tester

      // Auth Tools
      case 'jwt-decoder':
        return <JWTDecoder />;
      case 'password-generator':
        return <PasswordGenerator />;
      case 'oauth-tester':
        return <APITester />; // Reuse API Tester

      // Developer Tools
      case 'json-formatter':
        return <JSONFormatter />;
      case 'regex-tester':
        return <RegexTester />;
      case 'uuid-generator':
        return <UUIDGenerator />;
      case 'timestamp-converter':
        return <TimestampConverter />;
      case 'color-converter':
        return <ColorConverter />;
      case 'markdown-preview':
        return <MarkdownPreview />;
      case 'diff-viewer':
        return <DiffViewer />;

      default:
        return <ToolsGrid />;
    }
  };

  return (
    <div className={styles.galaxyMind}>
      {renderTool()}
    </div>
  );
};

export default GalaxyMind;
