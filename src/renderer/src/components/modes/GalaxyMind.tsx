import React from 'react';
import { useStore } from '../../store/store';
import ToolsGrid from '../galaxymind/ToolsGrid';
import APITester from '../galaxymind/APITester';
import PortScanner from '../galaxymind/PortScanner';
import SubdomainFinder from '../galaxymind/SubdomainFinder';
import DNSAnalyzer from '../galaxymind/DNSAnalyzer';
import WHOISLookup from '../galaxymind/WHOISLookup';
import UptimeChecker from '../galaxymind/UptimeChecker';
import HeaderAnalyzer from '../galaxymind/HeaderAnalyzer';
import SQLInjectionTester from '../galaxymind/SQLInjectionTester';
import XSSDetector from '../galaxymind/XSSDetector';
import Base64Tool from '../galaxymind/Base64Tool';
import URLTool from '../galaxymind/URLTool';
import HashGenerator from '../galaxymind/HashGenerator';
import JWTDecoder from '../galaxymind/JWTDecoder';
import JSONFormatter from '../galaxymind/JSONFormatter';
import RegexTester from '../galaxymind/RegexTester';
import UUIDGenerator from '../galaxymind/UUIDGenerator';
import TimestampConverter from '../galaxymind/TimestampConverter';
import PasswordGenerator from '../galaxymind/PasswordGenerator';
import ColorConverter from '../galaxymind/ColorConverter';
import HTMLEntityEncoder from '../galaxymind/HTMLEntityEncoder';
import MarkdownPreview from '../galaxymind/MarkdownPreview';
import LoremIpsumGenerator from '../galaxymind/LoremIpsumGenerator';
import DiffViewer from '../galaxymind/DiffViewer';
import CSSMinifier from '../galaxymind/CSSMinifier';
import JSONBeautifier from '../galaxymind/JSONBeautifier';
import SlugGenerator from '../galaxymind/SlugGenerator';
import CronGenerator from '../galaxymind/CronGenerator';
import styles from './GalaxyMind.module.css';

const GalaxyMind: React.FC = () => {
  const { activeGalaxyTool } = useStore();

  const renderTool = () => {
    switch (activeGalaxyTool) {
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
      case 'uptime-checker':
        return <UptimeChecker />;
      case 'header-analyzer':
        return <HeaderAnalyzer />;
      case 'sql-injection':
        return <SQLInjectionTester />;
      case 'xss-detector':
        return <XSSDetector />;
      case 'base64-tool':
        return <Base64Tool />;
      case 'url-tool':
        return <URLTool />;
      case 'hash-generator':
        return <HashGenerator />;
      case 'jwt-decoder':
        return <JWTDecoder />;
      case 'json-formatter':
        return <JSONFormatter />;
      case 'regex-tester':
        return <RegexTester />;
      case 'uuid-generator':
        return <UUIDGenerator />;
      case 'timestamp-converter':
        return <TimestampConverter />;
      case 'password-generator':
        return <PasswordGenerator />;
      case 'color-converter':
        return <ColorConverter />;
      case 'html-encoder':
        return <HTMLEntityEncoder />;
      case 'markdown-preview':
        return <MarkdownPreview />;
      case 'lorem-ipsum':
        return <LoremIpsumGenerator />;
      case 'diff-viewer':
        return <DiffViewer />;
      case 'css-minifier':
        return <CSSMinifier />;
      case 'json-beautifier':
        return <JSONBeautifier />;
      case 'slug-generator':
        return <SlugGenerator />;
      case 'cron-generator':
        return <CronGenerator />;
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
