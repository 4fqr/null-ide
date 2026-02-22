import React from 'react';
import { useStore } from '../../store/store';
import ToolsGrid from '../galaxymind/ToolsGrid';

import APITester from '../galaxymind/APITester';
import PortScanner from '../galaxymind/PortScanner';
import SubdomainFinder from '../galaxymind/SubdomainFinder';
import DNSAnalyzer from '../galaxymind/DNSAnalyzer';
import WHOISLookup from '../galaxymind/WHOISLookup';

import HeaderAnalyzer from '../galaxymind/HeaderAnalyzer';
import SQLInjectionTester from '../galaxymind/SQLInjectionTester';
import XSSDetector from '../galaxymind/XSSDetector';
import LFIScanner from '../galaxymind/LFIScanner';
import CSRFTester from '../galaxymind/CSRFTester';
import DirectoryFuzzer from '../galaxymind/DirectoryFuzzer';
import CommandInjectionTester from '../galaxymind/CommandInjectionTester';
import SSRFTester from '../galaxymind/SSRFTester';
import XXETester from '../galaxymind/XXETester';
import SSTIDetector from '../galaxymind/SSTIDetector';
import FileUploadTester from '../galaxymind/FileUploadTester';

import ReverseShellGenerator from '../galaxymind/ReverseShellGenerator';
import PayloadEncoder from '../galaxymind/PayloadEncoder';
import WebShellGenerator from '../galaxymind/WebShellGenerator';
import CodeObfuscator from '../galaxymind/CodeObfuscator';
import ShellcodeGenerator from '../galaxymind/ShellcodeGenerator';

import HashCracker from '../galaxymind/HashCracker';
import HashGenerator from '../galaxymind/HashGenerator';
import Base64Tool from '../galaxymind/Base64Tool';
import JWTCracker from '../galaxymind/JWTCracker';
import EncryptionTool from '../galaxymind/EncryptionTool';
import CertificateAnalyzer from '../galaxymind/CertificateAnalyzer';
import SSLScanner from '../galaxymind/SSLScanner';
import HTTPMethodTester from '../galaxymind/HTTPMethodTester';
import OpenRedirectScanner from '../galaxymind/OpenRedirectScanner';
import ClickjackingTester from '../galaxymind/ClickjackingTester';
import ServerFingerprinter from '../galaxymind/ServerFingerprinter';
import CookieAnalyzer from '../galaxymind/CookieAnalyzer';
import RobotsTxtAnalyzer from '../galaxymind/RobotsTxtAnalyzer';
import IDORTester from '../galaxymind/IDORTester';
import HostHeaderInjection from '../galaxymind/HostHeaderInjection';
import GraphQLScanner from '../galaxymind/GraphQLScanner';
import NoSQLInjectionTester from '../galaxymind/NoSQLInjectionTester';
import PathTraversalScanner from '../galaxymind/PathTraversalScanner';
import LDAPInjectionTester from '../galaxymind/LDAPInjectionTester';
import XPathInjectionTester from '../galaxymind/XPathInjectionTester';
import JWTAlgorithmConfusion from '../galaxymind/JWTAlgorithmConfusion';
import RaceConditionTester from '../galaxymind/RaceConditionTester';
import CachePoisoningScanner from '../galaxymind/CachePoisoningScanner';
import DOMXSSScanner from '../galaxymind/DOMXSSScanner';
import DNSRebindingTester from '../galaxymind/DNSRebindingTester';
import APIRateLimitTester from '../galaxymind/APIRateLimitTester';

import PacketAnalyzer from '../galaxymind/PacketAnalyzer';
import HTTPSmuggling from '../galaxymind/HTTPSmuggling';
import CORSTester from '../galaxymind/CORSTester';

import JWTDecoder from '../galaxymind/JWTDecoder';
import PasswordGenerator from '../galaxymind/PasswordGenerator';
import OAuthTester from '../galaxymind/OAuthTester';

import JSONFormatter from '../galaxymind/JSONFormatter';
import RegexTester from '../galaxymind/RegexTester';
import UUIDGenerator from '../galaxymind/UUIDGenerator';
import TimestampConverter from '../galaxymind/TimestampConverter';
import ColorConverter from '../galaxymind/ColorConverter';
import MarkdownPreview from '../galaxymind/MarkdownPreview';
import DiffViewer from '../galaxymind/DiffViewer';

import SSRFAdvanced from '../galaxymind/SSRFAdvanced';
import XXEAdvanced from '../galaxymind/XXEAdvanced';
import CRLFInjection from '../galaxymind/CRLFInjection';
import TemplateInjection from '../galaxymind/TemplateInjection';
import DeserializationScanner from '../galaxymind/DeserializationScanner';
import MassAssignment from '../galaxymind/MassAssignment';
import PrototypePollution from '../galaxymind/PrototypePollution';
import WebSocketSecurity from '../galaxymind/WebSocketSecurity';
import HTTP2Scanner from '../galaxymind/HTTP2Scanner';
import BlindXSSHunter from '../galaxymind/BlindXSSHunter';
import CSPBypass from '../galaxymind/CSPBypass';
import SRIAnalyzer from '../galaxymind/SRIAnalyzer';
import HSTSChecker from '../galaxymind/HSTSChecker';
import GraphQLAdvanced from '../galaxymind/GraphQLAdvanced';

import AuthBypass from '../galaxymind/AuthBypass';
import AuthzBypass from '../galaxymind/AuthzBypass';
import SessionMgmt from '../galaxymind/SessionMgmt';
import OAuth2Scanner from '../galaxymind/OAuth2Scanner';
import SAMLScanner from '../galaxymind/SAMLScanner';
import JWTWeakSecret from '../galaxymind/JWTWeakSecret';
import APIKeyScanner from '../galaxymind/APIKeyScanner';
import PasswordPolicyChecker from '../galaxymind/PasswordPolicyChecker';

import CloudMetadata from '../galaxymind/CloudMetadata';
import S3Scanner from '../galaxymind/S3Scanner';
import DockerScanner from '../galaxymind/DockerScanner';
import K8sScanner from '../galaxymind/K8sScanner';
import RedisScanner from '../galaxymind/RedisScanner';
import MongoScanner from '../galaxymind/MongoScanner';
import ElasticScanner from '../galaxymind/ElasticScanner';
import MemcachedScanner from '../galaxymind/MemcachedScanner';
import EtcdScanner from '../galaxymind/EtcdScanner';
import ConsulScanner from '../galaxymind/ConsulScanner';

import CertTransparency from '../galaxymind/CertTransparency';
import TLSScanner from '../galaxymind/TLSScanner';
import VNCScanner from '../galaxymind/VNCScanner';
import RDPScanner from '../galaxymind/RDPScanner';
import FTPScanner from '../galaxymind/FTPScanner';
import SMBScanner from '../galaxymind/SMBScanner';
import SNMPScanner from '../galaxymind/SNMPScanner';
import LDAPScanner from '../galaxymind/LDAPScanner';
import BGPScanner from '../galaxymind/BGPScanner';
import ARPScanner from '../galaxymind/ARPScanner';

import PaddingOracle from '../galaxymind/PaddingOracle';
import HashExtension from '../galaxymind/HashExtension';
import RSAAnalyzer from '../galaxymind/RSAAnalyzer';
import CipherID from '../galaxymind/CipherID';
import StegoDetector from '../galaxymind/StegoDetector';
import RandomAnalyzer from '../galaxymind/RandomAnalyzer';
import CryptoAddress from '../galaxymind/CryptoAddress';

import DNSRebind from '../galaxymind/DNSRebind';
import RaceCondition from '../galaxymind/RaceCondition';
import SSInjection from '../galaxymind/SSInjection';

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
      case 'reverse-dns':
        return <DNSAnalyzer />;

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
      case 'command-injection':
        return <CommandInjectionTester />;
      case 'ssrf-tester':
        return <SSRFTester />;
      case 'xxe-tester':
        return <XXETester />;
      case 'ssti-detector':
        return <SSTIDetector />;
      case 'file-upload-tester':
        return <FileUploadTester />;

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

      case 'hash-cracker':
        return <HashCracker />;
      case 'hash-generator':
        return <HashGenerator />;
      case 'base64-tool':
        return <Base64Tool />;
      case 'jwt-cracker':
        return <JWTCracker />;
      case 'encryption-tool':
        return <EncryptionTool />;
      case 'certificate-analyzer':
        return <CertificateAnalyzer />;

      case 'packet-analyzer':
        return <PacketAnalyzer />;
      case 'request-smuggling':
        return <HTTPSmuggling />;
      case 'cors-tester':
        return <CORSTester />;

      case 'jwt-decoder':
        return <JWTDecoder />;
      case 'password-generator':
        return <PasswordGenerator />;
      case 'oauth-tester':
        return <OAuthTester />;

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

      case 'ssl-scanner':
        return <SSLScanner />;
      case 'http-method-tester':
        return <HTTPMethodTester />;
      case 'open-redirect-scanner':
        return <OpenRedirectScanner />;
      case 'clickjacking-tester':
        return <ClickjackingTester />;
      case 'server-fingerprinter':
        return <ServerFingerprinter />;
      case 'cookie-analyzer':
        return <CookieAnalyzer />;
      case 'robots-txt-analyzer':
        return <RobotsTxtAnalyzer />;
      case 'idor-tester':
        return <IDORTester />;
      case 'host-header-injection':
        return <HostHeaderInjection />;
      case 'graphql-scanner':
        return <GraphQLScanner />;
      case 'nosql-injection':
        return <NoSQLInjectionTester />;
      case 'path-traversal':
        return <PathTraversalScanner />;
      case 'ldap-injection':
        return <LDAPInjectionTester />;
      case 'xpath-injection':
        return <XPathInjectionTester />;
      case 'jwt-algorithm-confusion':
        return <JWTAlgorithmConfusion />;
      case 'race-condition-tester':
        return <RaceConditionTester />;
      case 'cache-poisoning-scanner':
        return <CachePoisoningScanner />;
      case 'dom-xss-scanner':
        return <DOMXSSScanner />;
      case 'dns-rebinding-tester':
        return <DNSRebindingTester />;
      case 'api-rate-limit-tester':
        return <APIRateLimitTester />;

      case 'ssrf-advanced':
        return <SSRFAdvanced />;
      case 'xxe-advanced':
        return <XXEAdvanced />;
      case 'crlf-injection':
        return <CRLFInjection />;
      case 'template-injection':
        return <TemplateInjection />;
      case 'deserialization-scanner':
        return <DeserializationScanner />;
      case 'mass-assignment':
        return <MassAssignment />;
      case 'prototype-pollution':
        return <PrototypePollution />;
      case 'websocket-security':
        return <WebSocketSecurity />;
      case 'http2-scanner':
        return <HTTP2Scanner />;
      case 'blind-xss-hunter':
        return <BlindXSSHunter />;
      case 'csp-bypass':
        return <CSPBypass />;
      case 'sri-analyzer':
        return <SRIAnalyzer />;
      case 'hsts-checker':
        return <HSTSChecker />;
      case 'graphql-advanced':
        return <GraphQLAdvanced />;

      case 'auth-bypass':
        return <AuthBypass />;
      case 'authz-bypass':
        return <AuthzBypass />;
      case 'session-mgmt':
        return <SessionMgmt />;
      case 'oauth2-scanner':
        return <OAuth2Scanner />;
      case 'saml-scanner':
        return <SAMLScanner />;
      case 'jwt-weak-secret':
        return <JWTWeakSecret />;
      case 'api-key-scanner':
        return <APIKeyScanner />;
      case 'password-policy-checker':
        return <PasswordPolicyChecker />;

      case 'cloud-metadata':
        return <CloudMetadata />;
      case 's3-scanner':
        return <S3Scanner />;
      case 'docker-scanner':
        return <DockerScanner />;
      case 'k8s-scanner':
        return <K8sScanner />;
      case 'redis-scanner':
        return <RedisScanner />;
      case 'mongo-scanner':
        return <MongoScanner />;
      case 'elastic-scanner':
        return <ElasticScanner />;
      case 'memcached-scanner':
        return <MemcachedScanner />;
      case 'etcd-scanner':
        return <EtcdScanner />;
      case 'consul-scanner':
        return <ConsulScanner />;

      case 'cert-transparency':
        return <CertTransparency />;
      case 'tls-scanner':
        return <TLSScanner />;
      case 'vnc-scanner':
        return <VNCScanner />;
      case 'rdp-scanner':
        return <RDPScanner />;
      case 'ftp-scanner':
        return <FTPScanner />;
      case 'smb-scanner':
        return <SMBScanner />;
      case 'snmp-scanner':
        return <SNMPScanner />;
      case 'ldap-scanner':
        return <LDAPScanner />;
      case 'bgp-scanner':
        return <BGPScanner />;
      case 'arp-scanner':
        return <ARPScanner />;

      case 'padding-oracle':
        return <PaddingOracle />;
      case 'hash-extension':
        return <HashExtension />;
      case 'rsa-analyzer':
        return <RSAAnalyzer />;
      case 'cipher-id':
        return <CipherID />;
      case 'stego-detector':
        return <StegoDetector />;
      case 'random-analyzer':
        return <RandomAnalyzer />;
      case 'crypto-address':
        return <CryptoAddress />;

      case 'dns-rebind':
        return <DNSRebind />;
      case 'race-condition':
        return <RaceCondition />;
      case 'ssi-injection':
        return <SSInjection />;

      default:
        return <ToolsGrid />;
    }
  };

  return <div className={styles.galaxyMind}>{renderTool()}</div>;
};

export default GalaxyMind;
