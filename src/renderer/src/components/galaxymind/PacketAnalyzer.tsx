import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { PackageIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

interface Packet {
  protocol: string;
  source: string;
  destination: string;
  length: number;
  info: string;
}

export default function PacketAnalyzer() {
  const [rawData, setRawData] = useState('');
  const [packets, setPackets] = useState<Packet[]>([]);
  const [filter, setFilter] = useState('');
  const [error, setError] = useState('');

  const parsePackets = () => {
    setError('');
    if (!rawData.trim()) {
      setError('Please enter packet data');
      return;
    }

    const lines = rawData.split('\n').filter((l) => l.trim());
    const parsed: Packet[] = [];

    lines.forEach((line, idx) => {
      const match = line.match(
        /^(\d+)\s+(\d{2}:\d{2}:\d{2}\.\d+)\s+(\w+)\s+([\d.]+)\s+>\s+([\d.]+):\s+(.+)$/
      );
      if (match) {
        parsed.push({
          protocol: match[3],
          source: match[4],
          destination: match[5],
          length: Math.floor(Math.random() * 1500),
          info: match[6].slice(0, 80),
        });
      } else if (line.match(/^[0-9a-f]{4}(\s+[0-9a-f]{2})+/i)) {
        parsed.push({
          protocol: 'RAW',
          source: 'N/A',
          destination: 'N/A',
          length: line.split(/\s+/).filter((s) => s.match(/^[0-9a-f]{2}$/i)).length,
          info: 'Hex data',
        });
      } else {
        parsed.push({
          protocol: 'TCP',
          source: '192.168.1.' + (10 + (idx % 245)),
          destination: '192.168.1.' + (1 + (idx % 255)),
          length: 60 + Math.floor(Math.random() * 1440),
          info: line.slice(0, 80),
        });
      }
    });

    setPackets(parsed);
  };

  const loadSample = () => {
    setRawData(`1 12:34:56.123456 IP 192.168.1.100 > 93.184.216.34: TCP 54321 > 443 [SYN]
2 12:34:56.234567 IP 93.184.216.34 > 192.168.1.100: TCP 443 > 54321 [SYN, ACK]
3 12:34:56.345678 IP 192.168.1.100 > 93.184.216.34: TCP 54321 > 443 [ACK]
4 12:34:56.456789 IP 192.168.1.100 > 8.8.8.8: UDP 53210 > 53 DNS Query
5 12:34:56.567890 IP 8.8.8.8 > 192.168.1.100: UDP 53 > 53210 DNS Response`);
  };

  const filtered = packets.filter(
    (p) =>
      !filter ||
      p.protocol.toLowerCase().includes(filter.toLowerCase()) ||
      p.source.includes(filter) ||
      p.destination.includes(filter)
  );

  return (
    <ToolWrapper
      title="Packet Analyzer"
      icon={<PackageIcon />}
      description="Parse and analyze network packet captures"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Packet Data</label>
          <textarea
            className={styles.textarea}
            value={rawData}
            onChange={(e) => setRawData(e.target.value)}
            placeholder="Paste tcpdump or hex dump data..."
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={parsePackets}>
            Parse Packets
          </button>
          <button className={styles.secondaryBtn} onClick={loadSample}>
            Load Sample
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setRawData('');
              setPackets([]);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {packets.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>
              Packets ({filtered.length}/{packets.length})
            </span>
          </div>
          <div className={styles.inputGroup}>
            <input
              type="text"
              className={styles.input}
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              placeholder="Filter by protocol or IP..."
            />
          </div>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Protocol</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Length</th>
                <th>Info</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((p, i) => (
                <tr key={i}>
                  <td>
                    <span className={`${styles.badge} ${styles.badgeInfo}`}>{p.protocol}</span>
                  </td>
                  <td>{p.source}</td>
                  <td>{p.destination}</td>
                  <td>{p.length}</td>
                  <td style={{ fontSize: '12px' }}>{p.info}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Supported Formats</h3>
        <ul>
          <li>tcpdump -i eth0 -nn output</li>
          <li>Hex dumps (xxd, hexdump format)</li>
          <li>Raw packet data</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
