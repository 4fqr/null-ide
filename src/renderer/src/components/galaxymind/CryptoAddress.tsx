import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { LockIcon, LoadingIcon } from '../common/Icons';

interface AddressAnalysis {
  valid: boolean;
  currency: string;
  format: string;
  checksumValid?: boolean;
  metadata: { [key: string]: string };
  warnings: string[];
}

export default function CryptoAddress() {
  const { addToolResult } = useStore();
  const [address, setAddress] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AddressAnalysis | null>(null);

  const analyzeAddress = async () => {
    if (!address) return;

    setLoading(true);
    setResult(null);

    try {
      let valid = false;
      let currency = 'Unknown';
      let format = 'Unknown';
      let checksumValid: boolean | undefined = undefined;
      const metadata: { [key: string]: string } = {};
      const warnings: string[] = [];

      const cleanAddr = address.trim();

      if (/^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(cleanAddr)) {
        currency = 'Bitcoin';
        format = 'P2PKH (Legacy)';
        valid = true;
        metadata['Network'] = cleanAddr.startsWith('1') ? 'Mainnet' : 'Testnet';
        metadata['Type'] = 'Pay-to-Public-Key-Hash';
      } else if (/^3[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(cleanAddr)) {
        currency = 'Bitcoin';
        format = 'P2SH (Script Hash)';
        valid = true;
        metadata['Network'] = 'Mainnet';
        metadata['Type'] = 'Pay-to-Script-Hash';
      } else if (/^(bc1|tb1)[a-z0-9]{39,59}$/.test(cleanAddr.toLowerCase())) {
        currency = 'Bitcoin';
        format = 'Bech32 (SegWit)';
        valid = true;
        metadata['Network'] = cleanAddr.startsWith('bc1') ? 'Mainnet' : 'Testnet';
        metadata['Type'] = 'Native SegWit';
        metadata['Encoding'] = 'Bech32';
      } else if (/^0x[a-fA-F0-9]{40}$/.test(cleanAddr)) {
        currency = 'Ethereum';
        format = 'EIP-55 (Checksummed)';
        valid = true;

        const lowerAddr = cleanAddr.toLowerCase();
        const upperAddr = cleanAddr.toUpperCase();
        const mixedCase = cleanAddr !== lowerAddr && cleanAddr !== upperAddr;

        if (mixedCase) {
          checksumValid = true;
          metadata['Checksum'] = 'Present (EIP-55)';
        } else {
          checksumValid = false;
          warnings.push('Address not checksummed - susceptible to typos');
        }

        metadata['Type'] = 'EOA or Contract';
        metadata['Length'] = '20 bytes (160 bits)';
      } else if (/^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$/.test(cleanAddr)) {
        currency = 'Litecoin';
        format = cleanAddr.startsWith('L') ? 'P2PKH' : 'P2SH';
        valid = true;
        metadata['Network'] = 'Mainnet';
      } else if (/^r[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(cleanAddr)) {
        currency = 'Ripple (XRP)';
        format = 'Base58';
        valid = true;
        metadata['Type'] = 'Classic Address';
      } else if (/^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/.test(cleanAddr)) {
        currency = 'Monero';
        format = 'CryptoNote';
        valid = true;
        metadata['Type'] = 'Standard Address';
        metadata['Length'] = '95 characters';
      } else if (/^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$/.test(cleanAddr)) {
        currency = 'Dogecoin';
        format = 'P2PKH';
        valid = true;
        metadata['Network'] = 'Mainnet';
      } else if (/^addr1[a-z0-9]{58}$/.test(cleanAddr.toLowerCase())) {
        currency = 'Cardano (ADA)';
        format = 'Shelley Era';
        valid = true;
        metadata['Era'] = 'Shelley';
        metadata['Encoding'] = 'Bech32';
      } else if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(cleanAddr)) {
        currency = 'Solana';
        format = 'Base58';
        valid = true;
        metadata['Length'] = '32-44 characters';
      } else {
        warnings.push('Address format not recognized');
        warnings.push('May be a newer cryptocurrency or invalid');
      }

      if (valid) {
        if (/^(.)\1+$/.test(cleanAddr.replace(/[^0-9a-zA-Z]/g, ''))) {
          warnings.push('Address contains repeating pattern - verify carefully!');
        }

        if (currency === 'Bitcoin') {
          warnings.push('Best practice: Use new address for each transaction');
        }

        if (currency === 'Bitcoin' || currency === 'Ethereum') {
          warnings.push('Note: Transactions are publicly visible on blockchain');
        }
      }

      const analysis: AddressAnalysis = {
        valid,
        currency,
        format,
        checksumValid,
        metadata,
        warnings,
      };

      setResult(analysis);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Crypto Address',
        input: { address },
        output: analysis,
        success: true,
        timestamp: Date.now(),
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        valid: false,
        currency: 'Error',
        format: 'Error',
        metadata: {},
        warnings: [`Error: ${errorMsg}`],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Cryptocurrency Address Tools"
      icon={<LockIcon />}
      description="Validate and analyze cryptocurrency addresses"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Cryptocurrency Address</label>
          <input
            type="text"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="Enter BTC, ETH, or other crypto address..."
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={analyzeAddress}
            disabled={loading || !address}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Analyzing...
              </>
            ) : (
              'Analyze Address'
            )}
          </button>
        </div>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Address Analysis</span>
          </div>

          <div className={styles.resultItem}>
            <strong>Valid:</strong>{' '}
            <span className={result.valid ? styles.textSuccess : styles.textError}>
              {result.valid ? 'YES' : 'NO'}
            </span>
          </div>

          {result.valid && (
            <>
              <div className={styles.resultItem}>
                <strong>Currency:</strong> {result.currency}
              </div>

              <div className={styles.resultItem}>
                <strong>Format:</strong> {result.format}
              </div>

              {result.checksumValid !== undefined && (
                <div className={styles.resultItem}>
                  <strong>Checksum:</strong>{' '}
                  <span className={result.checksumValid ? styles.textSuccess : styles.textError}>
                    {result.checksumValid ? 'Valid' : 'Not Checksummed'}
                  </span>
                </div>
              )}

              {Object.keys(result.metadata).length > 0 && (
                <div className={styles.resultItem}>
                  <strong>Metadata:</strong>
                  <div style={{ marginLeft: '20px' }}>
                    {Object.entries(result.metadata).map(([key, value]) => (
                      <div key={key}>
                        {key}: {value}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </>
          )}

          {result.warnings.length > 0 && (
            <div className={styles.resultItem}>
              <strong>Warnings & Notes:</strong>
              <ul style={{ margin: '8px 0 0 20px', color: 'var(--color-text-secondary)' }}>
                {result.warnings.map((warning, idx) => (
                  <li key={idx}>{warning}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}
    </ToolWrapper>
  );
}
