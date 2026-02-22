import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { LockIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

interface RandomnessAnalysis {
  entropy: number;
  chiSquare: number;
  serialCorrelation: number;
  monobitTest: boolean;
  runsTest: boolean;
  longestRunTest: boolean;
  verdict: string;
  details: string[];
}

export const RandomAnalyzer: React.FC = () => {
  const { addToolResult } = useStore();
  const [randomData, setRandomData] = useState('');
  const [sampleSize, setSampleSize] = useState('1000');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RandomnessAnalysis | null>(null);

  const analyzeRandomness = async () => {
    if (!randomData) return;

    setLoading(true);
    setResult(null);

    try {
      const details: string[] = [];
      const data = randomData.replace(/\s+/g, '');
      const bytes: number[] = [];

      
      if (/^[0-9a-fA-F]+$/.test(data)) {
        for (let i = 0; i < data.length; i += 2) {
          bytes.push(parseInt(data.substr(i, 2), 16));
        }
        details.push('Input format: Hexadecimal');
      } else {
        for (let i = 0; i < data.length; i++) {
          bytes.push(data.charCodeAt(i));
        }
        details.push('Input format: ASCII/Binary');
      }

      details.push(`Sample size: ${bytes.length} bytes`);

      
      const freq: { [key: number]: number } = {};
      for (const byte of bytes) {
        freq[byte] = (freq[byte] || 0) + 1;
      }

      let entropy = 0;
      for (const count of Object.values(freq)) {
        const p = count / bytes.length;
        entropy -= p * Math.log2(p);
      }

      details.push(`\nEntropy: ${entropy.toFixed(4)} bits/byte`);
      details.push(`Maximum entropy: 8.0 bits/byte`);
      details.push(
        `Entropy quality: ${entropy > 7.5 ? 'GOOD' : entropy > 6.5 ? 'MODERATE' : 'POOR'}`
      );

      
      const expectedFreq = bytes.length / 256;
      let chiSquare = 0;
      for (let i = 0; i < 256; i++) {
        const observed = freq[i] || 0;
        chiSquare += Math.pow(observed - expectedFreq, 2) / expectedFreq;
      }

      details.push(`\nChi-square: ${chiSquare.toFixed(2)}`);
      details.push(`Expected range: 200-300 (for good randomness)`);
      const chiPass = chiSquare > 200 && chiSquare < 300;
      details.push(`Chi-square test: ${chiPass ? 'PASS' : 'FAIL'}`);

      
      let sum = 0;
      let sumSq = 0;
      let serial = 0;
      for (let i = 0; i < bytes.length - 1; i++) {
        sum += bytes[i];
        sumSq += bytes[i] * bytes[i];
        serial += bytes[i] * bytes[i + 1];
      }

      const mean = sum / bytes.length;
      const serialCorr =
        (serial / (bytes.length - 1) - mean * mean) / (sumSq / bytes.length - mean * mean);

      details.push(`\nSerial correlation: ${serialCorr.toFixed(4)}`);
      details.push(`Expected: close to 0.0 for random data`);
      const corrPass = Math.abs(serialCorr) < 0.1;
      details.push(`Serial correlation test: ${corrPass ? 'PASS' : 'FAIL'}`);

      
      const bits: number[] = [];
      for (const byte of bytes) {
        for (let i = 7; i >= 0; i--) {
          bits.push((byte >> i) & 1);
        }
      }

      const ones = bits.filter((b) => b === 1).length;
      const zeros = bits.length - ones;
      const monobitRatio = ones / bits.length;

      details.push(`\n--- NIST Tests ---`);
      details.push(`Monobit test: ${ones} ones, ${zeros} zeros`);
      details.push(`Ratio: ${monobitRatio.toFixed(4)} (expected: ~0.5)`);
      const monobitPass = Math.abs(monobitRatio - 0.5) < 0.05;
      details.push(`Result: ${monobitPass ? 'PASS' : 'FAIL'}`);

      
      let runs = 1;
      for (let i = 1; i < bits.length; i++) {
        if (bits[i] !== bits[i - 1]) runs++;
      }

      const expectedRuns = bits.length / 2;
      const runsRatio = runs / expectedRuns;

      details.push(`\nRuns test: ${runs} runs detected`);
      details.push(`Expected: ~${expectedRuns.toFixed(0)} runs`);
      details.push(`Ratio: ${runsRatio.toFixed(4)}`);
      const runsPass = runsRatio > 0.8 && runsRatio < 1.2;
      details.push(`Result: ${runsPass ? 'PASS' : 'FAIL'}`);

      
      let currentRun = 1;
      let longestRun = 1;
      for (let i = 1; i < bits.length; i++) {
        if (bits[i] === bits[i - 1]) {
          currentRun++;
          longestRun = Math.max(longestRun, currentRun);
        } else {
          currentRun = 1;
        }
      }

      const expectedLongest = Math.log2(bits.length);
      details.push(`\nLongest run: ${longestRun} bits`);
      details.push(`Expected: ~${expectedLongest.toFixed(0)} for random data`);
      const longestPass = longestRun < expectedLongest * 2;
      details.push(`Result: ${longestPass ? 'PASS' : 'FAIL'}`);

      
      const testsPass = [chiPass, corrPass, monobitPass, runsPass, longestPass];
      const passCount = testsPass.filter((p) => p).length;

      let verdict = 'POOR';
      if (passCount === 5 && entropy > 7.5) verdict = 'EXCELLENT';
      else if (passCount >= 4 && entropy > 7.0) verdict = 'GOOD';
      else if (passCount >= 3) verdict = 'MODERATE';

      details.push(`\n=== OVERALL VERDICT ===`);
      details.push(`Tests passed: ${passCount}/5`);
      details.push(`Randomness quality: ${verdict}`);

      if (verdict === 'POOR' || verdict === 'MODERATE') {
        details.push(`\n⚠️  WARNING: Weak random number generator detected!`);
        details.push(`This PRNG may be predictable or have patterns`);
        details.push(`Recommendation: Use cryptographically secure PRNG`);
      }

      const analysis: RandomnessAnalysis = {
        entropy: Math.round(entropy * 1000) / 1000,
        chiSquare: Math.round(chiSquare * 100) / 100,
        serialCorrelation: Math.round(serialCorr * 10000) / 10000,
        monobitTest: monobitPass,
        runsTest: runsPass,
        longestRunTest: longestPass,
        verdict,
        details,
      };

      setResult(analysis);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Random Analyzer',
        input: { randomData, sampleSize },
        output: analysis,
        success: true,
        timestamp: Date.now(),
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        entropy: 0,
        chiSquare: 0,
        serialCorrelation: 0,
        monobitTest: false,
        runsTest: false,
        longestRunTest: false,
        verdict: 'Error',
        details: [`Error: ${errorMsg}`],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="PRNG Quality Analyzer"
      icon={<LockIcon />}
      description="Analyze randomness quality of data using statistical tests"
    >
      <div className={styles.inputGroup}>
        <label className={styles.label}>Random Data (Hex or Binary):</label>
        <textarea
          value={randomData}
          onChange={(e) => setRandomData(e.target.value)}
          placeholder="Enter random data to analyze (hex format recommended)..."
          className={styles.textarea}
          rows={8}
        />
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Sample Size (bytes):</label>
        <input
          type="number"
          value={sampleSize}
          onChange={(e) => setSampleSize(e.target.value)}
          className={styles.input}
        />
      </div>

      <button
        onClick={analyzeRandomness}
        disabled={loading || !randomData}
        className={styles.primaryBtn}
      >
        {loading ? (
          <>
            <LoadingIcon /> Analyzing...
          </>
        ) : (
          'Analyze Randomness'
        )}
      </button>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Randomness Analysis Results</span>
          </div>

          <div className={styles.resultItem}>
            <strong>Overall Verdict:</strong>{' '}
            <span
              style={{
                color:
                  result.verdict === 'EXCELLENT'
                    ? '#44ff44'
                    : result.verdict === 'GOOD'
                      ? '#88ff88'
                      : result.verdict === 'MODERATE'
                        ? '#ffaa00'
                        : '#ff4444',
                fontWeight: 'bold',
                fontSize: '1.2em',
              }}
            >
              {result.verdict}
            </span>
          </div>

          <div className={styles.resultItem}>
            <strong>Statistical Tests:</strong>
            <div>Entropy: {result.entropy} bits/byte</div>
            <div>Chi-square: {result.chiSquare}</div>
            <div>Serial Correlation: {result.serialCorrelation}</div>
          </div>

          <div className={styles.resultItem}>
            <strong>NIST Tests:</strong>
            <div>Monobit Test: {result.monobitTest ? '✓ PASS' : '✗ FAIL'}</div>
            <div>Runs Test: {result.runsTest ? '✓ PASS' : '✗ FAIL'}</div>
            <div>Longest Run Test: {result.longestRunTest ? '✓ PASS' : '✗ FAIL'}</div>
          </div>

          <div className={styles.resultItem}>
            <strong>Detailed Analysis:</strong>
            <pre className={styles.codeBlock}>{result.details.join('\n')}</pre>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default RandomAnalyzer;
