import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { LockIcon, LoadingIcon } from '../common/Icons';

interface StegoAnalysis {
  fileType: string;
  fileSize: number;
  suspiciousIndicators: string[];
  lsbAnalysis: {
    redChannel: number;
    greenChannel: number;
    blueChannel: number;
  };
  recommendations: string[];
}

export const StegoDetector: React.FC = () => {
  const { addToolResult } = useStore();
  const [fileUrl, setFileUrl] = useState('');
  const [fileData, setFileData] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<StegoAnalysis | null>(null);

  const analyzeFile = async () => {
    if (!fileUrl && !fileData) return;

    setLoading(true);
    setResult(null);

    try {
      const suspiciousIndicators: string[] = [];
      const recommendations: string[] = [];

      let data: string;
      let fileType = 'Unknown';
      let fileSize = 0;

      if (fileUrl) {
        const response = await window.electronAPI.net.httpFetch(fileUrl, {
          method: 'GET',
        });
        data = String(response);
        fileSize = data.length;
      } else {
        data = fileData;
        fileSize = data.length;
      }

      if (data.startsWith('\x89PNG')) {
        fileType = 'PNG Image';
        suspiciousIndicators.push('PNG format detected - commonly used for LSB steganography');
      } else if (data.startsWith('\xFF\xD8\xFF')) {
        fileType = 'JPEG Image';
        suspiciousIndicators.push('JPEG format - may use DCT coefficient modification');
      } else if (data.startsWith('GIF8')) {
        fileType = 'GIF Image';
      } else if (data.startsWith('BM')) {
        fileType = 'BMP Image';
        suspiciousIndicators.push('BMP format - very common for steganography');
      } else if (data.includes('WAVE') || data.includes('RIFF')) {
        fileType = 'WAV Audio';
        suspiciousIndicators.push('Audio file - may contain hidden data in samples');
      }

      if (fileSize > 10000000) {
        suspiciousIndicators.push(
          `Large file size (${Math.round(fileSize / 1024 / 1024)}MB) - may contain hidden data`
        );
      }

      let lsbRed = 0,
        lsbGreen = 0,
        lsbBlue = 0;
      let sampleCount = 0;

      for (let i = 0; i < Math.min(data.length, 10000); i++) {
        const byte = data.charCodeAt(i);
        if (i % 3 === 0) lsbRed += byte & 1;
        else if (i % 3 === 1) lsbGreen += byte & 1;
        else lsbBlue += byte & 1;
        sampleCount++;
      }

      const samples = sampleCount / 3;
      const redPercent = Math.round((lsbRed / samples) * 100);
      const greenPercent = Math.round((lsbGreen / samples) * 100);
      const bluePercent = Math.round((lsbBlue / samples) * 100);

      if (
        Math.abs(redPercent - 50) < 5 &&
        Math.abs(greenPercent - 50) < 5 &&
        Math.abs(bluePercent - 50) < 5
      ) {
        suspiciousIndicators.push('LSB distribution very close to 50% - possible steganography!');
        recommendations.push('Run specialized steganalysis tools (StegExpose, OpenStego)');
      }

      if (data.includes('Photoshop') || data.includes('GIMP')) {
        suspiciousIndicators.push('Image edited with graphics software - metadata present');
      }

      const hiddenMarkers = ['-----BEGIN', '-----END', 'password', 'secret', 'hidden'];
      for (const marker of hiddenMarkers) {
        if (data.toLowerCase().includes(marker.toLowerCase())) {
          suspiciousIndicators.push(`Found text marker: "${marker}" in binary data`);
        }
      }

      const expectedBitFreq = sampleCount / 2;
      const totalBits = lsbRed + lsbGreen + lsbBlue;
      const chiSquare = Math.pow(totalBits - expectedBitFreq * 3, 2) / (expectedBitFreq * 3);

      if (chiSquare < 2) {
        suspiciousIndicators.push('Chi-square test shows random LSB distribution');
        recommendations.push('Possible LSB embedding detected');
      }

      if (suspiciousIndicators.length === 0) {
        recommendations.push('No obvious steganography indicators found');
        recommendations.push('Consider deeper analysis with specialized tools');
      } else {
        recommendations.push('Extract LSBs and analyze for hidden messages');
        recommendations.push('Check EXIF metadata for anomalies');
        recommendations.push('Use tools like zsteg, steghide, or binwalk');
      }

      const analysis: StegoAnalysis = {
        fileType,
        fileSize,
        suspiciousIndicators,
        lsbAnalysis: {
          redChannel: redPercent,
          greenChannel: greenPercent,
          blueChannel: bluePercent,
        },
        recommendations,
      };

      setResult(analysis);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Stego Detector',
        input: { fileUrl, fileData },
        output: analysis,
        success: true,
        timestamp: Date.now(),
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        fileType: 'Error',
        fileSize: 0,
        suspiciousIndicators: [`Error: ${errorMsg}`],
        lsbAnalysis: { redChannel: 0, greenChannel: 0, blueChannel: 0 },
        recommendations: [],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Steganography Detector"
      icon={<LockIcon />}
      description="Detect hidden data in images and files using steganography analysis"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>File URL:</label>
          <input
            type="text"
            value={fileUrl}
            onChange={(e) => setFileUrl(e.target.value)}
            placeholder="https://example.com/image.png"
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Or paste file data (Base64/Hex):</label>
          <textarea
            value={fileData}
            onChange={(e) => setFileData(e.target.value)}
            placeholder="Paste file content here..."
            className={styles.textarea}
            rows={6}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={analyzeFile}
            disabled={loading || (!fileUrl && !fileData)}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Analyzing...
              </>
            ) : (
              'Analyze for Steganography'
            )}
          </button>
        </div>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>Steganography Analysis</div>

          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <span className={styles.resultLabel}>File Type:</span>
              <span className={styles.resultValue}>{result.fileType}</span>
            </div>
          </div>

          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <span className={styles.resultLabel}>File Size:</span>
              <span className={styles.resultValue}>{Math.round(result.fileSize / 1024)} KB</span>
            </div>
          </div>

          <div className={styles.resultItem}>
            <strong>LSB Analysis:</strong>
            <div>Red Channel: {result.lsbAnalysis.redChannel}% ones</div>
            <div>Green Channel: {result.lsbAnalysis.greenChannel}% ones</div>
            <div>Blue Channel: {result.lsbAnalysis.blueChannel}% ones</div>
            <div style={{ fontSize: '0.9em', color: '#888', marginTop: '5px' }}>
              (Normal random data: ~50%, Embedded data: closer to 50%)
            </div>
          </div>

          {result.suspiciousIndicators.length > 0 && (
            <div className={styles.resultItem}>
              <strong>Suspicious Indicators:</strong>
              <ul>
                {result.suspiciousIndicators.map((indicator, idx) => (
                  <li
                    key={idx}
                    style={{
                      color: indicator.includes('⚠️') ? '#ffaa00' : 'inherit',
                    }}
                  >
                    {indicator}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className={styles.resultItem}>
            <strong>Recommendations:</strong>
            <ul>
              {result.recommendations.map((rec, idx) => (
                <li key={idx}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default StegoDetector;
