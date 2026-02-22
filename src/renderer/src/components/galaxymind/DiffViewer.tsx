import { useState } from 'react';
import { DiffIcon, SearchIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface DiffLine {
  type: 'added' | 'removed' | 'unchanged';
  content: string;
  lineNumber1?: number;
  lineNumber2?: number;
}

export default function DiffViewer() {
  const [text1, setText1] = useState('');
  const [text2, setText2] = useState('');
  const [diff, setDiff] = useState<DiffLine[]>([]);

  const calculateDiff = () => {
    const lines1 = text1.split('\n');
    const lines2 = text2.split('\n');
    const result: DiffLine[] = [];

    let i = 0,
      j = 0;

    while (i < lines1.length || j < lines2.length) {
      if (i >= lines1.length) {
        result.push({ type: 'added', content: lines2[j], lineNumber2: j + 1 });
        j++;
      } else if (j >= lines2.length) {
        result.push({ type: 'removed', content: lines1[i], lineNumber1: i + 1 });
        i++;
      } else if (lines1[i] === lines2[j]) {
        result.push({
          type: 'unchanged',
          content: lines1[i],
          lineNumber1: i + 1,
          lineNumber2: j + 1,
        });
        i++;
        j++;
      } else {
        const line1InText2 = lines2.slice(j).indexOf(lines1[i]);
        const line2InText1 = lines1.slice(i).indexOf(lines2[j]);

        if (line1InText2 === -1 && line2InText1 === -1) {
          result.push({ type: 'removed', content: lines1[i], lineNumber1: i + 1 });
          result.push({ type: 'added', content: lines2[j], lineNumber2: j + 1 });
          i++;
          j++;
        } else if (line1InText2 !== -1 && (line2InText1 === -1 || line1InText2 < line2InText1)) {
          result.push({ type: 'removed', content: lines1[i], lineNumber1: i + 1 });
          i++;
        } else {
          result.push({ type: 'added', content: lines2[j], lineNumber2: j + 1 });
          j++;
        }
      }
    }

    setDiff(result);
  };

  const getStats = () => {
    const added = diff.filter((d) => d.type === 'added').length;
    const removed = diff.filter((d) => d.type === 'removed').length;
    const unchanged = diff.filter((d) => d.type === 'unchanged').length;
    return { added, removed, unchanged };
  };

  const stats = getStats();

  return (
    <ToolWrapper
      title="Diff Viewer"
      icon={<DiffIcon />}
      description="Compare two text snippets side by side"
    >
      <div className={styles.section}>
        <div className={styles.grid2}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Original Text</label>
            <textarea
              className={styles.textarea}
              value={text1}
              onChange={(e) => setText1(e.target.value)}
              placeholder="Enter original text..."
            />
          </div>

          <div className={styles.inputGroup}>
            <label className={styles.label}>Modified Text</label>
            <textarea
              className={styles.textarea}
              value={text2}
              onChange={(e) => setText2(e.target.value)}
              placeholder="Enter modified text..."
            />
          </div>
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={calculateDiff} className={styles.primaryBtn}>
            <SearchIcon /> Compare
          </button>
        </div>
      </div>

      {diff.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Diff Results</span>
            <div className={styles.tagList}>
              <span className={styles.tag} style={{ color: '#00ff88' }}>
                +{stats.added} added
              </span>
              <span className={styles.tag} style={{ color: '#ff6b8a' }}>
                -{stats.removed} removed
              </span>
              <span className={styles.tag} style={{ color: '#888' }}>
                = {stats.unchanged} unchanged
              </span>
            </div>
          </div>

          <div className={styles.codeBlock} style={{ maxHeight: '400px', overflow: 'auto' }}>
            {diff.map((line, index) => (
              <div
                key={index}
                style={{
                  padding: '2px 8px',
                  background:
                    line.type === 'added'
                      ? 'rgba(0, 255, 136, 0.1)'
                      : line.type === 'removed'
                        ? 'rgba(255, 107, 138, 0.1)'
                        : 'transparent',
                  borderLeft:
                    line.type === 'added'
                      ? '2px solid #00ff88'
                      : line.type === 'removed'
                        ? '2px solid #ff6b8a'
                        : '2px solid transparent',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '13px',
                }}
              >
                <span style={{ color: '#666', width: '30px', display: 'inline-block' }}>
                  {line.lineNumber1 || ' '}
                </span>
                <span style={{ color: '#666', width: '30px', display: 'inline-block' }}>
                  {line.lineNumber2 || ' '}
                </span>
                <span
                  style={{
                    color:
                      line.type === 'added'
                        ? '#00ff88'
                        : line.type === 'removed'
                          ? '#ff6b8a'
                          : 'inherit',
                    width: '20px',
                    display: 'inline-block',
                  }}
                >
                  {line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' '}
                </span>
                {line.content}
              </div>
            ))}
          </div>
        </div>
      )}
    </ToolWrapper>
  );
}
