import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

const LoremIpsumGenerator: React.FC = () => {
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);
  const [format, setFormat] = useState<'paragraphs' | 'words' | 'sentences'>('paragraphs');
  const [count, setCount] = useState(3);
  const [generatedText, setGeneratedText] = useState('');

  const loremWords = [
    'lorem', 'ipsum', 'dolor', 'sit', 'amet', 'consectetur', 'adipiscing', 'elit',
    'sed', 'do', 'eiusmod', 'tempor', 'incididunt', 'ut', 'labore', 'et', 'dolore',
    'magna', 'aliqua', 'enim', 'ad', 'minim', 'veniam', 'quis', 'nostrud',
    'exercitation', 'ullamco', 'laboris', 'nisi', 'aliquip', 'ex', 'ea', 'commodo',
    'consequat', 'duis', 'aute', 'irure', 'in', 'reprehenderit', 'voluptate',
    'velit', 'esse', 'cillum', 'fugiat', 'nulla', 'pariatur', 'excepteur', 'sint',
    'occaecat', 'cupidatat', 'non', 'proident', 'sunt', 'culpa', 'qui', 'officia',
    'deserunt', 'mollit', 'anim', 'id', 'est', 'laborum'
  ];

  const generateWord = () => {
    return loremWords[Math.floor(Math.random() * loremWords.length)];
  };

  const generateSentence = () => {
    const length = Math.floor(Math.random() * 10) + 5;
    const words = Array.from({ length }, () => generateWord());
    words[0] = words[0].charAt(0).toUpperCase() + words[0].slice(1);
    return words.join(' ') + '.';
  };

  const generateParagraph = () => {
    const sentenceCount = Math.floor(Math.random() * 5) + 3;
    const sentences = Array.from({ length: sentenceCount }, () => generateSentence());
    return sentences.join(' ');
  };

  const generate = () => {
    let result = '';

    switch (format) {
      case 'paragraphs': {
        const paragraphsArray = Array.from({ length: count }, () => generateParagraph());
        result = paragraphsArray.join('\n\n');
        break;
      }
      case 'sentences': {
        const sentencesArray = Array.from({ length: count }, () => generateSentence());
        result = sentencesArray.join(' ');
        break;
      }
      case 'words': {
        const wordsArray = Array.from({ length: count }, () => generateWord());
        result = wordsArray.join(' ');
        break;
      }
    }

    setGeneratedText(result);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(generatedText);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>📝</span>
          Lorem Ipsum Generator
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.controlsRow}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Format</label>
            <select 
              className={styles.select}
              value={format}
              onChange={(e) => setFormat(e.target.value as 'paragraphs' | 'words' | 'sentences')}
            >
              <option value="paragraphs">Paragraphs</option>
              <option value="sentences">Sentences</option>
              <option value="words">Words</option>
            </select>
          </div>

          <div className={styles.inputGroup}>
            <label className={styles.label}>Count</label>
            <input
              type="number"
              min="1"
              max="100"
              className={styles.input}
              value={count}
              onChange={(e) => setCount(Number(e.target.value))}
            />
          </div>

          <button onClick={generate} className={styles.button}>
            ✨ Generate
          </button>
        </div>

        {generatedText && (
          <div className={styles.resultSection}>
            <div className={styles.resultHeader}>
              <label className={styles.label}>Generated Text</label>
              <button onClick={copyToClipboard} className={styles.copyButton}>
                📋 Copy
              </button>
            </div>
            <textarea
              className={styles.textarea}
              value={generatedText}
              readOnly
              rows={15}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default LoremIpsumGenerator;
