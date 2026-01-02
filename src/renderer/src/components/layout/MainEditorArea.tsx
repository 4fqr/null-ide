import React from 'react';
import Editor from '@monaco-editor/react';
import { useStore } from '../../store/store';
import styles from './MainEditorArea.module.css';

const MainEditorArea: React.FC = () => {
  const { tabs, activeTabId, updateTabContent, editorSettings } = useStore();
  const activeTab = tabs.find((tab) => tab.id === activeTabId);

  if (!activeTab) {
    return (
      <div className={styles.editorArea}>
        <div className={styles.empty}>
          <p>No file open</p>
          <p className="text-secondary">Open a file to start editing</p>
        </div>
      </div>
    );
  }

  const handleEditorChange = (value: string | undefined) => {
    if (value !== undefined && activeTab) {
      updateTabContent(activeTab.id, value);
    }
  };

  return (
    <div className={styles.editorArea}>
      <Editor
        height="100%"
        language={activeTab.language}
        value={activeTab.content}
        onChange={handleEditorChange}
        theme="vs-dark"
        options={{
          fontSize: editorSettings.fontSize,
          lineHeight: 24,
          padding: { top: 16, bottom: 16 },
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, 'Courier New', monospace",
          fontLigatures: true,
          fontWeight: '400',
          letterSpacing: 0.5,
          minimap: { enabled: editorSettings.minimap, scale: 1, showSlider: 'mouseover' },
          lineNumbers: 'on',
          lineNumbersMinChars: 3,
          renderWhitespace: 'selection',
          scrollBeyondLastLine: false,
          automaticLayout: true,
          tabSize: editorSettings.tabSize,
          insertSpaces: true,
          wordWrap: editorSettings.wordWrap ? 'on' : 'off',
          cursorBlinking: 'smooth',
          cursorSmoothCaretAnimation: 'on',
          cursorStyle: 'line',
          cursorWidth: 2,
          smoothScrolling: true,
          mouseWheelZoom: true,
          multiCursorModifier: 'ctrlCmd',
          bracketPairColorization: { enabled: true },
          guides: {
            bracketPairs: true,
            bracketPairsHorizontal: 'active',
            highlightActiveBracketPair: true,
            indentation: true,
            highlightActiveIndentation: true,
          },
          suggest: {
            snippetsPreventQuickSuggestions: false,
            showWords: true,
            showKeywords: true,
            showSnippets: true,
          },
          quickSuggestions: {
            other: true,
            comments: false,
            strings: false,
          },
          parameterHints: { enabled: true, cycle: true },
          formatOnPaste: true,
          formatOnType: true,
          autoClosingBrackets: 'always',
          autoClosingQuotes: 'always',
          autoIndent: 'full',
          folding: true,
          foldingStrategy: 'indentation',
          foldingHighlight: true,
          showFoldingControls: 'mouseover',
          matchBrackets: 'always',
          highlightActiveIndentGuide: true,
          renderLineHighlight: 'all',
          renderControlCharacters: false,
          rulers: [],
          scrollbar: {
            vertical: 'visible',
            horizontal: 'visible',
            useShadows: true,
            verticalHasArrows: false,
            horizontalHasArrows: false,
            verticalScrollbarSize: 14,
            horizontalScrollbarSize: 14,
          },
          overviewRulerBorder: false,
          occurrencesHighlight: true,
          selectionHighlight: true,
          codeLens: true,
          links: true,
          colorDecorators: true,
          comments: {
            insertSpace: true,
            ignoreEmptyLines: true,
          },
        }}
      />
    </div>
  );
};

export default MainEditorArea;
