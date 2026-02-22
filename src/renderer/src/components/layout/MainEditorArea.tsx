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
          lineHeight: 1.6,
          padding: { top: 20, bottom: 20 },
          fontFamily:
            "'JetBrains Mono', 'Fira Code', 'Cascadia Code', 'SF Mono', Consolas, monospace",
          fontLigatures: true,
          fontWeight: '400',
          letterSpacing: 0.3,
          minimap: {
            enabled: editorSettings.minimap,
            scale: 1,
            showSlider: 'mouseover',
            renderCharacters: false,
            maxColumn: 80,
          },
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
          bracketPairColorization: { enabled: true, independentColorPoolPerBracketType: true },
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
            preview: true,
            previewMode: 'subwordSmart',
          },
          quickSuggestions: {
            other: true,
            comments: false,
            strings: true,
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
          renderLineHighlight: 'all',
          renderControlCharacters: false,
          rulers: [],
          scrollbar: {
            vertical: 'visible',
            horizontal: 'visible',
            useShadows: false,
            verticalHasArrows: false,
            horizontalHasArrows: false,
            verticalScrollbarSize: 10,
            horizontalScrollbarSize: 10,
            alwaysConsumeMouseWheel: false,
          },
          overviewRulerBorder: false,
          occurrencesHighlight: 'singleFile',
          selectionHighlight: true,
          codeLens: true,
          links: true,
          colorDecorators: true,
          comments: {
            insertSpace: true,
            ignoreEmptyLines: true,
          },
          inlayHints: { enabled: 'on' },
          stickyScroll: { enabled: true },
        }}
      />
    </div>
  );
};

export default MainEditorArea;
