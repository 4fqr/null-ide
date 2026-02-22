import { useState } from 'react';
import { AlarmIcon, CopyIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface CronPart {
  minute: string;
  hour: string;
  dayOfMonth: string;
  month: string;
  dayOfWeek: string;
}

export default function CronGenerator() {
  const [cronParts, setCronParts] = useState<CronPart>({
    minute: '*',
    hour: '*',
    dayOfMonth: '*',
    month: '*',
    dayOfWeek: '*',
  });
  const [customExpression, setCustomExpression] = useState('');
  const [useCustom, setUseCustom] = useState(false);

  const presets = [
    { name: 'Every minute', value: '* * * * *' },
    { name: 'Every hour', value: '0 * * * *' },
    { name: 'Every day at midnight', value: '0 0 * * *' },
    { name: 'Every day at noon', value: '0 12 * * *' },
    { name: 'Every Monday at 9am', value: '0 9 * * 1' },
    { name: 'Every weekday at 9am', value: '0 9 * * 1-5' },
    { name: 'First day of month', value: '0 0 1 * *' },
    { name: 'Every 5 minutes', value: '*/5 * * * *' },
    { name: 'Every 15 minutes', value: '*/15 * * * *' },
    { name: 'Every 30 minutes', value: '*/30 * * * *' },
  ];

  const cronExpression = useCustom
    ? customExpression
    : `${cronParts.minute} ${cronParts.hour} ${cronParts.dayOfMonth} ${cronParts.month} ${cronParts.dayOfWeek}`;

  const updatePart = (part: keyof CronPart, value: string) => {
    setCronParts((prev) => ({ ...prev, [part]: value }));
  };

  const applyPreset = (preset: string) => {
    const parts = preset.split(' ');
    setCronParts({
      minute: parts[0],
      hour: parts[1],
      dayOfMonth: parts[2],
      month: parts[3],
      dayOfWeek: parts[4],
    });
    setUseCustom(false);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(cronExpression);
  };

  const getDescription = (): string => {
    if (useCustom) return 'Custom cron expression';

    const { minute, hour, dayOfMonth, month, dayOfWeek } = cronParts;

    if (
      minute === '*' &&
      hour === '*' &&
      dayOfMonth === '*' &&
      month === '*' &&
      dayOfWeek === '*'
    ) {
      return 'Runs every minute';
    }
    if (minute.startsWith('*/')) {
      return `Runs every ${minute.slice(2)} minutes`;
    }
    if (hour === '*' && minute !== '*') {
      return `Runs at minute ${minute} of every hour`;
    }
    if (dayOfMonth === '*' && hour !== '*' && minute !== '*') {
      return `Runs daily at ${hour}:${minute.padStart(2, '0')}`;
    }

    return 'Custom schedule';
  };

  return (
    <ToolWrapper
      title="Cron Expression Generator"
      icon={<AlarmIcon />}
      description="Generate and validate cron expressions"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Quick Presets</label>
          <div className={styles.tagList}>
            {presets.map((preset, index) => (
              <button
                key={index}
                className={styles.smallBtn}
                onClick={() => applyPreset(preset.value)}
              >
                {preset.name}
              </button>
            ))}
          </div>
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.checkboxGroup}>
            <input
              type="checkbox"
              checked={useCustom}
              onChange={(e) => setUseCustom(e.target.checked)}
              className={styles.checkbox}
            />
            Use custom expression
          </label>
        </div>

        {useCustom ? (
          <div className={styles.inputGroup}>
            <label className={styles.label}>Custom Cron Expression</label>
            <input
              type="text"
              className={styles.input}
              value={customExpression}
              onChange={(e) => setCustomExpression(e.target.value)}
              placeholder="* * * * *"
            />
          </div>
        ) : (
          <div className={styles.grid2}>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Minute (0-59)</label>
              <input
                type="text"
                className={styles.input}
                value={cronParts.minute}
                onChange={(e) => updatePart('minute', e.target.value)}
                placeholder="*"
              />
            </div>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Hour (0-23)</label>
              <input
                type="text"
                className={styles.input}
                value={cronParts.hour}
                onChange={(e) => updatePart('hour', e.target.value)}
                placeholder="*"
              />
            </div>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Day of Month (1-31)</label>
              <input
                type="text"
                className={styles.input}
                value={cronParts.dayOfMonth}
                onChange={(e) => updatePart('dayOfMonth', e.target.value)}
                placeholder="*"
              />
            </div>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Month (1-12)</label>
              <input
                type="text"
                className={styles.input}
                value={cronParts.month}
                onChange={(e) => updatePart('month', e.target.value)}
                placeholder="*"
              />
            </div>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Day of Week (0-6)</label>
              <input
                type="text"
                className={styles.input}
                value={cronParts.dayOfWeek}
                onChange={(e) => updatePart('dayOfWeek', e.target.value)}
                placeholder="*"
              />
            </div>
          </div>
        )}
      </div>

      <div className={styles.resultBox}>
        <div className={styles.resultHeader}>
          <span className={styles.resultTitle}>Cron Expression</span>
          <button onClick={copyToClipboard} className={styles.copyBtn}>
            <CopyIcon /> Copy
          </button>
        </div>
        <div className={styles.codeBlock}>{cronExpression}</div>
        <p style={{ color: 'var(--color-text-secondary)', marginTop: '8px' }}>{getDescription()}</p>

        <div className={styles.infoBox} style={{ marginTop: '16px' }}>
          <strong>Format:</strong> minute hour day month weekday
          <br />
          <strong>Special chars:</strong> * (any) / (step) , (list) - (range)
        </div>
      </div>
    </ToolWrapper>
  );
}
