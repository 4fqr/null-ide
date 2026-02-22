import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

interface RaceConditionTest {
  vulnerable: boolean;
  successfulRaces: number;
  totalAttempts: number;
  timingData: Array<{
    attempt: number;
    timing: number;
    result: string;
  }>;
  details: string[];
}

interface RequestResult {
  attempt: number;
  response: string;
  success: boolean;
  timing: number;
}

export const RaceCondition: React.FC = () => {
  const { addToolResult } = useStore();
  const [endpoint, setEndpoint] = useState('');
  const [threads, setThreads] = useState('10');
  const [payload, setPayload] = useState('');
  const [method, setMethod] = useState<'GET' | 'POST' | 'PUT'>('POST');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RaceConditionTest | null>(null);

  const testRaceCondition = async () => {
    if (!endpoint) return;

    setLoading(true);
    setResult(null);

    try {
      const details: string[] = [];
      const timingData: Array<{ attempt: number; timing: number; result: string }> = [];
      let successfulRaces = 0;
      const totalAttempts = parseInt(threads);

      details.push(`Testing race condition on: ${endpoint}`);
      details.push(`Method: ${method}`);
      details.push(`Concurrent threads: ${totalAttempts}`);
      details.push(`Payload: ${payload || 'None'}`);

      const requests: Promise<RequestResult>[] = [];
      const startTimes: number[] = [];

      for (let i = 0; i < totalAttempts; i++) {
        startTimes.push(Date.now());
        requests.push(
          window.electronAPI.net
            .httpFetch(endpoint, {
              method: method,
              headers: {
                'Content-Type': 'application/json',
              },
              body: payload || undefined,
            })
            .then((response) => ({
              attempt: i + 1,
              response: response.data || String(response),
              success: true,
              timing: Date.now() - startTimes[i],
            }))
            .catch((error) => ({
              attempt: i + 1,
              response: error instanceof Error ? error.message : 'Unknown error',
              success: false,
              timing: Date.now() - startTimes[i],
            }))
        );
      }

      details.push(`\nLaunching ${totalAttempts} concurrent requests...`);
      const startTime = Date.now();
      const results: RequestResult[] = await Promise.all(requests);
      const totalTime = Date.now() - startTime;

      details.push(`All requests completed in ${totalTime}ms`);
      details.push(`Average time per request: ${Math.round(totalTime / totalAttempts)}ms`);

      const responses = new Map<string, number>();
      const timings: number[] = [];

      for (const res of results) {
        timingData.push({
          attempt: res.attempt,
          timing: res.timing,
          result: res.response.substring(0, 100),
        });

        timings.push(res.timing);

        const respKey = res.response.substring(0, 200);
        responses.set(respKey, (responses.get(respKey) || 0) + 1);
      }

      details.push(`\nTiming Analysis:`);
      details.push(`Fastest: ${Math.min(...timings)}ms`);
      details.push(`Slowest: ${Math.max(...timings)}ms`);
      details.push(`Average: ${Math.round(timings.reduce((a, b) => a + b, 0) / timings.length)}ms`);

      const stdDev = Math.sqrt(
        timings.reduce((sum, t) => {
          const avg = timings.reduce((a, b) => a + b, 0) / timings.length;
          return sum + Math.pow(t - avg, 2);
        }, 0) / timings.length
      );

      details.push(`Std deviation: ${Math.round(stdDev)}ms`);

      if (stdDev > 50) {
        details.push(`High timing variance detected - possible race condition!`);
      }

      details.push(`\nResponse Analysis:`);
      details.push(`Unique responses: ${responses.size}`);

      if (responses.size > 1) {
        successfulRaces = totalAttempts - Math.max(...Array.from(responses.values()));
        details.push(`RACE CONDITION DETECTED!`);
        details.push(`Different responses received from concurrent requests`);
        details.push(`This indicates TOCTOU vulnerability`);

        let respNum = 1;
        for (const [resp, count] of responses.entries()) {
          details.push(`\nResponse ${respNum++} (${count} times):`);
          details.push(resp.substring(0, 150));
        }
      } else {
        details.push(`All requests returned same response`);
        details.push(`No obvious race condition detected`);
      }

      details.push(`\n--- Vulnerability Indicators ---`);
      const vulnerable = responses.size > 1 || stdDev > 100;

      if (vulnerable) {
        details.push(`Potential vulnerabilities:`);
        if (responses.size > 1) details.push(`- Non-atomic operations detected`);
        if (stdDev > 100) details.push(`- Inconsistent processing times`);
        details.push(`\nRecommendations:`);
        details.push(`- Implement proper locking mechanisms`);
        details.push(`- Use database transactions`);
        details.push(`- Add idempotency tokens`);
        details.push(`- Implement rate limiting`);
      } else {
        details.push(`No obvious TOCTOU vulnerabilities`);
        details.push(`Application appears to handle concurrency properly`);
      }

      const testResult: RaceConditionTest = {
        vulnerable,
        successfulRaces,
        totalAttempts,
        timingData,
        details,
      };

      setResult(testResult);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Race Condition',
        input: { endpoint, method, threads, payload },
        output: testResult,
        success: true,
        timestamp: Date.now(),
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        vulnerable: false,
        successfulRaces: 0,
        totalAttempts: 0,
        timingData: [],
        details: [`Error: ${errorMsg}`],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Race Condition Tester"
      icon={<ShieldIcon />}
      description="Test for TOCTOU race condition vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target Endpoint</label>
          <input
            type="text"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="https://api.example.com/transfer"
            className={styles.input}
          />
        </div>

        <div className={styles.grid2}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>HTTP Method</label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value as 'GET' | 'POST' | 'PUT')}
              className={styles.select}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
            </select>
          </div>

          <div className={styles.inputGroup}>
            <label className={styles.label}>Concurrent Threads</label>
            <input
              type="number"
              value={threads}
              onChange={(e) => setThreads(e.target.value)}
              min="2"
              max="100"
              className={styles.input}
            />
          </div>
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Request Payload (JSON)</label>
          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder='{"amount": 100, "account": "12345"}'
            className={styles.textarea}
            rows={4}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={testRaceCondition}
            disabled={loading || !endpoint}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test Race Condition'
            )}
          </button>
        </div>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Race Condition Test Results</span>
          </div>

          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <span className={styles.resultLabel}>Vulnerability Status:</span>
              <span className={result.vulnerable ? styles.statValueError : styles.statValueSuccess}>
                {result.vulnerable ? 'VULNERABLE' : 'Not Vulnerable'}
              </span>
            </div>
          </div>

          <div className={styles.grid3}>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Total Attempts</div>
              <div className={styles.statValue}>{result.totalAttempts}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Successful Races</div>
              <div className={styles.statValue}>{result.successfulRaces}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Success Rate</div>
              <div className={styles.statValue}>
                {result.totalAttempts > 0
                  ? Math.round((result.successfulRaces / result.totalAttempts) * 100)
                  : 0}
                %
              </div>
            </div>
          </div>

          {result.timingData.length > 0 && result.timingData.length <= 20 && (
            <div className={styles.resultItem}>
              <span className={styles.resultLabel}>Timing Data:</span>
              <pre className={styles.codeBlock}>
                {result.timingData
                  .map(
                    (t) => `Attempt ${t.attempt}: ${t.timing}ms - ${t.result.substring(0, 50)}...`
                  )
                  .join('\n')}
              </pre>
            </div>
          )}

          <div className={styles.resultItem}>
            <span className={styles.resultLabel}>Detailed Analysis:</span>
            <pre className={styles.codeBlock}>{result.details.join('\n')}</pre>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default RaceCondition;
