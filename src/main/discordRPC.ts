import { Client } from 'discord-rpc';
import type { DiscordActivity } from '../types/api';

const clientId = '1459478156120428606';

let rpc: Client | null = null;
let connected = false;
let retryCount = 0;
const MAX_RETRIES = 3;
const BASE_RETRY_DELAY = 5000;

export function initDiscordRPC() {
  if (rpc) {
    console.log('Discord RPC already initialized');
    return;
  }

  try {
    console.log('Initializing Discord RPC with Client ID:', clientId);
    rpc = new Client({ transport: 'ipc' });

    rpc.on('ready', () => {
      console.log('✅ Discord RPC connected successfully!');
      console.log(
        'Make sure you uploaded assets (null-ide, code, idle) to Discord Developer Portal'
      );
      connected = true;
      retryCount = 0;
      setTimeout(() => {
        updateActivity('Idling', null);
      }, 500);
    });

    rpc.on('disconnected', () => {
      console.log('❌ Discord RPC disconnected');
      connected = false;
    });

    rpc.on('error', (err: Error) => {
      console.error('Discord RPC error:', err);
      connected = false;
    });

    rpc
      .login({ clientId })
      .then(() => {
        console.log('Discord RPC login successful');
      })
      .catch((err: Error) => {
        console.error('Failed to connect to Discord RPC:', err);
        console.error('Make sure Discord is running and the client ID is correct');
        connected = false;

        if (retryCount < MAX_RETRIES) {
          retryCount++;
          const delay = BASE_RETRY_DELAY * Math.pow(2, retryCount - 1);
          console.log(
            `Retrying Discord RPC connection in ${delay / 1000}s (attempt ${retryCount}/${MAX_RETRIES})...`
          );

          setTimeout(() => {
            rpc = null;
            initDiscordRPC();
          }, delay);
        } else {
          console.error(`Discord RPC connection failed after ${MAX_RETRIES} attempts. Giving up.`);
          rpc = null;
        }
      });
  } catch (error) {
    console.error('Error initializing Discord RPC:', error);
    connected = false;
  }
}

export function updateActivity(state: string, fileName: string | null) {
  if (!rpc || !connected) {
    console.log('Discord RPC not connected, skipping activity update');
    return;
  }

  try {
    const activity: DiscordActivity = {
      details: fileName ? `Editing ${fileName}` : 'Hacking & Programming',
      state: fileName ? 'Working on code' : 'Null IDE - Security Toolkit',
      startTimestamp: Date.now(),
      largeImageKey: 'nullide',
      largeImageText: 'Null IDE',
      smallImageKey: fileName ? 'code' : 'idle',
      smallImageText: fileName ? 'Coding' : 'Idle',
      instance: false,
    };

    rpc
      .setActivity(activity)
      .then(() => {
        console.log(`✅ Discord activity updated: ${fileName || 'Idling'}`);
      })
      .catch((err: Error) => {
        console.error('Failed to set Discord activity:', err);
      });
  } catch (error) {
    console.error('Error updating Discord activity:', error);
  }
}

export function clearActivity() {
  if (!rpc || !connected) return;
  rpc.clearActivity().catch((err: Error) => {
    console.error('Failed to clear Discord activity:', err);
  });
}

export function disconnectDiscordRPC() {
  if (rpc) {
    try {
      rpc.destroy().catch(() => {
        // ignore destroy errors
      });
    } catch {
      // ignore errors
    }
    rpc = null;
    connected = false;
    retryCount = 0;
  }
}

export function isDiscordConnected(): boolean {
  return connected;
}
