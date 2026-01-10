import { Client } from 'discord-rpc';

const clientId = '1459478156120428606'; // You'll need to create a Discord app and get this ID

let rpc: Client | null = null;
let connected = false;

export function initDiscordRPC() {
  if (rpc) return;

  try {
    rpc = new Client({ transport: 'ipc' });

    rpc.on('ready', () => {
      console.log('✅ Discord RPC connected successfully');
      connected = true;
      // Set initial activity
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

    // Login with retry mechanism
    rpc.login({ clientId }).then(() => {
      console.log('Discord RPC login successful');
    }).catch((err: Error) => {
      console.error('Failed to connect to Discord RPC:', err);
      console.error('Make sure Discord is running and the client ID is correct');
      connected = false;
      // Retry after 5 seconds
      setTimeout(() => {
        console.log('Retrying Discord RPC connection...');
        rpc = null;
        initDiscordRPC();
      }, 5000);
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
    const activity: any = {
      details: fileName ? `Editing ${fileName}` : 'Idling',
      state: fileName ? 'Working on a file' : 'No files open',
      startTimestamp: Date.now(),
      largeImageKey: 'null-ide',
      largeImageText: 'Null IDE v3.2',
      smallImageKey: fileName ? 'code' : 'idle',
      smallImageText: fileName ? 'Coding' : 'Idle',
      instance: false,
    };

    rpc.setActivity(activity).then(() => {
      console.log(`✅ Discord activity updated: ${fileName || 'Idling'}`);
    }).catch((err: Error) => {
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
    rpc.destroy();
    rpc = null;
    connected = false;
  }
}
