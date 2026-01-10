import { Client } from 'discord-rpc';

const clientId = '1331234567890123456'; // You'll need to create a Discord app and get this ID

let rpc: Client | null = null;
let connected = false;

export function initDiscordRPC() {
  if (rpc) return;

  rpc = new Client({ transport: 'ipc' });

  rpc.on('ready', () => {
    console.log('Discord RPC connected');
    connected = true;
    updateActivity('Idling', null);
  });

  rpc.on('disconnected', () => {
    console.log('Discord RPC disconnected');
    connected = false;
  });

  rpc.login({ clientId }).catch((err: Error) => {
    console.error('Failed to connect to Discord RPC:', err);
    connected = false;
  });
}

export function updateActivity(state: string, fileName: string | null) {
  if (!rpc || !connected) return;

  const activity: any = {
    details: fileName ? `Editing ${fileName}` : 'Idling',
    state: fileName ? 'Working on a file' : 'No files open',
    startTimestamp: Date.now(),
    largeImageKey: 'null-ide-logo', // Upload logo to Discord app assets
    largeImageText: 'Null IDE v3.0',
    smallImageKey: fileName ? 'editing' : 'idle',
    smallImageText: fileName ? 'Coding' : 'Idle',
    instance: false,
  };

  rpc.setActivity(activity).catch((err: Error) => {
    console.error('Failed to set Discord activity:', err);
  });
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
