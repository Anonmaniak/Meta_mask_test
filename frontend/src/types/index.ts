export interface NetworkInfo {
  chainIdHex: string;
  chainIdNum: number;
  name: string;
  shortName: string;
  symbol: string;
  explorerBase: string;
}

export interface HealthResponse {
  status: string;
  timestamp: string;
  service: string;
  storage: string;
  starting_level: number;
  networks: {
    mainnet: { configured: boolean; connected: boolean };
    sepolia: { configured: boolean; connected: boolean };
  };
}

export interface ChatMessage {
  id: string;
  channel: string;
  sender: string;
  recipient?: string | null;
  message: string;
  isEncrypted?: boolean;
  canDecrypt?: boolean;
  decryptionError?: string;
  timestamp: string;
}
