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

export interface RecipientKeyWrapperPayload {
  recipient: string;
  keyFingerprint: string;
  iv: string;
  wrappedKey: string;
}

export interface EncryptedChatMessage {
  id: string;
  room_id?: string;
  channel?: string;
  sender: string;
  algorithm: string;
  content_iv: string;
  content_ciphertext: string;
  recipients: RecipientKeyWrapperPayload[];
  sender_public_key?: any;
  signature?: string;
  timestamp: string;
}

export interface EncryptedMessageSendPayload {
  version: 1;
  message_id: string;
  channel: string;
  sender: string;
  algorithm: string;
  key_version: number;
  content_iv: string;
  content_ciphertext: string;
  recipients: RecipientKeyWrapperPayload[];
  sender_public_key: any;
  signature: string;
  timestamp: string;
}

export interface RoomRecipientsResponse {
  room_id: string;
  count: number;
  recipients: Array<{
    address: string;
    public_key: any;
    public_key_fingerprint: string;
    algorithm: string;
    curve: string;
  }>;
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
  rawEnvelope?: EncryptedChatMessage;
}

export interface ChatPublicKey {
  version: 1;
  curve: 'P-256';
  format: 'raw+jwk';
  rawBase64Url: string;
  jwk?: any;
  fingerprint: string;
}

export interface ChatKeyChallengeRequest {
  address: string;
  public_key_fingerprint: string;
  chain_id?: number;
}

export interface ChatKeyChallengeResponse {
  challenge_id: string;
  address: string;
  message: string;
  expires_at: string;
  public_key_fingerprint: string;
}

export interface ChatKeyRegisterPayload {
  address: string;
  challenge_id: string;
  signature: string;
  public_key: ChatPublicKey;
  key_version?: number;
  rotate?: boolean;
}

export interface ChatKeyRegisterResponse {
  success: boolean;
  address: string;
  fingerprint: string;
  key_version: number;
  created_at: string;
  updated_at: string;
  rotated: boolean;
}

export interface ChatKeyLookupResponse {
  address: string;
  registered: boolean;
  public_key?: ChatPublicKey;
  fingerprint?: string;
  key_version?: number;
  created_at?: string;
  updated_at?: string;
}

export interface BatchChatKeyLookupResponse {
  keys: Record<string, ChatKeyLookupResponse>;
}
