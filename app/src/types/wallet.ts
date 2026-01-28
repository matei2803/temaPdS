export type SessionResponse = {
  sessionId?: string;
  [key: string]: unknown;
};

export type UserInfo = {
  id?: string;
  sub?: string;
  userId?: string;
  user_id?: string;
  [key: string]: unknown;
};

export type WalletSummary = {
  id: string;
  name?: string;
  permission?: string;
  [key: string]: unknown;
};

export type DidEntry = {
  did?: string;
  id?: string;
  alias?: string;
  method?: string;
  didDocument?: { id?: string; [key: string]: unknown };
  [key: string]: unknown;
};

export type KeyEntry = {
  keyId?: string;
  kid?: string;
  keyRef?: string;
  alias?: string;
  algorithm?: string;
  keyType?: string;
  createdAt?: string;
  [key: string]: unknown;
};

export type CredentialEntry = {
  id?: string;
  issuer?: string;
  subject?: string;
  type?: string | string[];
  issuedAt?: string;
  category?: string;
  status?: string;
  [key: string]: unknown;
};

export type AuthPayload = {
  id: string | null;
  token: string | null;
  keycloakUserId: string | null;
  raw?: unknown;
};
