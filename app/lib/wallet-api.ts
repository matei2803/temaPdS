import { apiFetch, getStoredToken, joinUrl } from "./api";
import { WALLET_API_BASE } from "./env";
import type {
  AuthPayload,
  CredentialEntry,
  DidEntry,
  KeyEntry,
  SessionResponse,
  UserInfo,
  WalletSummary,
} from "@/types/wallet";

const normalizeList = <T = unknown>(payload: unknown): T[] => {
  if (Array.isArray(payload)) return payload as T[];
  if (!payload || typeof payload !== "object") return [];
  const obj = payload as Record<string, unknown>;
  const candidates = ["items", "data", "result", "wallets", "dids", "keys", "credentials", "categories"];
  for (const key of candidates) {
    const value = obj[key];
    if (Array.isArray(value)) return value as T[];
  }
  return [];
};

const normalizeDid = (entry: unknown): DidEntry | null => {
  if (!entry || typeof entry !== "object") return null;
  const obj = entry as Record<string, unknown>;
  const didDoc =
    obj.didDocument && typeof obj.didDocument === "object"
      ? (obj.didDocument as { id?: unknown })
      : null;
  const did =
    (typeof obj.did === "string" && obj.did) ||
    (typeof obj.id === "string" && obj.id) ||
    (typeof obj.identifier === "string" && obj.identifier) ||
    (typeof obj.value === "string" && obj.value) ||
    (didDoc && typeof didDoc.id === "string" ? didDoc.id : undefined) ||
    undefined;
  return { ...obj, did };
};

const extractKeyId = (candidate: unknown): string | undefined => {
  if (candidate == null) return undefined;
  if (typeof candidate === "string" && candidate.trim()) return candidate;
  if (typeof candidate === "number") return String(candidate);
  if (typeof candidate === "object") {
    const obj = candidate as Record<string, unknown>;
    if (typeof obj.id === "string" && obj.id.trim()) return obj.id;
    if (typeof obj.keyId === "string" && obj.keyId.trim()) return obj.keyId;
    if (typeof obj.kid === "string" && obj.kid.trim()) return obj.kid;
  }
  return undefined;
};

const normalizeKey = (entry: unknown): KeyEntry | null => {
  if (!entry || typeof entry !== "object") return null;
  const obj = entry as Record<string, unknown>;
  const keyId =
    extractKeyId(obj.keyId) ||
    extractKeyId(obj.kid) ||
    extractKeyId(obj.keyRef) ||
    extractKeyId(obj.id) ||
    extractKeyId(obj.alias);
  return { ...obj, keyId };
};

const normalizeCredential = (entry: unknown): CredentialEntry | null => {
  if (!entry || typeof entry !== "object") return null;
  const obj = entry as Record<string, unknown>;
  const id =
    (obj.id as string | undefined) ||
    (obj.credentialId as string | undefined) ||
    (obj.alias as string | undefined);
  return { ...obj, id };
};

const normalizeWallet = (entry: unknown): WalletSummary | null => {
  if (!entry || typeof entry !== "object") return null;
  const obj = entry as Record<string, unknown>;
  const id = (obj.id || obj.walletId) as string | undefined;
  if (!id) return null;
  return {
    ...(obj as WalletSummary),
    id: String(id),
  };
};

const tokenOrStored = (token?: string) => token || getStoredToken();

function extractAuthPayload(json: unknown, fallback: string, contentType: string): AuthPayload {
  let id: string | null = null;
  let token: string | null = null;
  let keycloakUserId: string | null = null;

  if (json && typeof json === "object") {
    const obj = json as Record<string, unknown>;
    id = (obj.id as string) ?? null;
    token =
      ((obj.access_token || obj.token || obj.jwt || obj.id_token) as string | null) ??
      null;
    keycloakUserId = (obj.keycloakUserId as string) ?? null;
  } else if (!contentType.includes("application/json")) {
    const t = String(fallback || "").trim();
    if (t.startsWith("eyJ")) token = t;
  }

  return { id, token, keycloakUserId, raw: json ?? fallback };
}

export const walletApi = {
  getSession: (token?: string) =>
    apiFetch<SessionResponse>("/wallet-api/auth/session", {
      baseUrl: WALLET_API_BASE,
      token: tokenOrStored(token),
    }),

  getUserInfo: (token?: string) =>
    apiFetch<UserInfo>("/wallet-api/auth/user-info", {
      baseUrl: WALLET_API_BASE,
      token: tokenOrStored(token),
    }),

  logout: () =>
    apiFetch<void>("/wallet-api/auth/logout", {
      method: "POST",
      baseUrl: WALLET_API_BASE,
    }),

  logoutKeycloak: async () => {
    const res = await fetch(joinUrl(WALLET_API_BASE, "/wallet-api/auth/keycloak/logout"), {
      method: "POST",
      credentials: "include",
    });
    if (!res.ok) throw new Error(`Logout failed (${res.status})`);
    return true;
  },

  listWallets: async (token?: string) => {
    const data = await apiFetch<unknown>(`/wallet-api/wallet/accounts/wallets`, {
      baseUrl: WALLET_API_BASE,
      token: tokenOrStored(token),
    });
    return normalizeList<WalletSummary>(data)
      .map(normalizeWallet)
      .filter(Boolean) as WalletSummary[];
  },

  listDids: async (walletId: string, token?: string) => {
    const data = await apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/dids`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token) }
    );
    return normalizeList<DidEntry>(data)
      .map(normalizeDid)
      .filter(Boolean) as DidEntry[];
  },

  listIssuers: async (walletId: string, token?: string) => {
    return apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/issuers`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token) }
    );
  },

  createDid: async (walletId: string, type: "ebsi" | "key" | "web", options: Record<string, string> = {}, token?: string) => {
    const params = new URLSearchParams();
    Object.entries(options).forEach(([k, v]) => {
      if (v) params.set(k, v);
    });
    const qs = params.toString();
    const endpoint = `/wallet-api/wallet/${encodeURIComponent(walletId)}/dids/create/${type}`;
    const path = qs ? `${endpoint}?${qs}` : endpoint;
    return apiFetch<unknown>(path, {
      method: "POST",
      baseUrl: WALLET_API_BASE,
      token: tokenOrStored(token),
    });
  },

  listKeys: async (walletId: string, token?: string) => {
    const data = await apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/keys`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token) }
    );
    return normalizeList<KeyEntry>(data)
      .map(normalizeKey)
      .filter(Boolean) as KeyEntry[];
  },

  generateKey: async (
    walletId: string,
    { backend = "jwk", keyType = "Ed25519", alias }: { backend?: string; keyType?: string; alias?: string },
    token?: string
  ) => {
    const qs = alias ? `?alias=${encodeURIComponent(alias)}` : "";
    return apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/keys/generate${qs}`,
      {
        method: "POST",
        body: { backend, keyType },
        baseUrl: WALLET_API_BASE,
        token: tokenOrStored(token),
      }
    );
  },

  listCredentials: async (walletId: string, token?: string) => {
    const data = await apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/credentials`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token) }
    );
    return normalizeList<CredentialEntry>(data)
      .map(normalizeCredential)
      .filter(Boolean) as CredentialEntry[];
  },

  acceptCredentialOffer: async (
    walletId: string,
    offer: string,
    params?: { did?: string; pinOrTxCode?: string; requireUserInput?: string },
    token?: string
  ) => {
    const search = new URLSearchParams();
    if (params?.did) search.set("did", params.did);
    if (params?.pinOrTxCode) search.set("pinOrTxCode", params.pinOrTxCode);
    if (params?.requireUserInput) search.set("requireUserInput", params.requireUserInput);
    const qs = search.toString();
    const endpoint = `/wallet-api/wallet/${encodeURIComponent(walletId)}/exchange/useOfferRequest`;
    const path = qs ? `${endpoint}?${qs}` : endpoint;
    return apiFetch<unknown>(path, {
      method: "POST",
      baseUrl: WALLET_API_BASE,
      token: tokenOrStored(token),
      body: offer,
      rawBody: true,
      headers: { "content-type": "text/plain" },
    });
  },

  resolvePresentationRequest: async (walletId: string, presentationRequest: string, token?: string) =>
    apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/exchange/resolvePresentationRequest`,
      {
        method: "POST",
        baseUrl: WALLET_API_BASE,
        token: tokenOrStored(token),
        body: presentationRequest,
      }
    ),

  matchCredentialsForPresentationDefinition: async (
    walletId: string,
    presentationDefinition: unknown,
    token?: string
  ) =>
    apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/exchange/matchCredentialsForPresentationDefinition`,
      {
        method: "POST",
        baseUrl: WALLET_API_BASE,
        token: tokenOrStored(token),
        body: presentationDefinition,
      }
    ),

  usePresentationRequest: async (
    walletId: string,
    payload: { did: string; presentationRequest: string; selectedCredentials: string[]; disclosures?: unknown; note?: string },
    token?: string
  ) =>
    apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/exchange/usePresentationRequest`,
      {
        method: "POST",
        baseUrl: WALLET_API_BASE,
        token: tokenOrStored(token),
        body: payload,
      }
    ),

  keyMeta: (walletId: string, keyId: string, token?: string) =>
    apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/keys/${encodeURIComponent(keyId)}/meta`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token) }
    ),

  keyLoad: (walletId: string, keyId: string, token?: string) =>
    apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/keys/${encodeURIComponent(keyId)}/load`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token) }
    ),

  keyDelete: (walletId: string, keyId: string, token?: string) =>
    apiFetch<void>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/keys/${encodeURIComponent(keyId)}`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token), method: "DELETE" }
    ),

  keyRemoveRef: (walletId: string, keyId: string, token?: string) =>
    apiFetch<void>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/keys/${encodeURIComponent(keyId)}/remove`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token), method: "DELETE" }
    ),

  keyExport: async (walletId: string, keyId: string, token?: string) => {
    const url = joinUrl(
      WALLET_API_BASE,
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/keys/${encodeURIComponent(keyId)}/export`
    );
    const res = await fetch(url, {
      headers: tokenOrStored(token) ? { Authorization: `Bearer ${tokenOrStored(token)}` } : {},
      credentials: "include",
    });
    if (!res.ok) throw new Error(`Export failed (${res.status})`);
    return res.blob();
  },

  didView: (walletId: string, did: string, token?: string) =>
    apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/dids/${encodeURIComponent(did)}`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token) }
    ),

  didDelete: (walletId: string, did: string, token?: string) =>
    apiFetch<void>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/dids/${encodeURIComponent(did)}`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token), method: "DELETE" }
    ),

  viewCredential: (walletId: string, credentialId: string, token?: string) =>
    apiFetch<unknown>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/credentials/${encodeURIComponent(credentialId)}`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token) }
    ),

  deleteCredential: (walletId: string, credentialId: string, token?: string) =>
    apiFetch<void>(
      `/wallet-api/wallet/${encodeURIComponent(walletId)}/credentials/${encodeURIComponent(credentialId)}`,
      { baseUrl: WALLET_API_BASE, token: tokenOrStored(token), method: "DELETE" }
    ),

  fetchKeycloakToken: async () => {
    const res = await fetch(joinUrl(WALLET_API_BASE, "/wallet-api/auth/keycloak/token"), {
      method: "GET",
      credentials: "include",
    });
    const ct = res.headers.get("content-type") || "";
    const text = await res.text();
    if (!res.ok) throw new Error(`Token fetch failed (${res.status})`);
    if (ct.includes("application/json")) {
      try {
        const json = text ? JSON.parse(text) : {};
        return (json.token || json.access_token || json.jwt || "") as string;
      } catch {
        return "";
      }
    }
    return text.trim();
  },

  loginKeycloak: async ({ username, password }: { username: string; password: string }): Promise<AuthPayload> => {
    const res = await fetch(joinUrl(WALLET_API_BASE, "/wallet-api/auth/keycloak/login"), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ type: "keycloak", username, password }),
    });
    const ct = res.headers.get("content-type") || "";
    const text = await res.text();
    const data = ct.includes("application/json")
      ? (() => {
          try {
            return text ? JSON.parse(text) : {};
          } catch {
            return null;
          }
        })()
      : null;
    if (!res.ok) {
      const msg =
        (data && (data.error || data.message || (data as Record<string, string>).detail)) ||
        text ||
        `Login failed (${res.status})`;
      throw new Error(msg);
    }
    return extractAuthPayload(data, text, ct);
  },

  createKeycloakAccount: async ({
    username,
    password,
    email,
  }: {
    username: string;
    password: string;
    email: string;
  }) => {
    if (!username || !password || !email) throw new Error("Username, password si email sunt obligatorii.");
    const token = await walletApi.fetchKeycloakToken();
    if (!token || !token.startsWith("eyJ")) {
      throw new Error("Tokenul necesar pentru inregistrare nu a fost obtinut.");
    }
    const res = await fetch(joinUrl(WALLET_API_BASE, "/wallet-api/auth/keycloak/create"), {
      method: "POST",
      credentials: "include",
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        type: "keycloak",
        username,
        password,
        email,
        token,
      }),
    });
    const ct = res.headers.get("content-type") || "";
    const text = await res.text();
    const data = ct.includes("application/json")
      ? (() => {
          try {
            return text ? JSON.parse(text) : {};
          } catch {
            return null;
          }
        })()
      : null;
    const ok = res.status === 200 || res.status === 201;
    if (!ok) {
      const msg = (data && (data.error || data.message || (data as Record<string, string>).detail)) || text || `Create failed (${res.status})`;
      throw new Error(msg);
    }
    return data ?? {};
  },

  probeKeycloakToken: async () => {
    const res = await fetch(joinUrl(WALLET_API_BASE, "/wallet-api/auth/keycloak/token"), {
      method: "GET",
      credentials: "include",
    });
    const ct = res.headers.get("content-type") || "";
    const text = await res.text();
    const data = ct.includes("application/json")
      ? (() => {
          try {
            return text ? JSON.parse(text) : {};
          } catch {
            return null;
          }
        })()
      : null;
    if (!res.ok) throw new Error(`Token probe failed (${res.status})`);
    return { status: res.status, contentType: ct, data: ct.includes("application/json") ? data : text };
  },
};

export const resolveWalletBase = () => WALLET_API_BASE;
export const composeWalletUrl = (path: string) => joinUrl(WALLET_API_BASE, path);
