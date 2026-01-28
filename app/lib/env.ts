// Centralized env access mirroring the old app variables.
export const WALLET_API_BASE =
  (import.meta.env?.VITE_WALLET_BASE as string | undefined) ||
  (import.meta.env?.VITE_WALLET_API_BASE as string | undefined) ||
  "";

export const ISSUER_API_BASE =
  (import.meta.env?.VITE_ISSUER_BASE as string | undefined) ||
  (import.meta.env?.VITE_ISSUER_API_BASE as string | undefined) ||
  (import.meta.env?.VITE_WALTID_ISSUER_BASE as string | undefined) ||
  "";

export const VERIFIER_API_BASE =
  (import.meta.env?.VITE_VERIFIER_BASE as string | undefined) ||
  (import.meta.env?.VITE_VERIFIER_API_BASE as string | undefined) ||
  "";

export const WALTID_ISSUER_BASE =
  (import.meta.env?.VITE_WALTID_ISSUER_BASE as string | undefined) || "";

export const VC_REGISTRY_BASE =
  (import.meta.env?.VITE_VC_REGISTRY_BASE as string | undefined) ||
  (import.meta.env?.VITE_URL ? `http://${import.meta.env.VITE_URL}/dev/vc/issued` : "") ||
  "";

export const VITE_URL_HOST = import.meta.env?.VITE_URL as string | undefined;
