import { joinUrl } from "./api";
import { ISSUER_API_BASE } from "./env";

export type IssueJwtResponse = unknown;

export async function issueJwtCredential(body: unknown, sessionTtl?: string) {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (sessionTtl) headers.sessionTtl = sessionTtl;

  const base = import.meta.env.DEV ? "" : ISSUER_API_BASE;
  const res = await fetch(joinUrl(base, "/openid4vc/jwt/issue"), {
    method: "POST",
    credentials: "include",
    headers,
    body: JSON.stringify(body),
  });
  const text = await res.text();
  const data = text ? (() => { try { return JSON.parse(text); } catch { return text; } })() : null;
  if (!res.ok) {
    const msg = (data && (data.message || data.error || data.detail)) || `HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data as IssueJwtResponse;
}
