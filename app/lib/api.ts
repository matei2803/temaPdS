import { WALLET_API_BASE } from "./env";

export const joinUrl = (base: string, path: string) => {
  if (!base) return path;
  return `${base.replace(/\/+$/, "")}/${path.replace(/^\/+/, "")}`;
};

export class ApiError extends Error {
  status?: number;
  details?: unknown;

  constructor(message: string, status?: number, details?: unknown) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

export type ApiFetchOptions = {
  method?: string;
  token?: string;
  body?: unknown;
  headers?: Record<string, string>;
  baseUrl?: string;
  rawBody?: boolean;
};

const parseBody = async (res: Response) => {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

const buildHeaders = ({
  body,
  rawBody,
  token,
  headers,
}: Pick<ApiFetchOptions, "body" | "rawBody" | "token" | "headers">) => {
  const result: Record<string, string> = {
    accept: "application/json",
    ...(headers || {}),
  };

  if (token) result.Authorization = `Bearer ${token}`;

  const hasBody = body !== undefined;
  if (hasBody && !rawBody && !result["content-type"] && !(body instanceof FormData)) {
    result["content-type"] = "application/json";
  }
  if (hasBody && rawBody && !result["content-type"]) {
    result["content-type"] = "text/plain";
  }

  return result;
};

export async function apiFetch<T = unknown>(
  path: string,
  {
    method = "GET",
    token,
    body,
    headers,
    baseUrl = WALLET_API_BASE,
    rawBody = false,
  }: ApiFetchOptions = {}
): Promise<T> {
  const url =
    path.startsWith("http://") || path.startsWith("https://")
      ? path
      : joinUrl(baseUrl, path);

  const res = await fetch(url, {
    method,
    credentials: "include",
    headers: buildHeaders({ body, rawBody, token, headers }),
    body:
      body === undefined
        ? undefined
        : rawBody || typeof body === "string" || body instanceof FormData
        ? (body as BodyInit)
        : JSON.stringify(body),
  });

  const data = await parseBody(res);
  if (!res.ok) {
    const message =
      (data &&
        typeof data === "object" &&
        ("message" in data
          ? String((data as Record<string, unknown>).message)
          : "error" in data
          ? String((data as Record<string, unknown>).error)
          : "detail" in data
          ? String((data as Record<string, unknown>).detail)
          : "")) ||
      `HTTP ${res.status}`;
    throw new ApiError(message, res.status, data);
  }

  return data as T;
}

export const getStoredToken = () => {
  try {
    return localStorage.getItem("wallet_token") || "";
  } catch {
    return "";
  }
};

export const getStoredWalletId = () => {
  try {
    return localStorage.getItem("wallet_id") || "";
  } catch {
    return "";
  }
};
