export const extractUserId = (info: unknown): string => {
  if (!info || typeof info !== "object") return "";
  const obj = info as Record<string, unknown>;
  const candidates = [
    obj.id,
    obj.userId,
    obj.user_id,
    obj.sub,
    obj.subject,
    (obj.user as Record<string, unknown> | undefined)?.id,
  ];
  for (const c of candidates) {
    if (typeof c === "string" && c.trim()) return c;
  }
  return "";
};

export const userIdFromPath = (path: string): string => {
  const parts = path.split("/").filter(Boolean);
  return parts[0] || "";
};

export const buildUserPath = (userId: string, subPath: string) => {
  const safeUser = encodeURIComponent(userId || "");
  const cleanSub = subPath.replace(/^\/+/, "");
  return `/${safeUser}/${cleanSub}`;
};
