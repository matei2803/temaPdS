import { useEffect, useMemo, useState } from "react";
import { Wallet, Key, Plus, FileCheck, QrCode, Copy, RefreshCw, Send } from "lucide-react";
import { MainLayout } from "@/components/layout/MainLayout";
import { PageHeader } from "@/components/shared/PageHeader";
import { StatCard } from "@/components/shared/StatCard";
import { DataCard } from "@/components/shared/DataCard";
import { EmptyState } from "@/components/shared/EmptyState";
import { CredentialCard } from "@/components/shared/CredentialCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import {
  useAcceptCredentialOffer,
  useCreateDid,
  useGenerateKey,
  usePrimaryWallet,
  useWalletResources,
} from "@/hooks/useWalletApi";
import { CredentialEntry, DidEntry, KeyEntry } from "@/types/wallet";
import { getStoredWalletId } from "@/lib/api";
import { walletApi } from "@/lib/wallet-api";
import { VC_REGISTRY_BASE } from "@/lib/env";
import { VERIFIER_API_BASE } from "@/lib/env";
import { joinUrl } from "@/lib/api";

const DID_KEY_MAP_KEY = "did_key_map";
const OFFER_NOTIFICATION_KEY = "pending_credential_offers";

type PendingOffer = { did: string; offerUrl: string; createdAt: number; label?: string };

const loadDidKeyMap = (): Record<string, Record<string, string[]>> => {
  try {
    const raw = localStorage.getItem(DID_KEY_MAP_KEY);
    return raw ? (JSON.parse(raw) as Record<string, Record<string, string[]>>) : {};
  } catch {
    return {};
  }
};

const saveDidKeyMap = (map: Record<string, Record<string, string[]>>) => {
  try {
    localStorage.setItem(DID_KEY_MAP_KEY, JSON.stringify(map));
  } catch {
    // ignore storage errors
  }
};

const loadPendingOffers = (): PendingOffer[] => {
  try {
    const raw = localStorage.getItem(OFFER_NOTIFICATION_KEY);
    return raw ? (JSON.parse(raw) as PendingOffer[]) : [];
  } catch {
    return [];
  }
};

const savePendingOffers = (offers: PendingOffer[]) => {
  try {
    localStorage.setItem(OFFER_NOTIFICATION_KEY, JSON.stringify(offers));
  } catch {
    // ignore storage errors
  }
};

const normalizeDid = (did: string) => did.trim().toLowerCase().split("#")[0].split("?")[0];

export default function WalletPage() {
  type VCStatus = "valid" | "revoked" | "expired";
  type StatusEntry = { id: string; status: VCStatus };
  const { session, wallets, primaryWalletId } = usePrimaryWallet();
  const [didMethod, setDidMethod] = useState("did:ebsi");
  const [keyType, setKeyType] = useState("Ed25519");
  const [createDIDOpen, setCreateDIDOpen] = useState(false);
  const [createKeyOpen, setCreateKeyOpen] = useState(false);
  const [receiveOfferOpen, setReceiveOfferOpen] = useState(false);
  const [credentialOffer, setCredentialOffer] = useState("");
  const [availableOffers, setAvailableOffers] = useState<PendingOffer[]>([]);
  const [keyDialogOpen, setKeyDialogOpen] = useState(false);
  const [keyActionTarget, setKeyActionTarget] = useState<KeyEntry | null>(null);
  const [keyActionResult, setKeyActionResult] = useState<string>("");
  const [keyActionBusy, setKeyActionBusy] = useState(false);
  const [didDialogOpen, setDidDialogOpen] = useState(false);
  const [didActionTarget, setDidActionTarget] = useState<DidEntry | null>(null);
  const [didActionResult, setDidActionResult] = useState<string>("");
  const [didActionBusy, setDidActionBusy] = useState(false);
  const [credDialogOpen, setCredDialogOpen] = useState(false);
  const [credActionTarget, setCredActionTarget] = useState<CredentialEntry | null>(null);
  const [credActionResult, setCredActionResult] = useState<string>("");
  const [credActionBusy, setCredActionBusy] = useState(false);
  const [credDetail, setCredDetail] = useState<unknown>(null);
  const [credDetailLoading, setCredDetailLoading] = useState(false);
  const [selectedDidFilter, setSelectedDidFilter] = useState("");
  const [statusById, setStatusById] = useState<Record<string, VCStatus>>({});
  const [presentationRequest, setPresentationRequest] = useState("");
  const [resolvedRequest, setResolvedRequest] = useState<unknown>(null);
  const [presentationDefinition, setPresentationDefinition] = useState<unknown>(null);
  const [matchingCreds, setMatchingCreds] = useState<CredentialEntry[]>([]);
  const [selectedCredIds, setSelectedCredIds] = useState<string[]>([]);
  const [holderDid, setHolderDid] = useState("");
  const [presentResult, setPresentResult] = useState<unknown>(null);
  const [verifyError, setVerifyError] = useState("");
  const [loadingResolve, setLoadingResolve] = useState(false);
  const [loadingMatch, setLoadingMatch] = useState(false);
  const [loadingPresent, setLoadingPresent] = useState(false);
  const { toast } = useToast();

  const activeWalletId = primaryWalletId || getStoredWalletId() || wallets.data?.[0]?.id || "";

  const { didsQuery, keysQuery, credentialsQuery } = useWalletResources(activeWalletId);
  const createDid = useCreateDid(activeWalletId);
  const generateKey = useGenerateKey(activeWalletId);
  const acceptOffer = useAcceptCredentialOffer(activeWalletId);
  const sessionError = session.error instanceof Error ? session.error.message : null;
  const walletsError = wallets.error instanceof Error ? wallets.error.message : null;

  const dids: DidEntry[] = useMemo(() => didsQuery.data || [], [didsQuery.data]);
  const keys: KeyEntry[] = useMemo(() => keysQuery.data || [], [keysQuery.data]);
  const credentials: CredentialEntry[] = useMemo(
    () => credentialsQuery.data || [],
    [credentialsQuery.data]
  );

  useEffect(() => {
    const firstDid = dids.find((d) => d.did || d.id);
    if (!holderDid && firstDid) {
      setHolderDid(firstDid.did || (firstDid as any).id || "");
    }
  }, [dids, holderDid]);

  useEffect(() => {
    if (!receiveOfferOpen || !holderDid) return;
    const selectedDid = normalizeDid(holderDid);
    const offers = loadPendingOffers();
    const matching = offers.filter((o) => normalizeDid(o.did) === selectedDid);
    setAvailableOffers(matching);
    if (!matching.length) return;
    toast({
      title: "Credential offers available",
      description: "Select an offer to fill the URL.",
    });
  }, [receiveOfferOpen, holderDid, toast]);

  const handleSelectOffer = (offer: PendingOffer) => {
    setCredentialOffer(offer.offerUrl);
    const selectedDid = normalizeDid(holderDid);
    const remaining = loadPendingOffers().filter(
      (o) => !(normalizeDid(o.did) === selectedDid && o.offerUrl === offer.offerUrl)
    );
    savePendingOffers(remaining);
    setAvailableOffers((prev) => prev.filter((o) => o.offerUrl !== offer.offerUrl));
  };

  const formatKeyLabel = (key: KeyEntry) => {
    const candidates = [
      key.keyId,
      key.kid,
      key.keyRef,
      key.alias,
      (key as Record<string, unknown>)?.id,
    ];
    for (const c of candidates) {
      if (typeof c === "string" && c.trim()) return c;
      if (typeof c === "number") return String(c);
      if (c && typeof c === "object") {
        const id = (c as Record<string, unknown>).id;
        if (typeof id === "string" && id.trim()) return id;
      }
    }
    return "Unknown key";
  };

  const getKeyIds = (list: KeyEntry[]) =>
    list
      .map((k) => formatKeyLabel(k))
      .filter((id): id is string => Boolean(id && id !== "Unknown key"));

  const getDidIds = (list: DidEntry[]) =>
    list
      .map((d) => d.did || d.id || "")
      .filter((id): id is string => Boolean(id));

  const extractIssuer = (cred: CredentialEntry, detail?: unknown) => {
    const pickIssuer = (src: any) => {
      if (!src) return "";
      if (typeof src === "string") return src;
      if (typeof src === "object") {
        if (typeof src.id === "string") return src.id;
        if (typeof src.name === "string") return src.name;
      }
      return "";
    };
    const parsed = (detail as any)?.parsedDocument || (cred as any)?.parsedDocument;
    return (
      pickIssuer((parsed as any)?.issuer) ||
      pickIssuer((detail as any)?.issuer) ||
      pickIssuer((detail as any)?.credential?.issuer) ||
      pickIssuer(cred.issuer) ||
      "Unknown issuer"
    );
  };

  const extractIssuedAt = (cred: CredentialEntry, detail?: unknown) => {
    const maybe = (val: any) => (typeof val === "string" && val) || "";
    const parsed = (detail as any)?.parsedDocument || (cred as any)?.parsedDocument;
    return (
      maybe((parsed as any)?.issuanceDate) ||
      maybe((detail as any)?.issuanceDate) ||
      maybe((detail as any)?.issuedAt) ||
      maybe((detail as any)?.credential?.issuanceDate) ||
      maybe((detail as any)?.credential?.issuedAt) ||
      (cred.issuedAt as string) ||
      (cred.issuanceDate as string) ||
      (cred["issuance_date"] as string) ||
      "Unknown date"
    );
  };

  const extractExpirationFromCred = (cred: CredentialEntry) => {
    const parsed = (cred as any)?.parsedDocument;
    const maybe = (val: any) => (typeof val === "string" && val) || "";
    return (
      maybe(parsed?.expirationDate) ||
      maybe((cred as any)?.expirationDate) ||
      "Unknown date"
    );
  };

  const extractExpiration = (cred: CredentialEntry, detail?: unknown) => {
    const maybe = (val: any) => (typeof val === "string" && val) || "";
    const parsed = (detail as any)?.parsedDocument || (cred as any)?.parsedDocument;
    return (
      maybe((parsed as any)?.expirationDate) ||
      maybe((detail as any)?.expirationDate) ||
      maybe((detail as any)?.credential?.expirationDate) ||
      (cred as any)?.expirationDate ||
      "Unknown"
    );
  };


  const extractTypeLabel = (cred: CredentialEntry, detail?: unknown) => {
    const parsedTypes =
      (detail as any)?.parsedDocument?.type ||
      (detail as any)?.credential?.type ||
      (cred as any)?.parsedDocument?.type ||
      cred.type;

    if (Array.isArray(parsedTypes)) {
      const nonVc = parsedTypes.filter(
        (t) => t !== "VerifiableCredential" && t !== "Verifiable Credential"
      );
      if (nonVc.length) return nonVc[0];
      if (parsedTypes.length > 1) return parsedTypes[1];
      return parsedTypes[0] || "Verifiable Credential";
    }
    if (typeof parsedTypes === "string") {
      return parsedTypes;
    }
    return cred.type || "Verifiable Credential";
  };

  const base64UrlToBytes = (input: string) => {
    const norm = input.replace(/-/g, "+").replace(/_/g, "/");
    const pad = norm.length % 4 === 0 ? "" : "=".repeat(4 - (norm.length % 4));
    const bin = atob(norm + pad);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  };

  const decodeEncodedList = async (encoded: string) => {
    const raw = base64UrlToBytes(encoded);
    if (typeof DecompressionStream === "undefined") {
      return raw;
    }
    try {
      const ds = new DecompressionStream("gzip");
      const stream = new Response(new Blob([raw]).stream().pipeThrough(ds));
      const buf = await stream.arrayBuffer();
      return new Uint8Array(buf);
    } catch {
      return raw;
    }
  };

  const decodeBitAt = (bytes: Uint8Array, index: number) => {
    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    if (byteIndex >= bytes.length || index < 0) return null;
    const byte = bytes[byteIndex];
    return (byte >> (7 - bitIndex)) & 1;
  };

  const resolveStatusEntry = (cred: CredentialEntry) => {
    const status = (cred as any)?.credentialStatus || (cred as any)?.parsedDocument?.credentialStatus;
    if (!status || typeof status !== "object") return null;
    const urlRaw = (status as any).statusListCredential || (status as any).id;
    if (!urlRaw) return null;
    const [urlPart, fragment] = String(urlRaw).split("#");
    const indexRaw = (status as any).statusListIndex || (status as any).index || fragment;
    const idxNum = Number(indexRaw);
    if (!Number.isFinite(idxNum)) return null;
    return { url: String(urlPart || urlRaw), index: idxNum };
  };

  const extractHolderDid = (cred: CredentialEntry, detail?: unknown) => {
    const parsed = (detail as any)?.parsedDocument || (cred as any)?.parsedDocument;
    const subject =
      (parsed as any)?.credentialSubject ||
      (detail as any)?.credentialSubject ||
      (detail as any)?.credential?.credentialSubject ||
      (cred as any)?.credentialSubject;
    if (!subject) return "";
    if (Array.isArray(subject)) {
      const first = subject[0];
      if (first && typeof first === "object" && typeof (first as any).id === "string") return (first as any).id;
    }
    if (typeof subject === "object" && typeof (subject as any).id === "string") return (subject as any).id;
    if (typeof subject === "string") return subject;
    return "";
  };

  const extractSubjectEntries = (source: CredentialEntry, detail?: unknown) => {
    const parsed = (detail as any)?.parsedDocument || (source as any)?.parsedDocument;
    const subject =
      (parsed as any)?.credentialSubject ||
      (detail as any)?.credentialSubject ||
      (detail as any)?.credential?.credentialSubject ||
      (source as any)?.credentialSubject;
    if (!subject || typeof subject !== "object") return [];

    const entries: { key: string; value: string }[] = [];

    Object.entries(subject as Record<string, unknown>).forEach(([k, v]) => {
      if (k === "achievement" && v && typeof v === "object") {
        Object.entries(v as Record<string, unknown>).forEach(([ak, av]) => {
          entries.push({ key: ak, value: typeof av === "object" ? JSON.stringify(av) : String(av) });
        });
        return;
      }
      entries.push({ key: k, value: typeof v === "object" ? JSON.stringify(v) : String(v) });
    });

    return entries;
  };

  const formatDidLabel = (did: string) => {
    const isLong = (did.startsWith("did:jwk") || did.startsWith("did:jwt")) && did.length > 200;
    return isLong ? `${did.slice(0, 64)}…${did.slice(-24)}` : did;
  };

  const didSuffix = (did: string) => {
    const parts = String(did || "").split(":");
    return parts[parts.length - 1] || "";
  };

  const idSuffix = (id: string) => {
    if (!id) return "";
    const trimmed = String(id).trim();
    const withoutHash = trimmed.split("#")[0].split("?")[0];
    const slashParts = withoutHash.split("/").filter(Boolean);
    let tail = slashParts.length ? slashParts[slashParts.length - 1] : withoutHash;
    const colonParts = tail.split(":").filter(Boolean);
    tail = colonParts.length ? colonParts[colonParts.length - 1] : tail;
    return tail.replace(/\.json$/i, "");
  };

  const decodeJwtPayload = (token: string) => {
    try {
      const parts = token.split(".");
      if (parts.length < 2) return null;
      const payload = atob(parts[1].replace(/-/g, "+").replace(/_/g, "/"));
      return JSON.parse(payload);
    } catch {
      return null;
    }
  };

  const isLikelyVc = (payload: unknown) => {
    if (!payload || typeof payload !== "object") return false;
    const obj = payload as Record<string, unknown>;
    return Boolean(obj["@context"] || obj.credentialSubject || obj.type || obj.issuer);
  };

  const extractEmbeddedCredential = (payload: unknown): unknown => {
    if (!payload || typeof payload !== "object") return null;
    const obj = payload as Record<string, unknown>;
    if (obj.verifiableCredential) return obj.verifiableCredential;
    if (obj.credential) return obj.credential;
    if (obj.credentialDocument) return obj.credentialDocument;
    if ((obj as any).credentialResponse?.credential) return (obj as any).credentialResponse.credential;
    if (Array.isArray((obj as any).credentials) && (obj as any).credentials[0]) return (obj as any).credentials[0];
    if (Array.isArray((obj as any).verifiableCredentials) && (obj as any).verifiableCredentials[0])
      return (obj as any).verifiableCredentials[0];
    if (Array.isArray(payload) && payload.length) {
      const first = payload[0] as any;
      if (first?.document) return first.document;
      if (first?.credential) return first.credential;
      if (isLikelyVc(first)) return first;
    }
    if (obj.result) return extractEmbeddedCredential(obj.result);
    if (isLikelyVc(obj)) return obj;
    return null;
  };

  const extractCredentialIds = (payload: unknown) => {
    const ids = new Set<string>();
    const push = (v: unknown) => {
      if (!v) return;
      ids.add(String(v));
    };
    if (!payload || typeof payload !== "object") return [];
    const obj = payload as Record<string, unknown>;
    if (Array.isArray((obj as any).credentialIds)) (obj as any).credentialIds.forEach(push);
    push((obj as any).credentialId);
    push(obj.id);
    if (Array.isArray((obj as any).credentials)) (obj as any).credentials.forEach((c: any) => push(c?.id));
    if ((obj as any).verifiableCredential?.id) push((obj as any).verifiableCredential.id);
    if ((obj as any).credential?.id) push((obj as any).credential.id);
    if (Array.isArray(payload)) payload.forEach((item: any) => push(item?.id));
    if (obj.result) extractCredentialIds(obj.result).forEach(push);
    return Array.from(ids).filter(Boolean);
  };

  const findRevocationIndex = (credential: any) => {
    if (!credential) return null;
    const entries = Array.isArray(credential.credentialStatus)
      ? credential.credentialStatus
      : [credential.credentialStatus].filter(Boolean);
    for (const entry of entries) {
      if (!entry || typeof entry !== "object") continue;
      const purpose = String((entry as any).statusPurpose || "").toLowerCase();
      if (purpose && purpose !== "revocation") continue;
      if ((entry as any).statusListIndex !== undefined && (entry as any).statusListIndex !== null) {
        return String((entry as any).statusListIndex);
      }
    }
    return null;
  };

  const fetchJsonNoStore = async (url: string) => {
    const r = await fetch(url, { cache: "no-store" });
    if (!r.ok) throw new Error(`GET ${url} -> ${r.status}`);
    return r.json();
  };

  const putJson = async (url: string, body: unknown, contentType = "application/json") => {
    const res = await fetch(url, {
      method: "PUT",
      headers: { "Content-Type": contentType },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`PUT ${url} -> ${res.status}`);
    return url;
  };

  const publishAcceptedCredential = async (payload: unknown) => {
    if (!VC_REGISTRY_BASE?.trim()) return;
    if (!activeWalletId) throw new Error("Selectează un wallet înainte de publicare.");

    let credential = extractEmbeddedCredential(payload);
    const candidateIds = extractCredentialIds(payload);
    let fetchedFromId = "";

    if (!credential && candidateIds.length) {
      fetchedFromId = candidateIds[0];
      const fetched = await walletApi.viewCredential(activeWalletId, fetchedFromId);
      credential = extractEmbeddedCredential(fetched) || (fetched as any)?.document || fetched;
    }

    if (credential && typeof credential === "string") {
      const decoded = decodeJwtPayload(credential);
      if (decoded && typeof decoded === "object" && (decoded as any).vc) credential = (decoded as any).vc;
      else if (decoded && typeof decoded === "object") credential = decoded;
      else {
        try {
          credential = JSON.parse(credential);
        } catch {
          throw new Error("VC-ul acceptat nu este JSON și nici payload JWT decodificabil.");
        }
      }
    }

    if (!credential || typeof credential !== "object") throw new Error("Nu am putut extrage VC-ul din răspuns.");

    const issuerRaw = typeof (credential as any).issuer === "string" ? (credential as any).issuer : (credential as any).issuer?.id || "";
    const subjectNode = Array.isArray((credential as any).credentialSubject)
      ? (credential as any).credentialSubject[0]
      : (credential as any).credentialSubject || {};
    const holderRaw = typeof subjectNode === "string" ? subjectNode : subjectNode?.id || "";
    const issuerShort = encodeURIComponent(didSuffix(issuerRaw));
    const holderShort = encodeURIComponent(didSuffix(holderRaw));
    const vcId = (credential as any).id || fetchedFromId || candidateIds[0] || "";
    const vcShort = encodeURIComponent(idSuffix(vcId));

    if (!issuerShort || !holderShort || !vcShort) {
      throw new Error("Lipsește issuer/holder/id pentru calea din nginx.");
    }

    const base = VC_REGISTRY_BASE.replace(/\/+$/, "");
    const vcUrl = `${base}/${issuerShort}/${holderShort}/${vcShort}.json`;
    const indexUrl = `${base}/${issuerShort}/allVC.json`;
    const revIdx = findRevocationIndex(credential);
    const mappedUrl = revIdx !== null && revIdx !== undefined ? `${vcUrl}#${revIdx}` : vcUrl;

    await putJson(vcUrl, credential, "application/json");

    let index: Record<string, string> = {};
    try {
      const current = await fetchJsonNoStore(indexUrl);
      if (current && typeof current === "object" && !Array.isArray(current)) index = current;
    } catch {
      // ignore missing index; we'll create it
    }
    index[vcId || vcShort] = mappedUrl;
    const sorted = Object.keys(index)
      .sort()
      .reduce((acc, key) => {
        acc[key] = index[key];
        return acc;
      }, {} as Record<string, string>);
    await putJson(indexUrl, JSON.stringify(sorted, null, 2));
  };

  useEffect(() => {
    if (!selectedDidFilter && dids.length) {
      const first = dids.find((d) => d.did || d.id);
      setSelectedDidFilter((first?.did || (first as any)?.id || "") as string);
    }
  }, [dids, selectedDidFilter]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      if (!credentials.length) {
        setStatusById({});
        return;
      }
      const entries = await Promise.all(
        credentials.map(async (cred): Promise<StatusEntry | null> => {
          const id = cred.id || "";
          if (!id) return null;
          const expiration = extractExpirationFromCred(cred);
          const expTime = expiration ? Date.parse(expiration) : NaN;
          const isExpired = Number.isFinite(expTime) ? expTime < Date.now() : false;
          const statusEntry = resolveStatusEntry(cred);
          if (!statusEntry) {
            return { id, status: isExpired ? "expired" : "valid" };
          }
          try {
            const res = await fetch(statusEntry.url, { cache: "no-store" });
            if (!res.ok) throw new Error();
            const json = await res.json();
            const encoded =
              json?.credentialSubject?.encodedList ||
              json?.credentialSubject?.bitstring ||
              json?.encodedList ||
              json?.bitstring;
            if (!encoded || typeof encoded !== "string") {
              return { id, status: isExpired ? "expired" : "valid" };
            }
            const bytes = await decodeEncodedList(encoded);
            const bit = decodeBitAt(bytes, statusEntry.index);
            if (bit === 1) return { id, status: "revoked" };
            return { id, status: isExpired ? "expired" : "valid" };
          } catch {
            return { id, status: isExpired ? "expired" : "valid" };
          }
        })
      );
      if (cancelled) return;
      const next: Record<string, VCStatus> = {};
      entries.forEach((e) => {
        if (e?.id) next[e.id] = e.status;
      });
      setStatusById(next);
    };
    run();
    return () => {
      cancelled = true;
    };
  }, [credentials]);

  const matchWithPresentationDefinition = async (pd: unknown) => {
    if (!activeWalletId) return;
    const matches = await walletApi.matchCredentialsForPresentationDefinition(activeWalletId, pd);
    const list = Array.isArray(matches)
      ? matches
      : Array.isArray((matches as any)?.matches)
      ? (matches as any).matches
      : [];
    setMatchingCreds(list as CredentialEntry[]);
  };

  const resolvePresentationReq = async () => {
    if (!activeWalletId || !presentationRequest.trim()) {
      setVerifyError("Completează wallet și presentationRequest.");
      return;
    }
    try {
      setVerifyError("");
      setLoadingResolve(true);
      setResolvedRequest(null);
      setPresentationDefinition(null);
      setPresentResult(null);
      setMatchingCreds([]);
      setSelectedCredIds([]);
      let pd: unknown = null;
      try {
        pd = await decodePresentationURL(presentationRequest.trim());
      } catch (e) {
        // fallback server resolve
        const data = await walletApi.resolvePresentationRequest(
          activeWalletId,
          presentationRequest.trim()
        );
        setResolvedRequest(data);
        pd = extractPresentationDefinition(data);
      }
      if (!pd) throw new Error("presentationDefinition nu a fost găsit în răspuns.");
      setPresentationDefinition(pd);
      setLoadingMatch(true);
      await matchWithPresentationDefinition(pd);
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingResolve(false);
      setLoadingMatch(false);
    }
  };

  // matching se face automat dupa resolve

  const toggleCredentialSelect = (id: string) => {
    setSelectedCredIds((prev) =>
      prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]
    );
  };

  const presentCredentials = async () => {
    if (!activeWalletId || !holderDid.trim() || !presentationRequest.trim() || selectedCredIds.length === 0) {
      setVerifyError("Completează wallet, DID, presentationRequest și selectează credentiale.");
      return;
    }
    try {
      setVerifyError("");
      setLoadingPresent(true);
      setPresentResult(null);
      const selectedCreds = matchingCreds.filter((cred) => selectedCredIds.includes(cred.id));
      const res = await walletApi.usePresentationRequest(activeWalletId, {
        did: holderDid.trim(),
        presentationRequest: presentationRequest.trim(),
        selectedCredentials: selectedCredIds,
      });
      setPresentResult(res);
      toast({ title: "Presentation sent", description: "Verifier session updated." });
    } catch (e) {
      setVerifyError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingPresent(false);
    }
  };

  const handleKeyAction = async (action: "meta" | "load" | "export" | "delete" | "remove") => {
    if (!activeWalletId || !keyActionTarget) {
      toast({ variant: "destructive", title: "No wallet/key detected" });
      return;
    }
    const keyId = formatKeyLabel(keyActionTarget);
    if (!keyId || keyId === "Unknown key") {
      toast({ variant: "destructive", title: "Key ID missing" });
      return;
    }
    setKeyActionBusy(true);
    setKeyActionResult("");
    try {
      if (action === "meta") {
        const data = await walletApi.keyMeta(activeWalletId, keyId);
        setKeyActionResult(JSON.stringify(data, null, 2));
      } else if (action === "load") {
        const data = await walletApi.keyLoad(activeWalletId, keyId);
        setKeyActionResult(JSON.stringify(data, null, 2));
      } else if (action === "export") {
        const blob = await walletApi.keyExport(activeWalletId, keyId);
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `key-${keyId}.json`;
        a.click();
        URL.revokeObjectURL(url);
        toast({ title: "Key exported", description: keyId });
      } else if (action === "delete") {
        await walletApi.keyDelete(activeWalletId, keyId);
        toast({ title: "Key deleted", description: keyId });
        setKeyDialogOpen(false);
        keysQuery.refetch();
      } else if (action === "remove") {
        await walletApi.keyRemoveRef(activeWalletId, keyId);
        toast({ title: "Reference removed", description: keyId });
        setKeyDialogOpen(false);
        keysQuery.refetch();
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : "Action failed";
      toast({ variant: "destructive", title: "Error", description: message });
    } finally {
      setKeyActionBusy(false);
    }
  };

  const extractPresentationDefinition = (payload: unknown) => {
    if (!payload || typeof payload !== "object") return null;
    const obj = payload as any;
    return (
      obj.presentationDefinition ||
      obj.presentation_definition ||
      obj.presentation_definition ||
      obj?.vp_token?.presentationDefinition ||
      obj?.vp_token?.presentation_definition ||
      obj?.presentationRequest?.presentationDefinition ||
      obj?.requestObject?.presentation_definition ||
      null
    );
  };

  const decodePresentationURL = async (offerURL: string) => {
    const url = new URL(offerURL);
    const pdUri = url.searchParams.get("presentation_definition_uri");
    const stateParam = url.searchParams.get("state") || "";
    let lastErr: unknown = null;

    if (pdUri) {
      try {
        const res = await fetch(pdUri, { cache: "no-store", credentials: "include" });
        if (!res.ok) throw new Error(`GET ${pdUri} -> ${res.status}`);
        const txt = await res.text();
        return JSON.parse(txt);
      } catch (e) {
        lastErr = e;
      }
    }

    if (stateParam && VERIFIER_API_BASE) {
      const sessionUrl = joinUrl(VERIFIER_API_BASE, `/openid4vc/session/${encodeURIComponent(stateParam)}`);
      const res = await fetch(sessionUrl, { cache: "no-store", credentials: "include" });
      if (!res.ok) {
        throw new Error(
          `Nu am putut obține presentationDefinition. GET ${sessionUrl} -> ${res.status}${
            lastErr ? ` | PD fetch: ${String((lastErr as Error)?.message || lastErr)}` : ""
          }`
        );
      }
      const data = await res.json();
      const pd = extractPresentationDefinition(data);
      if (pd) return pd;
      throw new Error("Session nu conține presentationDefinition.");
    }

    throw lastErr || new Error("presentation_definition_uri lipsește");
  };

  const handleDidAction = async (action: "view" | "delete") => {
    if (!activeWalletId || !didActionTarget) {
      toast({ variant: "destructive", title: "No wallet/DID detected" });
      return;
    }
    const didVal = didActionTarget.did || didActionTarget.id || "";
    if (!didVal) {
      toast({ variant: "destructive", title: "DID missing" });
      return;
    }
    setDidActionBusy(true);
    setDidActionResult("");
    try {
      if (action === "view") {
        const data = await walletApi.didView(activeWalletId, didVal);
        setDidActionResult(JSON.stringify(data, null, 2));
      } else if (action === "delete") {
        await walletApi.didDelete(activeWalletId, didVal);
        const map = loadDidKeyMap();
        const walletMap = map[activeWalletId] || {};
        const linkedKeys = walletMap[didVal] || [];
        for (const keyId of linkedKeys) {
          try {
            await walletApi.keyDelete(activeWalletId, keyId);
          } catch (err) {
            console.warn("Key delete failed", keyId, err);
          }
        }
        delete walletMap[didVal];
        map[activeWalletId] = walletMap;
        saveDidKeyMap(map);
        toast({ title: "DID deleted", description: didVal });
        setDidDialogOpen(false);
        didsQuery.refetch();
        keysQuery.refetch();
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : "Action failed";
      toast({ variant: "destructive", title: "Error", description: message });
    } finally {
      setDidActionBusy(false);
    }
  };

  const handleCredentialAction = async (action: "view" | "delete") => {
    if (!activeWalletId || !credActionTarget) {
      toast({ variant: "destructive", title: "No wallet/credential detected" });
      return;
    }
    const credId = credActionTarget.id || "";
    if (!credId) {
      toast({ variant: "destructive", title: "Credential ID missing" });
      return;
    }
    setCredActionBusy(true);
    if (action === "view") setCredActionResult("");
    try {
      if (action === "view") {
        const data = await walletApi.viewCredential(activeWalletId, credId);
        setCredDetail(data);
        setCredActionResult(JSON.stringify(data, null, 2));
      } else if (action === "delete") {
        await walletApi.deleteCredential(activeWalletId, credId);
        toast({ title: "Credential deleted", description: credId });
        setCredDialogOpen(false);
        credentialsQuery.refetch();
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : "Action failed";
      toast({ variant: "destructive", title: "Error", description: message });
    } finally {
      setCredActionBusy(false);
    }
  };

  const loadCredentialDetail = async (credId: string) => {
    if (!activeWalletId || !credId) return;
    setCredDetailLoading(true);
    setCredDetail(null);
    try {
      const data = await walletApi.viewCredential(activeWalletId, credId);
      setCredDetail(data);
    } catch (e) {
      const message = e instanceof Error ? e.message : "Could not load credential";
      toast({ variant: "destructive", title: "Error", description: message });
    } finally {
      setCredDetailLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied",
      description: "Copied to clipboard",
    });
  };

  return (
    <MainLayout>
      <PageHeader
        icon={Wallet}
        title="My Wallet"
        description="Manage your decentralized identifiers, keys, and verifiable credentials"
      >
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <Label className="text-xs text-muted-foreground">Active wallet</Label>
            <div className="mt-2 p-3 rounded-lg border border-border/60 bg-muted/30 flex items-center justify-between">
              <div>
                <p className="text-sm font-mono break-all">
                  {activeWalletId || (wallets.isLoading || wallets.isFetching ? "Loading wallet..." : "No wallet found")}
                </p>
                {wallets.data?.[0]?.permission && (
                  <p className="text-xs text-muted-foreground">
                    Permission: {wallets.data[0].permission}
                  </p>
                )}
              </div>
              {activeWalletId && (
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => copyToClipboard(activeWalletId)}
                  aria-label="Copy wallet id"
                >
                  <Copy className="w-4 h-4" />
                </Button>
              )}
            </div>
          </div>
          <Dialog open={receiveOfferOpen} onOpenChange={setReceiveOfferOpen}>
            <DialogTrigger asChild>
              <Button variant="gradient" className="whitespace-nowrap">
                <QrCode className="w-4 h-4 mr-2" />
                Receive Credential
              </Button>
            </DialogTrigger>
            <DialogContent className="max-w-xl w-full">
              <DialogHeader>
                <DialogTitle>Receive Credential Offer</DialogTitle>
                <DialogDescription>
                  Paste the credential offer URL or scan the QR code
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-4 mt-4">
                <div className="space-y-2">
                  <Label>Holder DID</Label>
                  <Select value={holderDid} onValueChange={setHolderDid}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select DID" />
                    </SelectTrigger>
                    <SelectContent>
                      {dids.map((d) => {
                        const val = d.did || d.id || "";
                        return (
                          <SelectItem key={val} value={val} className="truncate max-w-[560px]">
                            <span className="truncate inline-block max-w-[520px]" title={val}>
                              {formatDidLabel(val)}
                            </span>
                          </SelectItem>
                        );
                      })}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Credential Offer URL</Label>
                  <Input
                    placeholder="openid-credential-offer://..."
                    value={credentialOffer}
                    onChange={(e) => setCredentialOffer(e.target.value)}
                  />
                  {availableOffers.length > 0 && (
                    <div className="space-y-2">
                      <Label className="text-xs text-muted-foreground">Available offers</Label>
                      <div className="flex flex-col gap-2">
                        {availableOffers.map((offer) => (
                          <Button
                            key={`${offer.offerUrl}-${offer.createdAt}`}
                            variant="outline"
                            size="sm"
                            onClick={() => handleSelectOffer(offer)}
                            className="justify-start"
                          >
                            {offer.label || "Credential offer"}
                          </Button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <Button
                  onClick={async () => {
                    if (!activeWalletId) {
                      toast({ variant: "destructive", title: "No wallet detected" });
                      return;
                    }
                    if (!credentialOffer.trim()) {
                      toast({ variant: "destructive", title: "Offer required" });
                      return;
                    }
                    try {
                      const data = await acceptOffer.mutateAsync({
                        offer: credentialOffer.trim(),
                        did: holderDid || undefined,
                      });
                      try {
                        await publishAcceptedCredential(data);
                      } catch (publishErr) {
                        toast({
                          variant: "destructive",
                          title: "Registry publish failed",
                          description: publishErr instanceof Error ? publishErr.message : String(publishErr),
                        });
                      }
                      toast({
                        title: "Credential received",
                        description: "The credential offer has been processed.",
                      });
                      setReceiveOfferOpen(false);
                      setCredentialOffer("");
                    } catch (e) {
                      const message = e instanceof Error ? e.message : "Offer processing failed.";
                      toast({ variant: "destructive", title: "Error", description: message });
                    }
                  }}
                  className="w-full"
                  disabled={acceptOffer.isPending}
                >
                  {acceptOffer.isPending ? "Processing..." : "Process Offer"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </PageHeader>

      <div className="container mx-auto px-4 py-4">
        {sessionError && (
          <div className="mb-4 text-sm text-destructive">
            Session check failed: {sessionError}
          </div>
        )}
        {walletsError && (
          <div className="mb-4 text-sm text-destructive">
            Cannot load wallets: {walletsError}
          </div>
        )}
      </div>

      <div className="container mx-auto px-4 py-8">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <StatCard icon={Wallet} label="DIDs" value={dids.length} />
          <StatCard icon={Key} label="Keys" value={keys.length} />
          <StatCard icon={FileCheck} label="Credentials" value={credentials.length} />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* DIDs Section */}
          <DataCard
            title="Decentralized Identifiers"
            description="Your DIDs for identity verification"
            actions={
              <Dialog open={createDIDOpen} onOpenChange={setCreateDIDOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Plus className="w-4 h-4 mr-1" />
                    Create DID
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create New DID</DialogTitle>
                    <DialogDescription>
                      Generate a new decentralized identifier
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 mt-4">
                    <div className="space-y-2">
                      <Label>DID Method</Label>
                      <Select value={didMethod} onValueChange={setDidMethod}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="did:ebsi">did:ebsi</SelectItem>
                          <SelectItem value="did:key">did:key</SelectItem>
                          <SelectItem value="did:web">did:web</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Button
                      onClick={async () => {
                        if (!activeWalletId) {
                          toast({ variant: "destructive", title: "No wallet detected" });
                          return;
                        }
                        const beforeKeys = new Set(getKeyIds(keys));
                        const beforeDids = new Set(getDidIds(dids));
                        const typeMap: Record<string, "ebsi" | "key" | "web"> = {
                          "did:ebsi": "ebsi",
                          "did:key": "key",
                          "did:web": "web",
                        };
                        const type = typeMap[didMethod] || "key";
                        try {
                          await createDid.mutateAsync({ type });
                          const didsResult = await didsQuery.refetch();
                          const map = loadDidKeyMap();
                          const walletMap = map[activeWalletId] || {};
                          const newDids = getDidIds((didsResult.data as DidEntry[]) || []).filter(
                            (d) => !beforeDids.has(d)
                          );
                          const createdDid = newDids[0];
                          const keysResult = await keysQuery.refetch();
                          const newKeys = getKeyIds((keysResult.data as KeyEntry[]) || []).filter(
                            (k) => !beforeKeys.has(k)
                          );
                          if (createdDid && newKeys.length) {
                            walletMap[createdDid] = Array.from(newKeys);
                            map[activeWalletId] = walletMap;
                            saveDidKeyMap(map);
                          }
                          toast({
                            title: "DID created",
                            description: "Your new DID has been generated successfully.",
                          });
                          setCreateDIDOpen(false);
                        } catch (e) {
                          const message = e instanceof Error ? e.message : "Failed to create DID.";
                          toast({ variant: "destructive", title: "Error", description: message });
                        }
                      }}
                      className="w-full"
                      disabled={createDid.isPending}
                    >
                      {createDid.isPending ? "Generating..." : "Generate DID"}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            }
          >
            {dids.length > 0 ? (
              <div className="space-y-3">
                {dids.map((did) => (
                    <div
                      key={did.did || did.id}
                      className="flex items-center justify-between p-4 bg-muted/30 rounded-lg border border-border/50 cursor-pointer hover:border-primary/40"
                      onClick={() => {
                        setDidActionTarget(did);
                        setDidActionResult("");
                        setDidDialogOpen(true);
                      }}
                    >
                      <div>
                        <p
                          className="font-mono text-sm truncate max-w-[260px]"
                          title={did.did || did.id}
                        >
                          {did.did || did.id}
                        </p>
                        <p className="text-xs text-muted-foreground mt-1">
                          Method: {did.method || "unknown"}
                        </p>
                      </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      onClick={() => copyToClipboard(did.did || did.id || "")}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                icon={Wallet}
                title="No DIDs yet"
                description="Create your first decentralized identifier"
                actionLabel="Create DID"
                onAction={() => setCreateDIDOpen(true)}
              />
            )}
          </DataCard>

          {/* Keys Section */}
          <DataCard
            title="Cryptographic Keys"
            description="Keys for signing and verification"
            actions={
              <Dialog open={createKeyOpen} onOpenChange={setCreateKeyOpen}>
                <DialogTrigger asChild>
                  <Button variant="outline" size="sm">
                    <Plus className="w-4 h-4 mr-1" />
                    Create Key
                  </Button>
                </DialogTrigger>
                <DialogContent>
                  <DialogHeader>
                    <DialogTitle>Create New Key</DialogTitle>
                    <DialogDescription>
                      Generate a new cryptographic key pair
                    </DialogDescription>
                  </DialogHeader>
                  <div className="space-y-4 mt-4">
                    <div className="space-y-2">
                      <Label>Key Type</Label>
                      <Select value={keyType} onValueChange={setKeyType}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="Ed25519">Ed25519</SelectItem>
                          <SelectItem value="secp256k1">secp256k1</SelectItem>
                          <SelectItem value="RSA">RSA</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <Button
                      onClick={async () => {
                        if (!activeWalletId) {
                          toast({ variant: "destructive", title: "No wallet detected" });
                          return;
                        }
                        try {
                          await generateKey.mutateAsync({ keyType });
                          toast({
                            title: "Key created",
                            description: "Your new cryptographic key has been generated.",
                          });
                          setCreateKeyOpen(false);
                        } catch (e) {
                          const message = e instanceof Error ? e.message : "Failed to create key.";
                          toast({ variant: "destructive", title: "Error", description: message });
                        }
                      }}
                      className="w-full"
                      disabled={generateKey.isPending}
                    >
                      {generateKey.isPending ? "Generating..." : "Generate Key"}
                    </Button>
                  </div>
                </DialogContent>
              </Dialog>
            }
          >
            {keys.length > 0 ? (
              <div className="space-y-3">
                {keys.map((key) => {
                  const keyLabel = formatKeyLabel(key);
                  const algorithm = key.algorithm || key.keyType || (typeof key === "object" && (key as Record<string, unknown>).alg ? String((key as Record<string, unknown>).alg) : "Unknown");
                  return (
                    <div
                      key={keyLabel}
                      className="flex items-center justify-between p-4 bg-muted/30 rounded-lg border border-border/50 cursor-pointer hover:border-primary/40"
                      onClick={() => {
                        setKeyActionTarget(key);
                        setKeyActionResult("");
                        setKeyDialogOpen(true);
                      }}
                    >
                      <div className="flex items-center gap-3">
                        <div className="w-10 h-10 rounded-lg bg-accent/10 flex items-center justify-center">
                          <Key className="w-5 h-5 text-accent" />
                        </div>
                        <div>
                          <p className="font-medium truncate max-w-[360px]" title={keyLabel}>
                            {keyLabel}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {algorithm} {key.createdAt ? `• ${key.createdAt}` : ""}
                          </p>
                        </div>
                      </div>
                      <Button variant="ghost" size="icon">
                        <RefreshCw className="w-4 h-4" />
                      </Button>
                    </div>
                  );
                })}
              </div>
            ) : (
              <EmptyState
                icon={Key}
                title="No keys yet"
                description="Generate your first cryptographic key"
                actionLabel="Create Key"
                onAction={() => setCreateKeyOpen(true)}
              />
            )}
          </DataCard>
        </div>

        {/* Credentials Section */}
        <div className="mt-6">
          <DataCard
            title="Verifiable Credentials"
            description="Your received and stored credentials"
          >
            <div className="space-y-2 mb-4">
              <Label>Select holder DID</Label>
              <Select value={selectedDidFilter} onValueChange={setSelectedDidFilter}>
                <SelectTrigger className="max-w-xl">
                  <SelectValue placeholder="Select DID" />
                </SelectTrigger>
                <SelectContent>
                  {dids.map((d) => {
                    const val = d.did || d.id || "";
                    return (
                      <SelectItem key={val} value={val}>
                        {val}
                      </SelectItem>
                    );
                  })}
                </SelectContent>
              </Select>
            </div>
            {credentials.length > 0 ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {credentials
                  .filter((cred) => {
                    if (!selectedDidFilter) return true;
                    const holder = extractHolderDid(cred);
                    return holder === selectedDidFilter;
                  })
                  .map((cred) => {
                  const typeValue = extractTypeLabel(cred, cred);
                  const issuer = extractIssuer(cred);
                  const issuedAt = extractExpirationFromCred(cred);
                  const status = statusById[String(cred.id || "")] || "valid";
                  return (
                    <CredentialCard
                      key={cred.id || typeValue + issuer}
                      type={typeValue}
                      issuer={issuer}
                      issuedAt={issuedAt}
                      status={status}
                      onClick={() => {
                        setCredActionTarget(cred);
                        setCredActionResult("");
                        setCredDetail(null);
                        setCredDetailLoading(false);
                        setCredDialogOpen(true);
                        if (cred.id) loadCredentialDetail(cred.id);
                      }}
                    />
                  );
                })}
              </div>
            ) : (
              <EmptyState
                icon={FileCheck}
                title="No credentials yet"
                description="Receive your first verifiable credential"
                actionLabel="Receive Credential"
                onAction={() => setReceiveOfferOpen(true)}
              />
            )}
          </DataCard>
        </div>
      </div>

      <div className="container mx-auto px-4 pb-10">
        <DataCard
          title="Verification Requests"
          description="Răspunde la presentationRequest"
        >
          <div className="grid md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>Presentation request URL</Label>
              <Input
                value={presentationRequest}
                onChange={(e) => setPresentationRequest(e.target.value)}
                placeholder="openid4vp://authorize?presentation_definition_uri=..."
              />
            </div>
                <div className="space-y-2">
                  <Label>Holder DID</Label>
                  <Select value={holderDid} onValueChange={setHolderDid}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select DID" />
                    </SelectTrigger>
                    <SelectContent>
                      {dids.map((d) => {
                        const val = d.did || d.id || "";
                        return (
                          <SelectItem key={val} value={val} className="truncate max-w-[560px]">
                            <span className="truncate inline-block max-w-[520px]" title={val}>
                              {formatDidLabel(val)}
                            </span>
                          </SelectItem>
                        );
                      })}
                    </SelectContent>
                  </Select>
                </div>
          </div>

          <div className="flex gap-2 mt-4 flex-wrap">
            <Button onClick={resolvePresentationReq} disabled={loadingResolve}>
              <RefreshCw className="w-4 h-4 mr-2" />
              {loadingResolve ? "Resolving..." : "Resolve request"}
            </Button>
          </div>

          {verifyError && (
            <p className="text-destructive text-sm mt-3">{verifyError}</p>
          )}

          {presentationDefinition && (
            <div className="mt-4">
              <Label className="text-xs text-muted-foreground">presentationDefinition</Label>
              <pre className="bg-muted/50 border border-border/60 rounded-lg p-3 text-xs max-h-64 overflow-auto whitespace-pre-wrap break-all">
                {JSON.stringify(presentationDefinition, null, 2)}
              </pre>
            </div>
          )}

          {matchingCreds.length > 0 && (
            <div className="mt-4 space-y-2">
              <Label>Credentials that match</Label>
              <div className="space-y-2">
                {matchingCreds
                  .filter((cred) => {
                    if (!holderDid) return true;
                    const holder = extractHolderDid(cred);
                    return holder === holderDid;
                  })
                  .map((cred) => {
                  const id = (cred as any)?.id || (cred as any)?.credentialId || "";
                  const typeLabel = extractTypeLabel(cred);
                  const issuer = extractIssuer(cred);
                  return (
                    <div
                      key={id}
                      className="flex items-center justify-between border border-border/60 rounded-md px-3 py-2"
                    >
                      <div>
                        <p className="font-medium">{typeLabel}</p>
                        <p className="text-xs text-muted-foreground">{issuer}</p>
                        <p className="text-xs text-muted-foreground font-mono break-all">{id}</p>
                      </div>
                      <Button
                        size="sm"
                        variant={selectedCredIds.includes(id) ? "default" : "outline"}
                        onClick={() => toggleCredentialSelect(id)}
                      >
                        {selectedCredIds.includes(id) ? "Selected" : "Select"}
                      </Button>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className="flex gap-2 mt-4">
            <Button onClick={presentCredentials} disabled={loadingPresent || selectedCredIds.length === 0}>
              <Send className="w-4 h-4 mr-2" />
              {loadingPresent ? "Sending..." : "Present credentials"}
            </Button>
            <Button variant="outline" onClick={() => {setPresentResult(null); setSelectedCredIds([]);}}>
              Clear
            </Button>
          </div>

          {presentResult && (
            <div className="mt-4">
              <Label className="text-xs text-muted-foreground">Presentation result</Label>
              <pre className="bg-muted/50 border border-border/60 rounded-lg p-3 text-xs max-h-64 overflow-auto whitespace-pre-wrap break-all">
                {JSON.stringify(presentResult, null, 2)}
              </pre>
            </div>
          )}
        </DataCard>
      </div>

      {/* Key actions dialog */}
      <Dialog open={keyDialogOpen} onOpenChange={setKeyDialogOpen}>
        <DialogContent className="max-w-4xl w-full">
          <DialogHeader>
            <DialogTitle>Key actions</DialogTitle>
            <DialogDescription>
              {keyActionTarget ? formatKeyLabel(keyActionTarget) : "Select a key to see actions"}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" disabled={keyActionBusy} onClick={() => handleKeyAction("meta")}>
                Meta
              </Button>
              <Button size="sm" variant="outline" disabled={keyActionBusy} onClick={() => handleKeyAction("load")}>
                Load
              </Button>
              <Button size="sm" variant="outline" disabled={keyActionBusy} onClick={() => handleKeyAction("export")}>
                Export
              </Button>
              <Button size="sm" variant="destructive" disabled={keyActionBusy} onClick={() => handleKeyAction("delete")}>
                Delete
              </Button>
              <Button size="sm" variant="outline" disabled={keyActionBusy} onClick={() => handleKeyAction("remove")}>
                Remove ref
              </Button>
            </div>
            {keyActionResult && (
              <pre className="bg-muted/50 border border-border/60 rounded-lg p-3 text-xs max-h-[60vh] overflow-auto whitespace-pre-wrap break-all w-full">
                {keyActionResult}
              </pre>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* DID actions dialog */}
      <Dialog open={didDialogOpen} onOpenChange={setDidDialogOpen}>
        <DialogContent className="max-w-4xl w-full">
          <DialogHeader>
            <DialogTitle>DID actions</DialogTitle>
            <DialogDescription>
              {didActionTarget ? (didActionTarget.did || didActionTarget.id) : "Select a DID to see actions"}
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" disabled={didActionBusy} onClick={() => handleDidAction("view")}>
                View
              </Button>
              <Button size="sm" variant="destructive" disabled={didActionBusy} onClick={() => handleDidAction("delete")}>
                Delete
              </Button>
            </div>
            {didActionResult && (
              <pre className="bg-muted/50 border border-border/60 rounded-lg p-3 text-xs max-h-[60vh] overflow-auto whitespace-pre-wrap break-all w-full">
                {didActionResult}
              </pre>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Credential actions dialog */}
      <Dialog open={credDialogOpen} onOpenChange={setCredDialogOpen}>
        <DialogContent className="max-w-4xl w-full">
          <DialogHeader>
            <DialogTitle>Credential actions</DialogTitle>
            <DialogDescription>
              {credActionTarget ? (Array.isArray(credActionTarget.type) ? credActionTarget.type.join(", ") : credActionTarget.type || credActionTarget.id) : "Select a credential"}
            </DialogDescription>
          </DialogHeader>
          {credActionTarget && (
            <div className="space-y-4">
              <div className="grid md:grid-cols-3 gap-4 p-3 rounded-lg bg-muted/30 border border-border/60">
                <div>
                  <p className="text-sm text-muted-foreground">Issuer</p>
                  <p className="font-medium break-words">{extractIssuer(credActionTarget, credDetail)}</p>
                </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Issued at</p>
                    <p className="font-medium break-words">{extractIssuedAt(credActionTarget, credDetail)}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Expires</p>
                    <p className="font-medium break-words">{extractExpiration(credActionTarget, credDetail)}</p>
                  </div>
                </div>

              {/* Credential Subject pretty print */}
              <div className="space-y-2">
                <p className="text-sm font-semibold">Credential Subject</p>
                <div className="grid gap-2 md:grid-cols-2">
                  {credDetailLoading ? (
                    <div className="text-sm text-muted-foreground">Loading credential...</div>
                  ) : (
                    (() => {
                      const entries = extractSubjectEntries(credActionTarget, credDetail);
                      return entries.length ? (
                        entries.map((entry, idx) => (
                          <div key={`${entry.key}-${idx}`} className="p-3 rounded-lg bg-muted/30 border border-border/60">
                            <p className="text-xs uppercase text-muted-foreground tracking-wide">{entry.key}</p>
                            <p className="text-sm font-medium break-words">{entry.value}</p>
                          </div>
                        ))
                      ) : (
                        <div className="text-sm text-muted-foreground">No credentialSubject provided.</div>
                      );
                    })()
                  )}
                </div>
              </div>

              <div className="flex flex-wrap gap-2">
                <Button size="sm" variant="outline" disabled={credActionBusy} onClick={() => handleCredentialAction("view")}>
                  View JSON
                </Button>
                <Button size="sm" variant="destructive" disabled={credActionBusy} onClick={() => handleCredentialAction("delete")}>
                  Delete
                </Button>
              </div>
              {credActionResult && (
                <pre className="bg-muted/50 border border-border/60 rounded-lg p-3 text-xs max-h-[60vh] overflow-auto whitespace-pre-wrap break-all w-full">
                  {credActionResult}
                </pre>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
