import { useCallback, useEffect, useMemo, useState } from "react";
import { BrowserProvider, Contract, Eip1193Provider, isHexString, keccak256, toUtf8Bytes } from "ethers";
import { FileCheck, Plus, Send, Eye, Users, Clock, CheckCircle, RefreshCw } from "lucide-react";
import { MainLayout } from "@/components/layout/MainLayout";
import { PageHeader } from "@/components/shared/PageHeader";
import { StatCard } from "@/components/shared/StatCard";
import { DataCard } from "@/components/shared/DataCard";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
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
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { usePrimaryWallet, useWalletResources } from "@/hooks/useWalletApi";
import { walletApi } from "@/lib/wallet-api";
import { issueJwtCredential } from "@/lib/issuer-api";
import { CredentialEntry } from "@/types/wallet";
import { formatISO } from "date-fns";
import { canonicalize } from "json-canonicalize";
import statusrAbi from "../../smart_contracts/abi_StatusR.json";

type SchemaField = { name: string; required: boolean };

export default function IssuerPage() {
  const STATUSR_CONTRACT_ADDRESS = import.meta.env.VITE_STATUSR_CONTRACT_ADDRESS as string | undefined;
  const [createOfferOpen, setCreateOfferOpen] = useState(false);
  const [walletId, setWalletId] = useState("");
  const [issuerDid, setIssuerDid] = useState("");
  const [issuerKeyId, setIssuerKeyId] = useState("");
  const [credentialJson, setCredentialJson] = useState("");
  const [sessionTtl, setSessionTtl] = useState("");
  const [issueResult, setIssueResult] = useState<unknown>(null);
  const [issuedCredentials, setIssuedCredentials] = useState<CredentialEntry[]>([]);
  const [loadingIssue, setLoadingIssue] = useState(false);
  const [issuedLoading, setIssuedLoading] = useState(false);
  const [credentialId, setCredentialId] = useState("");
  const [credentialConfigurationId, setCredentialConfigurationId] = useState("UniversityDegree_jwt_vc_json");
  const [credentialTypes, setCredentialTypes] = useState("VerifiableCredential,UniversityDegreeCredential");
  const [subjectId, setSubjectId] = useState("");
  const [subjectFields, setSubjectFields] = useState<{ key: string; value: string }[]>([]);
  const toInputDateTime = (iso?: string) => {
    if (!iso) return "";
    const d = new Date(iso);
    const off = d.getTimezoneOffset();
    const local = new Date(d.getTime() - off * 60 * 1000);
    return local.toISOString().slice(0, 16);
  };
  const addDaysIso = (iso: string, days: number) => {
    const base = iso ? new Date(iso) : new Date();
    return new Date(base.getTime() + days * 24 * 60 * 60 * 1000).toISOString();
  };

  const [issuanceDate, setIssuanceDate] = useState(() => toInputDateTime(new Date().toISOString()));
  const [expirationDate, setExpirationDate] = useState(() =>
    toInputDateTime(addDaysIso(new Date().toISOString(), 365))
  );
  const [schemaUrl, setSchemaUrl] = useState("");
  const [schemaFields, setSchemaFields] = useState<SchemaField[]>([]);
  const [schemaLoading, setSchemaLoading] = useState(false);
  const [schemaError, setSchemaError] = useState("");
  const [allowedSchemas, setAllowedSchemas] = useState<string[]>([]);
  const [allowedCredDefs, setAllowedCredDefs] = useState<string[]>([]);
  const [allowedError, setAllowedError] = useState("");
  const [credDefUrl, setCredDefUrl] = useState("");
  const [statusListUrl, setStatusListUrl] = useState("");
  const [statusListIndex, setStatusListIndex] = useState("");
  const [statusSize, setStatusSize] = useState("131072");
  const [statusPurpose, setStatusPurpose] = useState("revocation");
  const [issuerKeyMeta, setIssuerKeyMeta] = useState<unknown>(null);
  const [issuerKeyError, setIssuerKeyError] = useState("");
  const [issuerKeyJwk, setIssuerKeyJwk] = useState<Record<string, unknown> | null>(null);
  const [statusDialogOpen, setStatusDialogOpen] = useState(false);
  const [statusTarget, setStatusTarget] = useState<CredentialEntry | null>(null);
  const [statusInfo, setStatusInfo] = useState<{ url: string; index: number; bit: number | null } | null>(null);
  const [statusLoading, setStatusLoading] = useState(false);
  const [statusError, setStatusError] = useState("");
  const [statusById, setStatusById] = useState<Record<string, string>>({});
  const [selectedIssuerDids, setSelectedIssuerDids] = useState<string[]>([]);
  const [issuerRegistryVcs, setIssuerRegistryVcs] = useState<CredentialEntry[]>([]);
  const [issuerRegistryLoading, setIssuerRegistryLoading] = useState(false);
  const [issuerRegistryError, setIssuerRegistryError] = useState("");

  const generateCredentialId = () => {
    const template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx";
    const uuid =
      typeof crypto !== "undefined" && typeof (crypto as any).randomUUID === "function"
        ? (crypto as any).randomUUID()
        : template.replace(/[xy]/g, (c) => {
            const r = (Math.random() * 16) | 0;
            const v = c === "x" ? r : (r & 0x3) | 0x8;
            return v.toString(16);
          });
    return `urn:uuid:${uuid}`;
  };

  const base64UrlToBytes = (input: string) => {
    const norm = input.replace(/-/g, "+").replace(/_/g, "/");
    const pad = norm.length % 4 === 0 ? "" : "=".repeat(4 - (norm.length % 4));
    const bin = atob(norm + pad);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  };

  const bytesToBase64Url = (bytes: Uint8Array) => {
    let bin = "";
    bytes.forEach((b) => (bin += String.fromCharCode(b)));
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const decodeEncodedList = async (encoded: string) => {
    const raw = base64UrlToBytes(encoded);
    if (typeof DecompressionStream === "undefined") {
      return { bytes: raw, compressed: false };
    }
    try {
      const ds = new DecompressionStream("gzip");
      const stream = new Response(new Blob([raw]).stream().pipeThrough(ds));
      const buf = await stream.arrayBuffer();
      return { bytes: new Uint8Array(buf), compressed: true };
    } catch {
      return { bytes: raw, compressed: false };
    }
  };

  const encodeEncodedList = async (bytes: Uint8Array, compressed: boolean) => {
    if (!compressed || typeof CompressionStream === "undefined") {
      return bytesToBase64Url(bytes);
    }
    const cs = new CompressionStream("gzip");
    const stream = new Response(new Blob([bytes.slice().buffer]).stream().pipeThrough(cs));
    const buf = await stream.arrayBuffer();
    return bytesToBase64Url(new Uint8Array(buf));
  };

  const putJSON = async (url: string, body: unknown, contentType = "application/json") => {
    const res = await fetch(url, {
      method: "PUT",
      headers: { "Content-Type": contentType },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    if (!res.ok) throw new Error(`PUT ${url} -> ${res.status}`);
    return url;
  };

  const canonicalKeccak = (obj: unknown) => {
    const txt = canonicalize(obj);
    return keccak256(toUtf8Bytes(txt));
  };

  const normalizeHash32 = (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return "";
    const normalized = trimmed.startsWith("0x") ? trimmed : `0x${trimmed}`;
    return normalized.toLowerCase();
  };

  const getProvider = () => {
    const ethereum = (window as { ethereum?: Eip1193Provider }).ethereum;
    if (!ethereum) {
      throw new Error("No wallet detected. Install MetaMask or another EVM wallet.");
    }
    return new BrowserProvider(ethereum);
  };

  const getStatusRContract = async () => {
    if (!STATUSR_CONTRACT_ADDRESS || STATUSR_CONTRACT_ADDRESS === "0x0000000000000000000000000000000000000000") {
      throw new Error("Missing VITE_STATUSR_CONTRACT_ADDRESS in .env.");
    }
    const provider = getProvider();
    const signer = await provider.getSigner();
    return new Contract(STATUSR_CONTRACT_ADDRESS, statusrAbi, signer);
  };

  const decodeBitAt = (bytes: Uint8Array, index: number) => {
    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    if (byteIndex >= bytes.length || index < 0) return null;
    const byte = bytes[byteIndex];
    return (byte >> (7 - bitIndex)) & 1; // MSB-first
  };

  const setBitAt = (bytes: Uint8Array, index: number, value: 0 | 1) => {
    const byteIndex = Math.floor(index / 8);
    const bitIndex = index % 8;
    if (byteIndex >= bytes.length || index < 0) return bytes;
    const mask = 1 << (7 - bitIndex);
    const clone = new Uint8Array(bytes);
    if (value === 1) clone[byteIndex] = clone[byteIndex] | mask;
    else clone[byteIndex] = clone[byteIndex] & ~mask;
    return clone;
  };

  const resolveStatusEntry = (cred: any) => {
    const pick = (obj: any) => {
      if (!obj || typeof obj !== "object") return null;
      return (
        obj.credentialStatus ||
        obj.credential_status ||
        obj.status ||
        obj?.credential?.credentialStatus ||
        obj?.result?.credentialStatus ||
        null
      );
    };
    const status = pick(cred) || pick(cred.parsedDocument);
    if (!status || typeof status !== "object") return null;
    const urlRaw = status.statusListCredential || status.id;
    if (!urlRaw) return null;
    const [urlPart, fragment] = String(urlRaw).split("#");
    const indexRaw = status.statusListIndex || status.index || status.idx || fragment;
    const idxNum = Number(indexRaw);
    if (!Number.isFinite(idxNum)) return null;
    const purposeRaw = status.statusPurpose || status.purpose || "";
    return { url: String(urlPart || urlRaw), index: idxNum, purpose: String(purposeRaw || "").toLowerCase() };
  };

  const pickCredentialDoc = (cred: any) =>
    cred?.parsedDocument || cred?.credential || cred?.document || cred?.credentialData || cred || null;

  const extractIssuerDidFromStatus = (cred: any) => {
    const doc = pickCredentialDoc(cred);
    if (!doc || typeof doc !== "object") return "";
    const issuer = doc.issuer;
    if (typeof issuer === "string") return issuer;
    if (issuer && typeof issuer === "object" && typeof issuer.id === "string") return issuer.id;
    return "";
  };

  const extractCredDefId = (cred: any) => {
    const doc = pickCredentialDoc(cred);
    if (!doc || typeof doc !== "object") return "";
    const cd = (doc as any).credentialDefinition ?? (doc as any).credential_definition;
    if (cd && typeof cd === "object" && typeof cd.id === "string") return cd.id;
    if (typeof cd === "string") return cd;
    return "";
  };

  const extractCredDefDoc = (cred: any) => {
    const doc = pickCredentialDoc(cred);
    if (!doc || typeof doc !== "object") return null;
    const cd = (doc as any).credentialDefinition ?? (doc as any).credential_definition;
    if (!cd || typeof cd !== "object") return null;
    const keys = Object.keys(cd as Record<string, unknown>);
    if (keys.length === 0) return null;
    if (keys.every((k) => k === "id" || k === "type")) return null;
    return cd as Record<string, unknown>;
  };

  const resolveCredDefHash = async (cred: CredentialEntry) => {
    const credDefId = extractCredDefId(cred);
    const credDefDoc = extractCredDefDoc(cred);
    if (credDefId) {
      const trimmed = credDefId.trim();
      if (isHexString(trimmed, 32) || /^[0-9a-fA-F]{64}$/.test(trimmed)) {
        return normalizeHash32(trimmed);
      }
      if (/^https?:\/\//i.test(trimmed)) {
        const res = await fetch(trimmed, { cache: "no-store" });
        if (!res.ok) throw new Error(`GET ${trimmed} -> ${res.status}`);
        const json = await res.json();
        return normalizeHash32(canonicalKeccak(json));
      }
    }
    if (credDefDoc) {
      return normalizeHash32(canonicalKeccak(credDefDoc));
    }
    return "";
  };

  const resolvePurposeEnum = (purposeRaw: string) => {
    const normalized = purposeRaw.trim().toLowerCase();
    if (normalized === "suspension") return 1;
    return 0;
  };

  const updateStatusListOnchain = async (
    cred: CredentialEntry,
    listUrl: string,
    listJson: unknown,
    listBytes: Uint8Array,
    purposeRaw: string
  ) => {
    const issuerDidFromCred = normalizeDidExact(extractIssuerDidFromStatus(cred) || issuerDid);
    if (!issuerDidFromCred) throw new Error("Issuer DID missing for status list update.");
    const credDefHash = await resolveCredDefHash(cred);
    if (!credDefHash) throw new Error("Credential definition hash missing for status list update.");
    const issuerDidHash = keccak256(toUtf8Bytes(issuerDidFromCred));
    const purposeEnum = resolvePurposeEnum(purposeRaw || "revocation");
    const statusr = await getStatusRContract();
    const provider = getProvider();
    const signer = await provider.getSigner();
    const signerAddress = await signer.getAddress();
    const registrarRole = await statusr.REGISTRAR_ROLE();
    const hasRole = await statusr.hasRole(registrarRole, signerAddress);
    if (!hasRole) {
      throw new Error(`Wallet ${signerAddress} does not have REGISTRAR_ROLE on StatusR.`);
    }
    const listId = await statusr.deriveListId(issuerDidHash, credDefHash, purposeEnum);
    const listHash = canonicalKeccak(listJson);
    console.log("[Issuer] StatusR update", {
      listId,
      listHash,
      listUrl,
      issuerDidHash,
      credDefHash,
      purpose: purposeEnum,
    });
    const tx = await statusr.updateStatusList(listId, listHash, listUrl);
    await tx.wait();
  };

  const deriveConfigId = (types: string[]) => {
    const cleaned = types.map((t) => t.trim()).filter(Boolean);
    if (cleaned.includes("UniversityDegreeCredential")) return "UniversityDegree_jwt_vc_json";
    if (cleaned.includes("OpenBadgeCredential")) return "OpenBadgeCredential_jwt_vc_json";
    const main = cleaned.find((t) => t !== "VerifiableCredential") || cleaned[0] || "Credential";
    return `${main}_jwt_vc_json`;
  };
  const { toast } = useToast();
  const { primaryWalletId, wallets } = usePrimaryWallet();
  const activeWalletId = walletId || primaryWalletId || wallets.data?.[0]?.id || "";
  const { didsQuery, keysQuery } = useWalletResources(activeWalletId);
  const didOptions = useMemo(() => didsQuery.data || [], [didsQuery.data]);
  const keyOptions = useMemo(() => keysQuery.data || [], [keysQuery.data]);
  const calcIssuerShort = (did: string) => {
    const parts = did.split(":");
    return parts[parts.length - 1] || did;
  };
  const OFFER_NOTIFICATION_KEY = "pending_credential_offers";
  type PendingOffer = { did: string; offerUrl: string; createdAt: number; label?: string };
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
  const extractOfferUrl = (result: unknown) => {
    if (!result) return "";
    if (typeof result === "string") {
      const trimmed = result.trim();
      if (trimmed.startsWith("http")) return trimmed;
      if (trimmed.startsWith("openid-credential-offer://")) return trimmed;
      if (trimmed.startsWith("openid4vc://")) return trimmed;
    }
    if (typeof result === "object") {
      const obj = result as Record<string, any>;
      const candidates = [
        obj.offerUrl,
        obj.offer_url,
        obj.credentialOfferUrl,
        obj.credential_offer_url,
        obj.url,
        obj.offer?.url,
        obj.credentialOffer?.url,
      ];
      for (const c of candidates) {
        if (typeof c === "string") {
          const trimmed = c.trim();
          if (trimmed.startsWith("http")) return trimmed;
          if (trimmed.startsWith("openid-credential-offer://")) return trimmed;
          if (trimmed.startsWith("openid4vc://")) return trimmed;
        }
      }
    }
    return "";
  };
  const extractSubjectDid = (payload: any) => {
    if (!payload || typeof payload !== "object") return "";
    const candidates = [
      payload?.credentialData?.credentialSubject,
      payload?.mapping?.credentialSubject,
      payload?.credentialSubject,
    ];
    for (const subject of candidates) {
      if (!subject) continue;
      if (typeof subject === "string") return subject;
      if (typeof subject === "object" && typeof subject.id === "string") return subject.id;
      if (Array.isArray(subject)) {
        const first = subject.find((s) => s && typeof s === "object" && typeof s.id === "string");
        if (first) return first.id;
      }
    }
    return "";
  };
  const normalizeDid = useCallback(
    (did: string) => did.trim().toLowerCase().split("#")[0].split("?")[0],
    []
  );
  const normalizeDidExact = (did: string) => did.trim().split("#")[0].split("?")[0];
  const copyToClipboard = async (text: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(text);
        toast({ title: "Copied", description: "Offer URL copied to clipboard" });
        return true;
      }
      const el = document.createElement("textarea");
      el.value = text;
      el.style.position = "fixed";
      el.style.opacity = "0";
      document.body.appendChild(el);
      el.focus();
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
      toast({ title: "Copied", description: "Offer URL copied to clipboard" });
      return true;
    } catch (e) {
      toast({ variant: "destructive", title: "Copy failed", description: e instanceof Error ? e.message : String(e) });
      return false;
    }
  };
  const offerUrl = useMemo(() => extractOfferUrl(issueResult), [issueResult]);
  const issueResultText = useMemo(() => {
    if (typeof issueResult === "string") return issueResult;
    return JSON.stringify(issueResult, null, 2);
  }, [issueResult]);

  const registryBase = useMemo(() => {
    const host =
      (import.meta as any)?.env?.VITE_URL || "192.168.93.134";
    return `http://${host}/dev/vc/issued`;
  }, []);
  const accreditationBase = useMemo(() => {
    const host =
      (import.meta as any)?.env?.VITE_URL || "192.168.93.134";
    return `http://${host}/dev/vc/accreditation`;
  }, []);
  const allVaUrl = `${accreditationBase}/allVA.json`;

  const extractIssuerDid = (cred: any) => {
    const parsed = cred?.parsedDocument || cred?.credential || cred?.vc || null;
    const issuer = parsed?.issuer ?? cred?.issuer;
    if (typeof issuer === "string") return issuer;
    if (issuer && typeof issuer === "object" && typeof issuer.id === "string") return issuer.id;
    return "";
  };

  const extractIssuedAt = (cred: any) => {
    const parsed = cred?.parsedDocument || cred?.credential || cred?.vc || null;
    return (
      parsed?.issuanceDate ||
      cred?.issuanceDate ||
      cred?.issuedAt ||
      cred?.["issuance_date"] ||
      ""
    );
  };

  const extractTypeLabel = (cred: any) => {
    const parsedTypes = cred?.parsedDocument?.type || cred?.type;
    if (Array.isArray(parsedTypes)) {
      const nonVc = parsedTypes.filter((t) => t !== "VerifiableCredential" && t !== "Verifiable Credential");
      return nonVc[0] || parsedTypes[0] || "";
    }
    return typeof parsedTypes === "string" ? parsedTypes : "";
  };

  const extractExpirationDate = (cred: any) => {
    const parsed = cred?.parsedDocument || cred?.credential || cred?.vc || null;
    return (
      parsed?.expirationDate ||
      parsed?.validUntil ||
      cred?.expirationDate ||
      cred?.validUntil ||
      ""
    );
  };

  const groupedIssued = useMemo(() => {
    const map = new Map<string, CredentialEntry[]>();
    issuerRegistryVcs.forEach((cred) => {
      const issuer = extractIssuerDid(cred) || "unknown";
      if (!map.has(issuer)) map.set(issuer, []);
      map.get(issuer)!.push(cred);
    });
    return Array.from(map.entries());
  }, [issuerRegistryVcs]);

  const selectedIssuerDid = selectedIssuerDids[0] || "";

  const availableIssuerDids = useMemo(() => {
    const set = new Set<string>();
    didOptions.forEach((d) => {
      const didVal = d.did || d.id || "";
      if (didVal) set.add(didVal);
    });
    return Array.from(set);
  }, [didOptions]);

  useEffect(() => {
    if (!selectedIssuerDids.length && availableIssuerDids.length) {
      setSelectedIssuerDids([availableIssuerDids[0]]);
    }
  }, [availableIssuerDids, selectedIssuerDids.length]);

  useEffect(() => {
    const loadAllowed = async () => {
      if (!issuerDid) {
        setAllowedSchemas([]);
        setAllowedCredDefs([]);
        setAllowedError("");
        return;
      }
      try {
        const res = await fetch(allVaUrl, { cache: "no-store" });
        if (!res.ok) {
          if (res.status === 404) {
            setAllowedSchemas([]);
            setAllowedCredDefs([]);
            setAllowedError("");
            return;
          }
          throw new Error(`GET ${allVaUrl} -> ${res.status}`);
        }
        const json = await res.json();
        const wanted = normalizeDid(issuerDid);
        let entry: Record<string, unknown> | null = null;
        if (Array.isArray(json)) {
          entry =
            (json.find(
              (item) =>
                item &&
                typeof item === "object" &&
                typeof (item as any).did === "string" &&
                normalizeDid(String((item as any).did)) === wanted
            ) as Record<string, unknown>) || null;
        } else if (json && typeof json === "object") {
          const values = Object.values(json as Record<string, unknown>);
          entry =
            (values.find(
              (item) =>
                item &&
                typeof item === "object" &&
                typeof (item as any).did === "string" &&
                normalizeDid(String((item as any).did)) === wanted
            ) as Record<string, unknown>) || null;
        }
        const schemaList = entry?.allowedSchemas || entry?.credentialSchemas;
        const credDefList = entry?.allowedCredDefs || entry?.credentialDefinitions;
        setAllowedSchemas(
          Array.isArray(schemaList) ? schemaList.filter((v) => typeof v === "string") : []
        );
        setAllowedCredDefs(
          Array.isArray(credDefList) ? credDefList.filter((v) => typeof v === "string") : []
        );
        setAllowedError("");
      } catch (e) {
        setAllowedSchemas([]);
        setAllowedCredDefs([]);
        setAllowedError(e instanceof Error ? e.message : String(e));
      }
    };
    loadAllowed();
  }, [allVaUrl, issuerDid, normalizeDid]);

  useEffect(() => {
    const issuerDid = selectedIssuerDid;
    if (!issuerDid) {
      setIssuerRegistryVcs([]);
      setIssuerRegistryError("");
      return;
    }
    let cancelled = false;
    const loadRegistry = async () => {
      setIssuerRegistryLoading(true);
      setIssuerRegistryError("");
      try {
        const issuerShort = issuerDid.startsWith("did:jwk") ? issuerDid : issuerDid.split(":").pop() || issuerDid;
        const indexUrl = `${registryBase}/${issuerShort}/allVC.json`;
        const idxRes = await fetch(indexUrl, { cache: "no-store" });
        if (!idxRes.ok) {
          if (idxRes.status === 404) {
            if (!cancelled) {
              setIssuerRegistryVcs([]);
              setIssuerRegistryError("");
            }
            return;
          }
          throw new Error(`GET ${indexUrl} -> ${idxRes.status}`);
        }
        const idxJson = await idxRes.json();
        const entries = Object.entries(idxJson || {});
        const list = await Promise.all(
          entries.map(async ([vcId, urlWithIdx]) => {
            const url = String(urlWithIdx).split("#")[0];
            try {
              const vcRes = await fetch(url, { cache: "no-store" });
              if (!vcRes.ok) throw new Error(`GET ${url} -> ${vcRes.status}`);
              const vc = await vcRes.json();
              return {
                id: vc.id || vcId,
                issuer: vc?.issuer,
                type: vc?.type,
                issuanceDate: vc?.issuanceDate,
                parsedDocument: vc,
                status: vc?.credentialStatus,
              } as CredentialEntry;
            } catch {
              return {
                id: vcId,
                issuer: issuerDid,
                type: "",
                parsedDocument: null,
              } as CredentialEntry;
            }
          })
        );
        if (!cancelled) setIssuerRegistryVcs(list);
      } catch (e) {
        if (!cancelled) {
          const msg = e instanceof Error ? e.message : String(e);
          if (msg.includes(" 404") || msg.includes("-> 404") || msg.includes("Not Found")) {
            setIssuerRegistryVcs([]);
            setIssuerRegistryError("");
          } else {
            setIssuerRegistryError(msg);
            setIssuerRegistryVcs([]);
          }
        }
      } finally {
        if (!cancelled) setIssuerRegistryLoading(false);
      }
    };
    loadRegistry();
    return () => {
      cancelled = true;
    };
  }, [selectedIssuerDid, registryBase]);

  useEffect(() => {
    let cancelled = false;
    const computeStatuses = async () => {
      if (!issuerRegistryVcs.length) {
        setStatusById({});
        return;
      }
      const entries = await Promise.all(
        issuerRegistryVcs.map(async (cred) => {
          const id = cred.id || "";
          if (!id) return null;
          const expiration = extractExpirationDate(cred);
          const expTime = expiration ? Date.parse(expiration) : NaN;
          const isExpired = Number.isFinite(expTime) ? expTime < Date.now() : false;
          const statusEntry = resolveStatusEntry(cred);
          if (!statusEntry) {
            return { id, status: isExpired ? "expired" : "active" };
          }
          try {
            const res = await fetch(statusEntry.url, { cache: "no-store" });
            if (!res.ok) throw new Error(`GET ${statusEntry.url} -> ${res.status}`);
            const json = await res.json();
            const encoded =
              json?.credentialSubject?.encodedList ||
              json?.credentialSubject?.bitstring ||
              json?.encodedList ||
              json?.bitstring;
            if (!encoded || typeof encoded !== "string") {
              return { id, status: isExpired ? "expired" : "active" };
            }
            const { bytes } = await decodeEncodedList(encoded);
            const bit = decodeBitAt(bytes, statusEntry.index);
            if (bit === 1) return { id, status: "revoked" };
            if (isExpired) return { id, status: "expired" };
            return { id, status: "active" };
          } catch {
            return { id, status: isExpired ? "expired" : "active" };
          }
        })
      );
      if (cancelled) return;
      const next: Record<string, string> = {};
      entries.forEach((entry) => {
        if (entry?.id) next[entry.id] = entry.status;
      });
      setStatusById(next);
    };
    computeStatuses();
    return () => {
      cancelled = true;
    };
  }, [issuerRegistryVcs]);

  // load key meta to include full JWK in issuerKey (similar to old app)
  useEffect(() => {
    let cancelled = false;
    const loadMeta = async () => {
      if (!activeWalletId || !issuerKeyId) {
        setIssuerKeyMeta(null);
        setIssuerKeyJwk(null);
        setIssuerKeyError("");
        return;
      }
      try {
        const meta = await walletApi.keyMeta(activeWalletId, issuerKeyId);
        if (!cancelled) {
          setIssuerKeyMeta(meta);
          const jwkFromMeta = extractJwk(meta);
          if (jwkFromMeta) setIssuerKeyJwk(jwkFromMeta);
          setIssuerKeyError("");
        }
      } catch (e) {
        if (!cancelled) {
          setIssuerKeyMeta(null);
          setIssuerKeyJwk(null);
          setIssuerKeyError(e instanceof Error ? e.message : String(e));
        }
      }
    };
    loadMeta();
    return () => {
      cancelled = true;
    };
  }, [activeWalletId, issuerKeyId]);

  // load key material (public JWK) similar to old app /keys/{id}/load
  useEffect(() => {
    let cancelled = false;
    const loadJwk = async () => {
      if (!activeWalletId || !issuerKeyId) return;
      try {
        const data = await walletApi.keyLoad(activeWalletId, issuerKeyId);
        if (cancelled) return;
        const jwk = extractJwk(data) || extractJwk((data as any)?.key);
        if (jwk) {
          setIssuerKeyJwk(jwk);
          setIssuerKeyError("");
        }
      } catch (e) {
        if (!cancelled) {
          setIssuerKeyJwk(null);
          // keep previous meta error if exists
        }
      }
    };
    loadJwk();
    return () => {
      cancelled = true;
    };
  }, [activeWalletId, issuerKeyId]);

  const extractJwk = (meta: unknown): Record<string, unknown> | null => {
    if (!meta || typeof meta !== "object") return null;
    const obj = meta as Record<string, unknown>;
    const candidates = [
      obj.privateKeyJwk as Record<string, unknown>,
      obj.privateKey as Record<string, unknown>,
      (obj.key as Record<string, unknown>)?.privateKeyJwk as Record<string, unknown>,
      (obj.key as Record<string, unknown>)?.privateKey as Record<string, unknown>,
      obj.jwk as Record<string, unknown>,
      obj.key as Record<string, unknown>,
      obj.publicKeyJwk as Record<string, unknown>,
      obj.publicKey as Record<string, unknown>,
      obj.value as Record<string, unknown>,
      (obj.key as Record<string, unknown>)?.jwk as Record<string, unknown>,
      (obj.key as Record<string, unknown>)?.publicKeyJwk as Record<string, unknown>,
      (obj.key as Record<string, unknown>)?.publicKey as Record<string, unknown>,
      (obj.key as Record<string, unknown>)?.value as Record<string, unknown>,
      obj,
    ];
    for (const cand of candidates) {
      if (!cand || typeof cand !== "object") continue;
      const c = cand as Record<string, unknown>;
      if (c.kty || c.crv || c.x || c.y || c.d || c.kid) return c;
    }
    return null;
  };

  // helpers for schema parsing similar to old app
  const flattenSubjectProps = (doc: any, prefix = ""): SchemaField[] => {
    if (!doc || typeof doc !== "object") return [];
    const props = doc.properties || {};
    const reqList = Array.isArray(doc.required) ? doc.required : [];
    const fields: SchemaField[] = [];

    Object.entries(props).forEach(([name, schema]) => {
      const fullName = prefix ? `${prefix}.${name}` : name;
      const isObject =
        schema &&
        typeof schema === "object" &&
        (schema as any).type === "object" &&
        ((schema as any).properties || (schema as any).allOf);
      if (isObject) {
        fields.push(...flattenSubjectProps(schema as any, fullName));
      } else {
        fields.push({ name: fullName, required: reqList.includes(name) });
      }
    });

    if (Array.isArray((doc as any).allOf)) {
      (doc as any).allOf.forEach((part: any) => {
        fields.push(...flattenSubjectProps(part, prefix));
      });
    }

    return fields;
  };

  // load schema and suggest subject fields
  useEffect(() => {
    const fetchSchema = async () => {
      if (!schemaUrl.trim()) {
        setSchemaFields([]);
        setSchemaError("");
        setSubjectFields([]);
        return;
      }
      setSchemaLoading(true);
      setSchemaError("");
      try {
        const res = await fetch(schemaUrl.trim(), { cache: "no-store" });
        if (!res.ok) throw new Error(`Schema fetch HTTP ${res.status}`);
        const json = await res.json();
        const nodes: any[] = [];
        if (json?.properties?.credentialSubject) nodes.push(json.properties.credentialSubject);
        if (json?.credentialSubject) nodes.push(json.credentialSubject);
        if (Array.isArray(json?.allOf)) {
          json.allOf.forEach((part: any) => {
            if (part?.properties?.credentialSubject) nodes.push(part.properties.credentialSubject);
            if (part?.credentialSubject) nodes.push(part.credentialSubject);
          });
        }
        if (!nodes.length) nodes.push(json);

        const seen = new Set<string>();
        let fields: SchemaField[] = [];
        nodes.forEach((n) => {
          flattenSubjectProps(n).forEach((f) => {
            const key = `${f.name}-${f.required ? "1" : "0"}`;
            if (seen.has(key)) return;
            seen.add(key);
            fields.push(f);
          });
        });
        // dacă schema are achievement.* păstrăm acele câmpuri;
        // altfel dacă are credentialStatus.* păstrăm acelea; altfel leaf fără punct (ex: diploma)
        const hasAchievement = fields.some((f) => f.name.startsWith("achievement."));
        const hasStatus = fields.some((f) => f.name.startsWith("credentialStatus."));
        if (hasAchievement) {
          fields = fields.filter((f) => f.name.startsWith("achievement."));
        } else if (hasStatus) {
          fields = fields.filter((f) => f.name.startsWith("credentialStatus."));
        } else {
          // păstrăm doar câmpurile care nu au sub-proprietăți (fără punct)
          fields = fields.filter((f) => !f.name.includes("."));
        }

        setSchemaFields(fields);
        setSubjectFields(fields.map((f) => ({ key: f.name, value: "" })));
      } catch (e) {
        setSchemaError(e instanceof Error ? e.message : String(e));
        setSchemaFields([]);
        setSubjectFields([]);
      } finally {
        setSchemaLoading(false);
      }
    };
    fetchSchema();
  }, [schemaUrl]);

  useEffect(() => {
    // Build JSON payload similar to old app's preparedPayload
    const types = credentialTypes
      .split(",")
      .map((t) => t.trim())
      .filter(Boolean);
    const subject: Record<string, any> = {};
    subjectFields.forEach((f) => {
      if (!f.key.trim()) return;
      if (f.key.includes(".")) {
        const [parent, child] = f.key.split(".");
        subject[parent] = subject[parent] || {};
        subject[parent][child] = f.value;
      } else {
        subject[f.key.trim()] = f.value;
      }
    });
    if (subjectId.trim()) subject.id = subjectId.trim();

    const issuanceIso = issuanceDate ? new Date(issuanceDate).toISOString() : formatISO(new Date());
    const expirationIso = expirationDate ? new Date(expirationDate).toISOString() : "";

    const resolvedConfigId = credentialConfigurationId || deriveConfigId(types);

    const payload: Record<string, unknown> = {
      credentialConfigurationId: resolvedConfigId,
      credentialData: {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://www.w3.org/2018/credentials/examples/v1",
        ],
        id: credentialId || "",
        type: types.length ? types : ["VerifiableCredential"],
        issuer: { id: issuerDid || "" },
        issuanceDate: issuanceIso,
        credentialSubject: subject,
      },
      mapping: {
        id: credentialId || "",
        issuer: { id: issuerDid || "" },
        credentialSubject: subject,
        issuanceDate: issuanceIso,
        ...(expirationIso ? { expirationDate: expirationIso } : {}),
        ...(schemaUrl
          ? { credentialSchema: [{ id: schemaUrl.trim(), type: "JsonSchema" }] }
          : {}),
        ...(credDefUrl
          ? { credentialDefinition: { id: credDefUrl.trim(), type: "JsonSchema" } }
          : {}),
        ...(statusListUrl
          ? {
              credentialStatus: {
                id: `${statusListUrl.trim()}#${statusListIndex || "1"}`,
                type: "StatusList2021Entry",
                statusPurpose: statusPurpose || "revocation",
                statusListIndex: statusListIndex || "1",
                statusListCredential: statusListUrl.trim(),
                ...(statusSize ? { statusSize: Number(statusSize) } : {}),
              },
            }
          : {}),
      },
      issuerDid: issuerDid || "",
    };

    if (issuerKeyId) {
      const jwk = issuerKeyJwk || extractJwk(issuerKeyMeta);
      // kid deja este selectat, în payload trimitem doar JWK conform cerinței
      payload.issuerKey = jwk ? { type: "jwk", jwk } : undefined;
    }

    setCredentialJson(JSON.stringify(payload, null, 2));
  }, [
    credentialId,
    credentialTypes,
    subjectId,
    subjectFields,
    issuanceDate,
    expirationDate,
    issuerDid,
    issuerKeyId,
    issuerKeyMeta,
    issuerKeyJwk,
    schemaUrl,
    credDefUrl,
    statusListUrl,
    statusListIndex,
    statusSize,
    statusPurpose,
  ]);

  useEffect(() => {
    if (!walletId && primaryWalletId) setWalletId(primaryWalletId);
  }, [primaryWalletId, walletId]);

  const loadIssued = async () => {
    if (!activeWalletId) return;
    setIssuedLoading(true);
    try {
      const list = await walletApi.listCredentials(activeWalletId);
      const detailed = await Promise.all(
        list.map(async (item) => {
          if (!item.id) return item;
          try {
            const detail = await walletApi.viewCredential(activeWalletId, item.id);
            if (detail && typeof detail === "object") {
              const obj = detail as Record<string, unknown>;
              return { ...item, ...obj, parsedDocument: obj.parsedDocument || (item as any).parsedDocument };
            }
          } catch {
            // ignore detail errors
          }
          return item;
        })
      );
      setIssuedCredentials(detailed);
      const statusEntries = await Promise.all(
        detailed.map(async (cred) => {
          const id = cred.id || "";
          if (!id) return null;
          const expiration = extractExpirationDate(cred);
          const expTime = expiration ? Date.parse(expiration) : NaN;
          const isExpired = Number.isFinite(expTime) ? expTime < Date.now() : false;
          const statusEntry = resolveStatusEntry(cred);
          if (!statusEntry) {
            return { id, status: isExpired ? "expired" : "active" };
          }
          try {
            const res = await fetch(statusEntry.url, { cache: "no-store" });
            if (!res.ok) throw new Error(`GET ${statusEntry.url} -> ${res.status}`);
            const json = await res.json();
            const encoded =
              json?.credentialSubject?.encodedList ||
              json?.credentialSubject?.bitstring ||
              json?.encodedList ||
              json?.bitstring;
            if (!encoded || typeof encoded !== "string") {
              return { id, status: isExpired ? "expired" : "active" };
            }
            const { bytes } = await decodeEncodedList(encoded);
            const bit = decodeBitAt(bytes, statusEntry.index);
            if (bit === 1) return { id, status: "revoked" };
            if (isExpired) return { id, status: "expired" };
            return { id, status: "active" };
          } catch {
            return { id, status: isExpired ? "expired" : "active" };
          }
        })
      );
      setStatusById((prev) => {
        const next = { ...prev };
        statusEntries.forEach((entry) => {
          if (entry?.id) next[entry.id] = entry.status;
        });
        return next;
      });
    } catch (e) {
      toast({ variant: "destructive", title: "Cannot load issued VCs", description: e instanceof Error ? e.message : String(e) });
      setIssuedCredentials([]);
    } finally {
      setIssuedLoading(false);
    }
  };

  useEffect(() => {
    loadIssued();
  }, [activeWalletId]);

  // auto compute next status list index from registry (allVC.json)
  useEffect(() => {
    const computeNextStatusIndex = async () => {
      if (!issuerDid || !statusListUrl) return;
      try {
        const origin = new URL(statusListUrl.trim()).origin;
        const issuerShort = calcIssuerShort(issuerDid);
        const allVcUrl = `${origin}/dev/vc/issued/${issuerShort}/allVC.json`;
        const res = await fetch(allVcUrl, { cache: "no-store" });
        if (!res.ok) throw new Error(`allVC.json HTTP ${res.status}`);
        const data = await res.json();
        let maxIndex = -1;
        if (data && typeof data === "object") {
          Object.values(data as Record<string, string>).forEach((val) => {
            if (typeof val === "string") {
              const fragment = val.split("#")[1] || "";
              const num = Number(fragment);
              if (Number.isFinite(num) && num > maxIndex) maxIndex = num;
            }
          });
        }
        const next = maxIndex + 1;
        setStatusListIndex(String(next));
      } catch (e) {
        // silent fail; user can input manually
        console.warn("Cannot auto-compute status index", e);
      }
    };
    computeNextStatusIndex();
  }, [issuerDid, statusListUrl]);

  // auto build revocation status list URL when issuer DID changes (pattern ca în old app)
  useEffect(() => {
    if (!issuerDid) return;
    const autoUrl = `http://192.168.93.134/dev/status/${calcIssuerShort(
      issuerDid
    )}/revocation/1.0.0.json`;
    setStatusListUrl((prev) => (!prev || prev.includes("/dev/status/") ? autoUrl : prev));
  }, [issuerDid]);

  // generate random urn:uuid when deschidem dialogul sau lipsește id-ul
  useEffect(() => {
    if (createOfferOpen) {
      // regenerează de fiecare dată la deschiderea dialogului pentru ID complet nou
      setCredentialId(generateCredentialId());
      const arr = credentialTypes.split(",").map((t) => t.trim()).filter(Boolean);
      setCredentialConfigurationId(deriveConfigId(arr));
    }
  }, [createOfferOpen]);

  const handleIssue = async () => {
    if (!activeWalletId) {
      toast({ variant: "destructive", title: "Select wallet" });
      return;
    }
    if (!issuerDid) {
      toast({ variant: "destructive", title: "Select issuer DID" });
      return;
    }
    if (!issuerKeyId) {
      toast({ variant: "destructive", title: "Select issuer key" });
      return;
    }
    const schemaTrimmed = schemaUrl.trim();
    if (allowedSchemas.length && !allowedSchemas.includes(schemaTrimmed)) {
      toast({
        variant: "destructive",
        title: "Schema not allowed",
        description: "Select an allowed credential schema for this issuer.",
      });
      return;
    }
    const credDefTrimmed = credDefUrl.trim();
    if (allowedCredDefs.length && !allowedCredDefs.includes(credDefTrimmed)) {
      toast({
        variant: "destructive",
        title: "Credential definition not allowed",
        description: "Select an allowed credential definition for this issuer.",
      });
      return;
    }
    let payload: any;
    try {
      payload = credentialJson.trim() ? JSON.parse(credentialJson) : {};
    } catch (err) {
      toast({ variant: "destructive", title: "Invalid credential JSON" });
      return;
    }
    const jwk = issuerKeyJwk || extractJwk(issuerKeyMeta);
    payload = {
      ...payload,
      issuerDid,
      issuerKey: jwk ? { type: "jwk", jwk } : { kid: issuerKeyId },
    };
    setLoadingIssue(true);
    setIssueResult(null);
    try {
      const res = await issueJwtCredential(payload, sessionTtl.trim() || undefined);
      setIssueResult(res);
      const nextOfferUrl = extractOfferUrl(res);
      const didRaw = subjectId.trim() || extractSubjectDid(payload);
      const did = didRaw ? normalizeDid(didRaw) : "";
      const offerLabel = credentialConfigurationId || credentialTypes.split(",")[0]?.trim() || "Credential offer";
      if (nextOfferUrl) {
        await copyToClipboard(nextOfferUrl);
      }
      if (nextOfferUrl && did) {
        const offers = loadPendingOffers();
        offers.push({ did, offerUrl: nextOfferUrl, createdAt: Date.now(), label: offerLabel });
        savePendingOffers(offers);
      }
      toast({ title: "Issued", description: "Credential offer created via issuer API." });
      await loadIssued();
    } catch (e) {
      toast({ variant: "destructive", title: "Issue failed", description: e instanceof Error ? e.message : String(e) });
    } finally {
      setLoadingIssue(false);
    }
  };

  const loadStatusFor = async (cred: CredentialEntry) => {
    const entry = resolveStatusEntry(cred);
    if (!entry) {
      setStatusError("Nu am găsit credentialStatus (url/index).");
      setStatusInfo(null);
      return;
    }
    setStatusLoading(true);
    setStatusError("");
    try {
      const res = await fetch(entry.url, { cache: "no-store" });
      if (!res.ok) throw new Error(`GET ${entry.url} -> ${res.status}`);
      const json = await res.json();
      const encoded =
        json?.credentialSubject?.encodedList ||
        json?.credentialSubject?.bitstring ||
        json?.encodedList ||
        json?.bitstring;
      if (!encoded || typeof encoded !== "string")
        throw new Error("encodedList/bitstring lipsă în status list.");
      const { bytes } = await decodeEncodedList(encoded);
      const bit = decodeBitAt(bytes, entry.index);
      setStatusInfo({ url: entry.url, index: entry.index, bit });
    } catch (e) {
      setStatusError(e instanceof Error ? e.message : String(e));
      setStatusInfo(null);
    } finally {
      setStatusLoading(false);
    }
  };

  const updateCredentialStatus = async (nextBit: 0 | 1) => {
    if (!statusTarget) return;
    const entry = resolveStatusEntry(statusTarget);
    if (!entry) return;
    setStatusLoading(true);
    setStatusError("");
    try {
      const res = await fetch(entry.url, { cache: "no-store" });
      if (!res.ok) throw new Error(`GET ${entry.url} -> ${res.status}`);
      const json = await res.json();
      const encoded =
        json?.credentialSubject?.encodedList ||
        json?.credentialSubject?.bitstring ||
        json?.encodedList ||
        json?.bitstring;
      if (!encoded || typeof encoded !== "string")
        throw new Error("encodedList/bitstring lipsă în status list.");
      const decoded = await decodeEncodedList(encoded);
      const updated = setBitAt(decoded.bytes, entry.index, nextBit);
      const newEncoded = await encodeEncodedList(updated, decoded.compressed);
      const next = { ...json };
      if (next.credentialSubject && typeof next.credentialSubject === "object") {
        next.credentialSubject = {
          ...next.credentialSubject,
          ...(next.credentialSubject.encodedList ? { encodedList: newEncoded } : {}),
          ...(next.credentialSubject.bitstring ? { bitstring: newEncoded } : {}),
        };
      } else {
        next.credentialSubject = { encodedList: newEncoded };
      }
      await putJSON(entry.url, next, "application/json");
      await updateStatusListOnchain(
        statusTarget,
        entry.url,
        next,
        updated,
        entry.purpose || statusPurpose || "revocation"
      );
      toast({ title: "On-chain updated", description: "Status list hash updated on StatusR." });
      const label = nextBit === 1 ? "Revocat" : "Activat";
      toast({ title: label, description: `Index ${entry.index} actualizat.` });
      if (statusTarget?.id) {
        setStatusById((prev) => ({
          ...prev,
          [statusTarget.id as string]: nextBit === 1 ? "revoked" : "active",
        }));
      }
      await loadStatusFor(statusTarget);
    } catch (e) {
      setStatusError(e instanceof Error ? e.message : String(e));
    } finally {
      setStatusLoading(false);
    }
  };

  return (
    <MainLayout>
      <PageHeader
        icon={FileCheck}
        title="Issuer Portal"
        description="Create and manage verifiable credential offers"
      >
        <Dialog open={createOfferOpen} onOpenChange={setCreateOfferOpen}>
          <DialogTrigger asChild>
            <Button variant="gradient">
              <Plus className="w-4 h-4 mr-2" />
              Create Credential Offer
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-4xl w-full max-h-[90vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Credential Offer</DialogTitle>
              <DialogDescription>
                Generate a new credential offer for a holder
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 mt-4">
              <div className="space-y-2">
                <Label>Credential Type</Label>
                <Select value={walletId} onValueChange={setWalletId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select wallet" />
                  </SelectTrigger>
                  <SelectContent>
                    {(wallets.data || []).map((w) => (
                      <SelectItem key={w.id} value={w.id}>
                        {w.name || w.id}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Issuer DID</Label>
                <Select value={issuerDid} onValueChange={setIssuerDid}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select issuer DID" />
                  </SelectTrigger>
                  <SelectContent>
                    {didOptions.map((d) => {
                      const didVal = d.did || d.id || "";
                      const label =
                        didVal.startsWith("did:jwk") && didVal.length > 200
                          ? `${didVal.slice(0, 32)}…${didVal.slice(-16)}`
                          : didVal;
                      return (
                        <SelectItem key={didVal} value={didVal} className="truncate max-w-[320px]">
                          <span className="truncate inline-block max-w-[280px]" title={didVal}>{label}</span>
                        </SelectItem>
                      );
                    })}
                 </SelectContent>
               </Select>
             </div>
              <div className="space-y-2">
                <Label>Issuer key</Label>
                <Select value={issuerKeyId} onValueChange={setIssuerKeyId}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select key" />
                  </SelectTrigger>
                  <SelectContent>
                    {keyOptions.map((k) => {
                      const label = k.keyId || k.kid || k.keyRef || k.alias || "(no id)";
                      return (
                        <SelectItem key={label} value={label}>
                          {label}
                        </SelectItem>
                      );
                    })}
                  </SelectContent>
                </Select>
                {issuerKeyError && (
                  <p className="text-xs text-destructive">Key meta error: {issuerKeyError}</p>
                )}
                {!issuerKeyError && (issuerKeyMeta || issuerKeyJwk) && (
                  <p className="text-xs text-muted-foreground">Key meta loaded (JWK attached in payload).</p>
                )}
              </div>
              <div className="space-y-2">
                <Label>Credential payload (JSON)</Label>
                <Textarea
                  placeholder='{"credentialData": {...}, "mapping": {...}}'
                  value={credentialJson}
                  onChange={(e) => setCredentialJson(e.target.value)}
                  rows={10}
                  className="font-mono text-sm"
                />
              </div>
              <div className="grid md:grid-cols-3 gap-3">
                <div className="space-y-2">
                  <Label>Schema URL (JsonSchema)</Label>
                  <Input value={schemaUrl} onChange={(e) => setSchemaUrl(e.target.value)} placeholder="http://host/dev/schemas/..." />
                </div>
                <div className="space-y-2">
                  <Label>Credential Definition URL</Label>
                  <Input value={credDefUrl} onChange={(e) => setCredDefUrl(e.target.value)} placeholder="http://host/dev/creddefs/..." />
                </div>
                <div className="space-y-2">
                  <Label>Status List URL</Label>
                  <Input value={statusListUrl} onChange={(e) => setStatusListUrl(e.target.value)} placeholder="http://host/dev/status/.../revocation/1.0.0.json" />
                </div>
              </div>
              {(allowedSchemas.length > 0 || allowedCredDefs.length > 0 || allowedError) && (
                <div className="space-y-2">
                  {allowedError && <p className="text-xs text-destructive">allVA.json: {allowedError}</p>}
                  <div className="grid md:grid-cols-2 gap-3">
                    {allowedSchemas.length > 0 && (
                      <div className="space-y-2">
                        <Label>Allowed Schemas</Label>
                        <Select
                          value={allowedSchemas.includes(schemaUrl.trim()) ? schemaUrl.trim() : ""}
                          onValueChange={(val) => setSchemaUrl(val)}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select allowed schema" />
                          </SelectTrigger>
                          <SelectContent>
                            {allowedSchemas.map((schema) => (
                              <SelectItem key={schema} value={schema}>
                                {schema}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                    {allowedCredDefs.length > 0 && (
                      <div className="space-y-2">
                        <Label>Allowed Credential Definitions</Label>
                        <Select
                          value={allowedCredDefs.includes(credDefUrl.trim()) ? credDefUrl.trim() : ""}
                          onValueChange={(val) => setCredDefUrl(val)}
                        >
                          <SelectTrigger>
                            <SelectValue placeholder="Select allowed cred def" />
                          </SelectTrigger>
                          <SelectContent>
                            {allowedCredDefs.map((credDef) => (
                              <SelectItem key={credDef} value={credDef}>
                                {credDef}
                              </SelectItem>
                            ))}
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                  </div>
                </div>
              )}
              <div className="grid md:grid-cols-3 gap-3">
                <div className="space-y-2">
                  <Label>Status List Index</Label>
                  <Input value={statusListIndex} onChange={(e) => setStatusListIndex(e.target.value)} placeholder="0" />
                </div>
                <div className="space-y-2">
                  <Label>Status Size</Label>
                  <Input value={statusSize} onChange={(e) => setStatusSize(e.target.value)} placeholder="131072" />
                </div>
                <div className="space-y-2">
                  <Label>Status Purpose</Label>
                  <Input value={statusPurpose} onChange={(e) => setStatusPurpose(e.target.value)} placeholder="revocation" />
                </div>
              </div>
              <div className="space-y-2">
                <Label>Credential ID</Label>
                <div className="flex gap-2">
                  <Input value={credentialId} onChange={(e) => setCredentialId(e.target.value)} placeholder="urn:uuid:..." />
                  <Button variant="outline" size="sm" onClick={() => setCredentialId(generateCredentialId())}>
                    Random
                  </Button>
                </div>
              </div>
              <div className="space-y-2">
                <Label>Types (comma separated)</Label>
                <Input
                  value={credentialTypes}
                  onChange={(e) => {
                    const val = e.target.value;
                    setCredentialTypes(val);
                    const arr = val.split(",").map((t) => t.trim()).filter(Boolean);
                    setCredentialConfigurationId((prev) => (!prev ? deriveConfigId(arr) : prev));
                  }}
                  placeholder="VerifiableCredential,OpenBadgeCredential"
                />
              </div>
              <div className="space-y-2">
                <Label>Credential Configuration ID</Label>
                <div className="flex gap-2">
                  <Input
                    value={credentialConfigurationId}
                    onChange={(e) => setCredentialConfigurationId(e.target.value)}
                    placeholder="UniversityDegree_jwt_vc_json"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      const arr = credentialTypes.split(",").map((t) => t.trim()).filter(Boolean);
                      setCredentialConfigurationId(deriveConfigId(arr));
                    }}
                  >
                    Auto
                  </Button>
                </div>
              </div>
              <div className="grid md:grid-cols-2 gap-3">
                <div className="space-y-2">
                  <Label>Credential Subject ID</Label>
                  <Input value={subjectId} onChange={(e) => setSubjectId(e.target.value)} placeholder="did:..." />
                </div>
                <div className="space-y-2">
                  <Label>Issuance Date</Label>
                  <Input type="datetime-local" value={issuanceDate} onChange={(e) => setIssuanceDate(e.target.value)} />
                </div>
              </div>
              <div className="space-y-2">
                <Label>Expiration Date</Label>
                <Input type="datetime-local" value={expirationDate} onChange={(e) => setExpirationDate(e.target.value)} placeholder="optional" />
              </div>
              <div className="space-y-2">
                <Label>Credential Subject Fields</Label>
                <div className="space-y-2">
                  {subjectFields.map((f, idx) => (
                    <div key={idx} className="grid grid-cols-2 gap-2">
                      <div className="h-10 px-3 flex items-center rounded-md border border-border/60 bg-muted/30 text-sm font-medium">
                        {f.key.split(".").pop() || f.key}
                      </div>
                      <div className="flex gap-2">
                        <Input
                          value={f.value}
                          onChange={(e) =>
                            setSubjectFields((prev) =>
                              prev.map((item, i) => (i === idx ? { ...item, value: e.target.value } : item))
                            )
                          }
                          placeholder="field value"
                        />
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() =>
                            setSubjectFields((prev) => prev.filter((_, i) => i !== idx))
                          }
                        >
                          Remove
                        </Button>
                      </div>
                    </div>
                  ))}
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setSubjectFields((prev) => [...prev, { key: "", value: "" }])}
                  >
                    Add field
                  </Button>
                  {schemaLoading && <p className="text-xs text-muted-foreground">Loading schema fields…</p>}
                  {schemaError && <p className="text-xs text-destructive">Schema error: {schemaError}</p>}
                </div>
              </div>
              <div className="space-y-2">
                <Label>sessionTtl (optional)</Label>
                <Input value={sessionTtl} onChange={(e) => setSessionTtl(e.target.value)} placeholder="e.g. 60000" />
              </div>

              <div className="flex gap-3">
                <Button onClick={handleIssue} className="flex-1" disabled={loadingIssue}>
                  <Send className="w-4 h-4 mr-2" />
                  {loadingIssue ? "Issuing..." : "Generate Offer"}
                </Button>
              </div>
              {issueResult && (
                <div className="p-4 bg-muted/50 rounded-lg border border-border space-y-2">
                  {offerUrl && (
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">Offer URL (trimite către user)</Label>
                      <div className="flex gap-2">
                        <Input readOnly value={offerUrl} className="font-mono text-xs" />
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyToClipboard(offerUrl)}
                        >
                          Copy
                        </Button>
                      </div>
                    </div>
                  )}
                  <div>
                    <Label className="text-xs text-muted-foreground">Response</Label>
                    <pre className="font-mono text-xs mt-2 break-all max-h-64 overflow-auto">
                      {issueResultText}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </DialogContent>
        </Dialog>
      </PageHeader>

      <div className="container mx-auto px-4 py-8">
        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <StatCard icon={FileCheck} label="Total Issued" value={issuerRegistryVcs.length} />
          <StatCard icon={CheckCircle} label="Active" value={issuerRegistryVcs.filter((c) => (statusById[c.id || ""] || "active") === "active").length} />
          <StatCard icon={Clock} label="Pending" value={0} />
          <StatCard icon={Users} label="Unique Holders" value={"—"} />
        </div>

        {/* Issued Credentials Table */}
        <DataCard
          title="Issued Credentials"
          description="All credentials issued by this entity"
        >
          <div className="space-y-6">
            <div className="space-y-2">
              <Label>Select issuer DID</Label>
              <Select
                value={selectedIssuerDids[0] || ""}
                onValueChange={(val) => setSelectedIssuerDids(val ? [val] : [])}
              >
                <SelectTrigger className="max-w-xl">
                  <SelectValue placeholder="Select DID" />
                </SelectTrigger>
                <SelectContent>
                  {availableIssuerDids.map((did) => {
                    const isJwt = did.startsWith("did:jwk") || did.startsWith("did:jwt");
                    const label =
                      isJwt && did.length > 200 ? `${did.slice(0, 64)}…${did.slice(-24)}` : did;
                    return (
                      <SelectItem key={did} value={did} className="truncate max-w-[560px]">
                        <span className="truncate inline-block max-w-[520px]" title={did}>
                          {label}
                        </span>
                      </SelectItem>
                    );
                  })}
                </SelectContent>
              </Select>
            </div>
            {issuerRegistryLoading && (
              <p className="text-xs text-muted-foreground">Loading VC registry…</p>
            )}
            {issuerRegistryError && (
              <p className="text-xs text-destructive">Registry error: {issuerRegistryError}</p>
            )}
            {issuerRegistryVcs.length > 0 ? (
              <>
                {groupedIssued
                  .filter(([issuerDid]) => (selectedIssuerDid ? issuerDid === selectedIssuerDid : true))
                  .map(([issuerDid, creds]) => (
                <div key={issuerDid} className="space-y-2">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>ID</TableHead>
                          <TableHead>Type</TableHead>
                          <TableHead>Issuer</TableHead>
                          <TableHead>Issued At</TableHead>
                          <TableHead>Status</TableHead>
                          <TableHead className="text-right">Actions</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {creds.map((cred, idx) => {
                          const issuerLabel = extractIssuerDid(cred);
                          const issuedAtLabel = extractIssuedAt(cred);
                          const typeLabel = extractTypeLabel(cred);
                          const statusLabel = statusById[String(cred.id || "")] || "active";
                          const statusEntry = resolveStatusEntry(cred);
                          return (
                            <TableRow key={String(cred.id || cred.credentialId || idx)}>
                              <TableCell className="font-mono text-sm">{cred.id}</TableCell>
                              <TableCell>{typeLabel || "—"}</TableCell>
                              <TableCell className="font-mono text-sm">{issuerLabel || "—"}</TableCell>
                              <TableCell>{issuedAtLabel || "—"}</TableCell>
                              <TableCell>
                                <Badge
                                  variant={
                                    statusLabel === "revoked"
                                      ? "destructive"
                                      : statusLabel === "expired"
                                      ? "secondary"
                                      : "default"
                                  }
                                >
                                  {statusLabel}
                                </Badge>
                              </TableCell>
                              <TableCell className="text-right space-x-1">
                                {statusLabel === "revoked" ? (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    className="bg-success text-success-foreground hover:bg-success/90"
                                    disabled={!statusEntry}
                                    onClick={() => {
                                      setStatusTarget(cred);
                                      setStatusDialogOpen(true);
                                      loadStatusFor(cred);
                                    }}
                                  >
                                    Activate
                                  </Button>
                                ) : (
                                  <Button
                                    size="sm"
                                    variant="destructive"
                                    disabled={!statusEntry}
                                    onClick={() => {
                                      setStatusTarget(cred);
                                      setStatusDialogOpen(true);
                                      loadStatusFor(cred);
                                    }}
                                  >
                                    Revoke
                                  </Button>
                                )}
                              </TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              ))}
              {selectedIssuerDid &&
                groupedIssued.filter(([issuerDid]) => issuerDid === selectedIssuerDid).length === 0 && (
                  <p className="text-sm text-muted-foreground">
                    Nu există VC-uri emise de DID-ul selectat.
                  </p>
                )}
              </>
            ) : (
              <EmptyState
                icon={FileCheck}
                title="No credentials issued yet"
                description="Create your first credential offer"
                actionLabel="Create Offer"
                onAction={() => setCreateOfferOpen(true)}
              />
            )}
          </div>
        </DataCard>
      </div>

      <Dialog open={statusDialogOpen} onOpenChange={setStatusDialogOpen}>
        <DialogContent className="max-w-xl w-full">
          <DialogHeader>
            <DialogTitle>Credential status</DialogTitle>
            <DialogDescription>
              Verifică și marchează revocare în status list (bit 0 = valid, 1 = revocat)
            </DialogDescription>
          </DialogHeader>
          {statusTarget && (
            <div className="space-y-3">
              <div className="text-sm">
                <div className="font-mono break-all">{statusTarget.id}</div>
                <div className="text-muted-foreground">
                  {Array.isArray(statusTarget.type) ? statusTarget.type.join(", ") : statusTarget.type}
                </div>
              </div>
              {statusError && <p className="text-destructive text-sm">{statusError}</p>}
              {statusInfo && (
                <div className="space-y-2">
                  <div className="text-sm">
                    <span className="font-semibold">Status list:</span>{" "}
                    <span className="font-mono break-all text-xs">{statusInfo.url}</span>
                  </div>
                  <div className="flex gap-2 items-center text-sm">
                    <span>Index: {statusInfo.index}</span>
                    <Badge variant={statusInfo.bit === 1 ? "destructive" : "default"}>
                      {statusInfo.bit === 1 ? "Revoked (bit=1)" : statusInfo.bit === 0 ? "Valid (bit=0)" : "N/A"}
                    </Badge>
                  </div>
                </div>
              )}
              <div className="flex gap-2">
                <Button onClick={() => statusTarget && loadStatusFor(statusTarget)} disabled={statusLoading}>
                  <RefreshCw className="w-4 h-4 mr-2" />
                  {statusLoading ? "Checking..." : "Check status"}
                </Button>
                {(statusInfo?.bit ?? 0) === 1 ? (
                  <Button
                    variant="default"
                    className="bg-success text-success-foreground hover:bg-success/90"
                    onClick={() => updateCredentialStatus(0)}
                    disabled={statusLoading}
                  >
                    Activate
                  </Button>
                ) : (
                  <Button
                    variant="destructive"
                    onClick={() => updateCredentialStatus(1)}
                    disabled={statusLoading}
                  >
                    Mark revoked
                  </Button>
                )}
              </div>
              {statusLoading && <p className="text-xs text-muted-foreground">Loading status…</p>}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </MainLayout>
  );
}
