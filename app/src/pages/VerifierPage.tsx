import { useEffect, useMemo, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import { ShieldCheck, Copy, Play, RefreshCw, CheckCircle, XCircle, Clock } from "lucide-react";
import { MainLayout } from "@/components/layout/MainLayout";
import { PageHeader } from "@/components/shared/PageHeader";
import { StatCard } from "@/components/shared/StatCard";
import { DataCard } from "@/components/shared/DataCard";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { useToast } from "@/hooks/use-toast";
import { VERIFIER_API_BASE } from "@/lib/env";
import { joinUrl } from "@/lib/api";
import { BrowserProvider, Contract, Eip1193Provider, hexlify, isHexString, keccak256, toUtf8Bytes } from "ethers";
import { canonicalize } from "json-canonicalize";
import tirAbi from "../../smart_contracts/abi_TIR.json";
import tsrAbi from "../../smart_contracts/abi_TSR.json";
import cdrAbi from "../../smart_contracts/abi_CDR.json";
import statusrAbi from "../../smart_contracts/abi_StatusR.json";

type SessionResult = any;
type VerificationEntry = {
  id: string;
  createdAt: string;
  authUrl: string;
  state: string;
  status: "pending" | "verified" | "failed";
  result?: "ok" | "not_ok" | "unknown";
  reason?: string;
  verificationVerdict?: "valid" | "invalid";
  statusListVerdict?: "valid" | "revoked";
  issuerActiveVerdict?: "valid" | "invalid";
  issuerAccreditedVerdict?: "valid" | "invalid";
  issuerOffchainVerdict?: "valid" | "invalid";
  issuerSchemaOnchainVerdict?: "valid" | "invalid";
  issuerSchemaOffchainVerdict?: "valid" | "invalid";
  issuerCredDefOnchainVerdict?: "valid" | "invalid";
  issuerCredDefOffchainVerdict?: "valid" | "invalid";
  issuerStatusListOnchainVerdict?: "valid" | "invalid";
  issuerStatusListOffchainVerdict?: "valid" | "invalid";
  issuerDidDocVerdict?: "valid" | "invalid";
  issuerAccreditationVerdict?: "valid" | "invalid";
  issuerSchemaId?: string;
  issuerCredDefId?: string;
  issuerDid?: string;
  expiresAt?: number;
};

const vpPolicyOptions = [
  { id: "signature", label: "signature" },
  { id: "holder-binding", label: "holder-binding" },
  { id: "presentation-definition", label: "presentation-definition" },
];

const vcPolicyOptions = [
  { id: "signature", label: "signature" },
  { id: "expired", label: "expired" },
  { id: "revoked-status-list", label: "revoked-status-list" },
  { id: "not-before", label: "not-before" },
  { id: "allowed-issuer", label: "allowed-issuer" },
  { id: "webhook", label: "webhook" },
  { id: "schema", label: "schema" },
];

const TIR_CONTRACT_ADDRESS = import.meta.env.VITE_TIR_CONTRACT_ADDRESS as string | undefined;
const TSR_CONTRACT_ADDRESS = import.meta.env.VITE_TSR_CONTRACT_ADDRESS as string | undefined;
const CDR_CONTRACT_ADDRESS = import.meta.env.VITE_CDR_CONTRACT_ADDRESS as string | undefined;
const STATUSR_CONTRACT_ADDRESS = import.meta.env.VITE_STATUSR_CONTRACT_ADDRESS as string | undefined;

const parseStateFromAuthUrl = (url: string) => {
  try {
    const u = new URL(url);
    const sp = u.searchParams.get("state");
    if (sp) return sp;
  } catch {
    /* ignore */
  }
  const match = url.match(/state=([^&#]+)/);
  return match ? decodeURIComponent(match[1]) : "";
};

export default function VerifierPage() {
  const { toast } = useToast();
  const [authorizeBaseUrl, setAuthorizeBaseUrl] = useState("openid4vp://authorize");
  const [responseMode, setResponseMode] = useState("");
  const [successRedirectUri, setSuccessRedirectUri] = useState("");
  const [errorRedirectUri, setErrorRedirectUri] = useState("");
  const [statusCallbackUri, setStatusCallbackUri] = useState("");
  const [sessionTtl, setSessionTtl] = useState("");
  const [requestCredentialType, setRequestCredentialType] = useState("UniversityDegreeCredential");
  const [requestCredentialFormat, setRequestCredentialFormat] = useState("jwt_vc_json");
  const [authUrl, setAuthUrl] = useState("");
  const [stateParam, setStateParam] = useState("");
  const [statusResult, setStatusResult] = useState<SessionResult>(null);
  const [vpPolicies, setVpPolicies] = useState<Set<string>>(new Set());
  const [vcPolicies, setVcPolicies] = useState<Set<string>>(new Set());
  const [loadingInit, setLoadingInit] = useState(false);
  const [loadingStatus, setLoadingStatus] = useState(false);
  const [error, setError] = useState("");
  const [verificationLog, setVerificationLog] = useState<VerificationEntry[]>([]);
  const [now, setNow] = useState(() => Date.now());
  const [localStatusLoading, setLocalStatusLoading] = useState(false);
  const [localStatusError, setLocalStatusError] = useState("");
  const [localStatusResult, setLocalStatusResult] = useState<{
    statusListCredential: string;
    statusListIndex: number;
    statusPurpose: string;
    bit: number;
    verdict: string;
    source: "embedded" | "fetched";
  } | null>(null);
  const [lastCheckedState, setLastCheckedState] = useState("");
  const [issuerAccredited, setIssuerAccredited] = useState<"" | "valid" | "invalid">("");
  const [issuerActive, setIssuerActive] = useState<"" | "valid" | "invalid">("");
  const [issuerOffchain, setIssuerOffchain] = useState<"" | "valid" | "invalid">("");
  const [issuerSchemaOnchain, setIssuerSchemaOnchain] = useState<"" | "valid" | "invalid">("");
  const [issuerSchemaRegistry, setIssuerSchemaRegistry] = useState<"" | "valid" | "invalid">("");
  const [issuerSchemaOffchain, setIssuerSchemaOffchain] = useState<"" | "valid" | "invalid">("");
  const [issuerCredDefOnchain, setIssuerCredDefOnchain] = useState<"" | "valid" | "invalid">("");
  const [issuerCredDefOffchain, setIssuerCredDefOffchain] = useState<"" | "valid" | "invalid">("");
  const [issuerStatusListOnchain, setIssuerStatusListOnchain] = useState<"" | "valid" | "invalid">("");
  const [issuerStatusListOffchain, setIssuerStatusListOffchain] = useState<"" | "valid" | "invalid">("");
  const [issuerDidDoc, setIssuerDidDoc] = useState<"" | "valid" | "invalid">("");
  const [issuerAccreditationDoc, setIssuerAccreditationDoc] = useState<"" | "valid" | "invalid">("");
  const [issuerIssuanceTiming, setIssuerIssuanceTiming] = useState<"" | "valid" | "invalid">("");
  const [issuerAccreditedDid, setIssuerAccreditedDid] = useState("");
  const [issuerAccreditedError, setIssuerAccreditedError] = useState("");
  const [issuerActiveError, setIssuerActiveError] = useState("");
  const [issuerSchemaOnchainError, setIssuerSchemaOnchainError] = useState("");
  const [issuerSchemaRegistryError, setIssuerSchemaRegistryError] = useState("");
  const [issuerSchemaOffchainError, setIssuerSchemaOffchainError] = useState("");
  const [issuerCredDefOnchainError, setIssuerCredDefOnchainError] = useState("");
  const [issuerCredDefOffchainError, setIssuerCredDefOffchainError] = useState("");
  const [issuerStatusListOnchainError, setIssuerStatusListOnchainError] = useState("");
  const [issuerStatusListOffchainError, setIssuerStatusListOffchainError] = useState("");
  const [issuerOffchainError, setIssuerOffchainError] = useState("");
  const [issuerDidDocError, setIssuerDidDocError] = useState("");
  const [issuerAccreditationError, setIssuerAccreditationError] = useState("");
  const [issuerIssuanceTimingError, setIssuerIssuanceTimingError] = useState("");
  const [issuerSchemaId, setIssuerSchemaId] = useState("");
  const [issuerCredDefId, setIssuerCredDefId] = useState("");

  const verificationVerdict = useMemo(() => {
    const pick = (obj: any): unknown => {
      if (!obj || typeof obj !== "object") return undefined;
      if (obj.verificationResult !== undefined) return obj.verificationResult;
      if (obj.verification_result !== undefined) return obj.verification_result;
      if (obj.result !== undefined && typeof obj.result === "object") {
        if (obj.result.verificationResult !== undefined) return obj.result.verificationResult;
        if (obj.result.verification_result !== undefined) return obj.result.verification_result;
      }
      if (obj.session !== undefined) return pick(obj.session);
      return undefined;
    };
    const val = pick(statusResult);
    if (val === true) return "valid";
    if (val === false) return "invalid";
    return "";
  }, [statusResult]);

  const statusListVerdict = useMemo(() => {
    if (!localStatusResult) return "";
    return localStatusResult.bit === 0 ? "valid" : "revoked";
  }, [localStatusResult]);

  const combinedVerdict = useMemo(() => {
    if (
      !verificationVerdict ||
      !statusListVerdict ||
      !issuerAccredited ||
      !issuerSchemaOnchain ||
      !issuerSchemaRegistry ||
      !issuerOffchain ||
      !issuerSchemaOffchain ||
      !issuerCredDefOnchain ||
      !issuerCredDefOffchain ||
      !issuerStatusListOnchain ||
      !issuerStatusListOffchain ||
      !issuerDidDoc ||
      !issuerAccreditationDoc ||
      !issuerIssuanceTiming
    ) {
      return "";
    }
    if (
      verificationVerdict === "valid" &&
      statusListVerdict === "valid" &&
      issuerAccredited === "valid" &&
      issuerSchemaOnchain === "valid" &&
      issuerSchemaRegistry === "valid" &&
      issuerOffchain === "valid" &&
      issuerSchemaOffchain === "valid" &&
      issuerCredDefOnchain === "valid" &&
      issuerCredDefOffchain === "valid" &&
      issuerStatusListOnchain === "valid" &&
      issuerStatusListOffchain === "valid" &&
      issuerDidDoc === "valid" &&
      issuerAccreditationDoc === "valid" &&
      issuerIssuanceTiming === "valid"
    ) {
      return "valid";
    }
    return "invalid";
  }, [
    verificationVerdict,
    statusListVerdict,
    issuerAccredited,
    issuerSchemaOnchain,
    issuerSchemaRegistry,
    issuerOffchain,
    issuerSchemaOffchain,
    issuerCredDefOnchain,
    issuerCredDefOffchain,
    issuerStatusListOnchain,
    issuerStatusListOffchain,
    issuerDidDoc,
    issuerAccreditationDoc,
    issuerIssuanceTiming,
  ]);

  const togglePolicy = (setter: Dispatch<SetStateAction<Set<string>>>) => (id: string) => {
    setter((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const vpPoliciesArr = useMemo(() => Array.from(vpPolicies), [vpPolicies]);
  const vcPoliciesArr = useMemo(() => Array.from(vcPolicies), [vcPolicies]);
  const latestVerification = verificationLog[0] || null;
  const sessionTtlMs = latestVerification?.expiresAt ? Math.max(0, latestVerification.expiresAt - now) : null;

  const formatCountdown = (ms: number | null) => {
    if (ms === null) return "—";
    const total = Math.max(0, Math.floor(ms / 1000));
    const min = Math.floor(total / 60);
    const sec = total % 60;
    return `${min}:${sec.toString().padStart(2, "0")}`;
  };

  useMemo(() => {
    if (!verificationLog.some((v) => v.expiresAt)) return;
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [verificationLog]);

  const normalizeBase64 = (input: string) => {
    const clean = String(input || "").replace(/[\r\n\s]/g, "");
    let normalized = clean.replace(/-/g, "+").replace(/_/g, "/");
    while (normalized.length % 4) normalized += "=";
    return normalized;
  };

  const decodeBase64ToBytes = (input: string) => {
    const normalized = normalizeBase64(input);
    const bin = atob(normalized);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) bytes[i] = bin.charCodeAt(i);
    return bytes;
  };

  const gunzipIfNeeded = async (bytes: Uint8Array) => {
    const isGzip = bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
    if (!isGzip) return bytes;
    if (typeof DecompressionStream !== "undefined") {
      const ds = new DecompressionStream("gzip") as unknown as ReadableWritablePair<Uint8Array, Uint8Array>;
      const stream = new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(bytes);
          controller.close();
        },
      }).pipeThrough(ds);
      const out = await new Response(stream).arrayBuffer();
      return new Uint8Array(out);
    }
    return bytes;
  };

  const bitAtIndex = (rawBytes: Uint8Array, index: number) => {
    if (!Number.isFinite(index) || index < 0) throw new Error("Invalid status list index.");
    const byteIndex = Math.floor(index / 8);
    if (byteIndex >= rawBytes.length) {
      throw new Error(`Index ${index} exceeds status list length.`);
    }
    const bitIndex = 7 - (index % 8);
    return (rawBytes[byteIndex] & (1 << bitIndex)) ? 1 : 0;
  };

  const pickStatusEntry = (vc: any) => {
    const entries: any[] = [];
    const push = (cand: any) => {
      if (!cand) return;
      if (Array.isArray(cand)) cand.forEach((x) => entries.push(x));
      else if (typeof cand === "object") entries.push(cand);
    };
    push(vc?.credentialStatus);
    push(vc?.credentialStatus?.entries);
    push(vc?.credentialStatus?.items);
    const preferred = entries.find((e) => {
      const types = Array.isArray(e?.type) ? e.type : e?.type ? [e.type] : [];
      return types.includes("StatusList2021Entry");
    });
    return preferred || entries[0] || null;
  };

  const resolveStatusListUrl = (entry: any) => {
    if (!entry || typeof entry !== "object") return "";
    if (entry.statusListCredential) return entry.statusListCredential;
    if (entry.statusList) return entry.statusList;
    if (entry.statusListUri) return entry.statusListUri;
    if (typeof entry.id === "string" && entry.id.includes("#")) return entry.id.split("#")[0];
    return "";
  };

  const resolveStatusIndex = (entry: any) => {
    if (!entry || typeof entry !== "object") return Number.NaN;
    const candidates = [entry.statusListIndex, entry.index, entry.statusIndex];
    for (const c of candidates) {
      const n = Number(c);
      if (Number.isFinite(n)) return n;
    }
    if (typeof entry.id === "string" && entry.id.includes("#")) {
      const frag = entry.id.split("#").pop();
      const n = Number(frag);
      if (Number.isFinite(n)) return n;
    }
    return Number.NaN;
  };

  const normalizeCredentialObject = (candidate: any) => {
    if (!candidate) return null;
    if (typeof candidate === "string") {
      const parts = candidate.split(".");
      if (parts.length === 3) {
        try {
          const payload = JSON.parse(new TextDecoder().decode(decodeBase64ToBytes(parts[1])));
          return payload.vc || payload;
        } catch {
          return null;
        }
      }
      try {
        return JSON.parse(candidate);
      } catch {
        return null;
      }
    }
    if (typeof candidate === "object") return candidate;
    return null;
  };

  const extractFirstCredential = (payload: any) => {
    const seen = new Set<any>();
    const queue = [payload];
    while (queue.length) {
      const node = queue.shift();
      if (!node || typeof node !== "object") continue;
      if (seen.has(node)) continue;
      seen.add(node);
      if (Array.isArray(node)) {
        queue.push(...node);
        continue;
      }
      if (node.verifiableCredential) {
        const arr = Array.isArray(node.verifiableCredential) ? node.verifiableCredential : [node.verifiableCredential];
        const normalized = normalizeCredentialObject(arr[0]);
        if (normalized) return normalized;
      }
      const types = Array.isArray(node.type) ? node.type : node.type ? [node.type] : [];
      if (types.includes("VerifiableCredential") || node.credentialStatus) return node;
      Object.values(node).forEach((v) => queue.push(v));
    }
    return null;
  };

  const extractIssuerDid = (vc: any) => {
    if (!vc || typeof vc !== "object") return "";
    const issuer = vc.issuer;
    if (typeof issuer === "string") return issuer;
    if (issuer && typeof issuer === "object" && typeof issuer.id === "string") return issuer.id;
    return "";
  };

  const extractSchemaIds = (vc: any) => {
    if (!vc || typeof vc !== "object") return [];
    const schema = vc.credentialSchema ?? vc.credential_schema;
    const ids: string[] = [];
    if (Array.isArray(schema)) {
      schema.forEach((s) => {
        if (s && typeof s === "object" && typeof s.id === "string") ids.push(s.id);
        else if (typeof s === "string") ids.push(s);
      });
      return ids;
    }
    if (schema && typeof schema === "object" && typeof schema.id === "string") return [schema.id];
    if (typeof schema === "string") return [schema];
    return [];
  };

  const extractCredDefId = (vc: any) => {
    if (!vc || typeof vc !== "object") return "";
    const cd = vc.credentialDefinition ?? vc.credential_definition;
    if (cd && typeof cd === "object" && typeof cd.id === "string") return cd.id;
    if (typeof cd === "string") return cd;
    return "";
  };

  const extractCredDefDoc = (vc: any) => {
    if (!vc || typeof vc !== "object") return null;
    const cd = vc.credentialDefinition ?? vc.credential_definition;
    if (!cd || typeof cd !== "object") return null;
    const keys = Object.keys(cd as Record<string, unknown>);
    if (keys.length === 0) return null;
    if (keys.every((k) => k === "id" || k === "type")) return null;
    return cd as Record<string, unknown>;
  };

  const getTirContract = async () => {
    if (!TIR_CONTRACT_ADDRESS || TIR_CONTRACT_ADDRESS === "0x0000000000000000000000000000000000000000") {
      throw new Error("Missing VITE_TIR_CONTRACT_ADDRESS in .env.");
    }
    const ethereum = (window as { ethereum?: Eip1193Provider }).ethereum;
    if (!ethereum) {
      throw new Error("No wallet detected. Install MetaMask or another EVM wallet.");
    }
    const provider = new BrowserProvider(ethereum);
    const network = await provider.getNetwork();
    const expectedChainId = import.meta.env.VITE_CHAIN_ID
      ? Number(import.meta.env.VITE_CHAIN_ID)
      : null;
    if (expectedChainId && Number(network.chainId) !== expectedChainId) {
      throw new Error(
        `Wrong network. Wallet is on chain ${network.chainId.toString()} (${network.name}); expected ${expectedChainId}.`
      );
    }
    const code = await provider.getCode(TIR_CONTRACT_ADDRESS);
    if (!code || code === "0x") {
      throw new Error(
        `TIR contract not found at ${TIR_CONTRACT_ADDRESS} on chain ${network.chainId.toString()} (${network.name}).`
      );
    }
    return new Contract(TIR_CONTRACT_ADDRESS, tirAbi, provider);
  };

  const getTsrContract = async () => {
    if (!TSR_CONTRACT_ADDRESS || TSR_CONTRACT_ADDRESS === "0x0000000000000000000000000000000000000000") {
      throw new Error("Missing VITE_TSR_CONTRACT_ADDRESS in .env.");
    }
    const ethereum = (window as { ethereum?: Eip1193Provider }).ethereum;
    if (!ethereum) {
      throw new Error("No wallet detected. Install MetaMask or another EVM wallet.");
    }
    const provider = new BrowserProvider(ethereum);
    const network = await provider.getNetwork();
    const expectedChainId = import.meta.env.VITE_CHAIN_ID
      ? Number(import.meta.env.VITE_CHAIN_ID)
      : null;
    if (expectedChainId && Number(network.chainId) !== expectedChainId) {
      throw new Error(
        `Wrong network. Wallet is on chain ${network.chainId.toString()} (${network.name}); expected ${expectedChainId}.`
      );
    }
    const code = await provider.getCode(TSR_CONTRACT_ADDRESS);
    if (!code || code === "0x") {
      throw new Error(
        `TSR contract not found at ${TSR_CONTRACT_ADDRESS} on chain ${network.chainId.toString()} (${network.name}).`
      );
    }
    return new Contract(TSR_CONTRACT_ADDRESS, tsrAbi, provider);
  };

  const getCdrContract = async () => {
    if (!CDR_CONTRACT_ADDRESS || CDR_CONTRACT_ADDRESS === "0x0000000000000000000000000000000000000000") {
      throw new Error("Missing VITE_CDR_CONTRACT_ADDRESS in .env.");
    }
    const ethereum = (window as { ethereum?: Eip1193Provider }).ethereum;
    if (!ethereum) {
      throw new Error("No wallet detected. Install MetaMask or another EVM wallet.");
    }
    const provider = new BrowserProvider(ethereum);
    const network = await provider.getNetwork();
    const expectedChainId = import.meta.env.VITE_CHAIN_ID
      ? Number(import.meta.env.VITE_CHAIN_ID)
      : null;
    if (expectedChainId && Number(network.chainId) !== expectedChainId) {
      throw new Error(
        `Wrong network. Wallet is on chain ${network.chainId.toString()} (${network.name}); expected ${expectedChainId}.`
      );
    }
    const code = await provider.getCode(CDR_CONTRACT_ADDRESS);
    if (!code || code === "0x") {
      throw new Error(
        `CDR contract not found at ${CDR_CONTRACT_ADDRESS} on chain ${network.chainId.toString()} (${network.name}).`
      );
    }
    return new Contract(CDR_CONTRACT_ADDRESS, cdrAbi, provider);
  };

  const getStatusRContract = async () => {
    if (!STATUSR_CONTRACT_ADDRESS || STATUSR_CONTRACT_ADDRESS === "0x0000000000000000000000000000000000000000") {
      throw new Error("Missing VITE_STATUSR_CONTRACT_ADDRESS in .env.");
    }
    const ethereum = (window as { ethereum?: Eip1193Provider }).ethereum;
    if (!ethereum) {
      throw new Error("No wallet detected. Install MetaMask or another EVM wallet.");
    }
    const provider = new BrowserProvider(ethereum);
    const network = await provider.getNetwork();
    const expectedChainId = import.meta.env.VITE_CHAIN_ID
      ? Number(import.meta.env.VITE_CHAIN_ID)
      : null;
    if (expectedChainId && Number(network.chainId) !== expectedChainId) {
      throw new Error(
        `Wrong network. Wallet is on chain ${network.chainId.toString()} (${network.name}); expected ${expectedChainId}.`
      );
    }
    const code = await provider.getCode(STATUSR_CONTRACT_ADDRESS);
    if (!code || code === "0x") {
      throw new Error(
        `StatusR contract not found at ${STATUSR_CONTRACT_ADDRESS} on chain ${network.chainId.toString()} (${network.name}).`
      );
    }
    return new Contract(STATUSR_CONTRACT_ADDRESS, statusrAbi, provider);
  };

  const resolveAllVaUrl = () => {
    const host = import.meta.env.VITE_URL || "192.168.93.134";
    return `http://${host}/dev/vc/accreditation/allVA.json`;
  };

  const resolveDidDocUrl = (did: string) => {
    const host = import.meta.env.VITE_URL || "192.168.93.134";
    const suffix = did.split(":").pop() || did;
    return `http://${host}/dev/did/${suffix}/1.0.0.json`;
  };

  const normalizeDid = (did: string) => did.split("#")[0].split("?")[0];
  const ZERO_HASH = `0x${"00".repeat(32)}`;

  const resolveAccreditationVcUrl = (did: string) => {
    const host = import.meta.env.VITE_URL || "192.168.93.134";
    const suffix = did.split(":").pop() || did;
    return `http://${host}/dev/vc/accreditation/${suffix}/1.0.0.json`;
  };

  const normalizeAccreditationUrl = (metadataURI: string) => {
    const trimmed = metadataURI.trim();
    if (!trimmed) return trimmed;
    const match = trimmed.match(/\/vc\/accreditation\/([^/]+)\.json$/);
    if (match) {
      const issuerSuffix = match[1];
      return trimmed.replace(
        /\/vc\/accreditation\/[^/]+\.json$/,
        `/vc/accreditation/${issuerSuffix}/1.0.0.json`
      );
    }
    const missingVersion = trimmed.match(/\/vc\/accreditation\/([^/]+)$/);
    if (missingVersion) {
      const issuerSuffix = missingVersion[1];
      return `${trimmed.replace(/\/$/, "")}/${issuerSuffix}/1.0.0.json`;
    }
    return trimmed;
  };

  const extractIssuanceDate = (vc: any) => {
    if (!vc || typeof vc !== "object") return "";
    if (typeof vc.issuanceDate === "string") return vc.issuanceDate;
    if (typeof vc.issued === "string") return vc.issued;
    if (typeof vc.validFrom === "string") return vc.validFrom;
    return "";
  };

  const toUnixSecondsSafe = (value: string) => {
    if (!value) return null;
    const parsed = Date.parse(value);
    if (Number.isNaN(parsed)) return null;
    return Math.floor(parsed / 1000);
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

  const resolveJsonHash = async (value: string) => {
    const trimmed = value.trim();
    if (!trimmed) return "";
    if (isHexString(trimmed, 32) || /^[0-9a-fA-F]{64}$/.test(trimmed)) {
      return normalizeHash32(trimmed);
    }
    if (!/^https?:\/\//i.test(trimmed)) {
      throw new Error(`Invalid URL for JSON hash: ${trimmed}`);
    }
    const res = await fetch(trimmed, { cache: "no-store" });
    if (!res.ok) throw new Error(`GET ${trimmed} -> ${res.status}`);
    const json = await res.json();
    return normalizeHash32(canonicalKeccak(json));
  };

  const resolveJsonHashList = async (values: string[]) => {
    const results = await Promise.all(values.map((value) => resolveJsonHash(value)));
    return results.filter(Boolean);
  };

  const isNoDataError = (error: unknown) => {
    if (!error || typeof error !== "object") return false;
    const err = error as { code?: string; shortMessage?: string; message?: string };
    return (
      err.code === "BAD_DATA" ||
      String(err.shortMessage || err.message || "").toLowerCase().includes("could not decode result data")
    );
  };

  const safeContractRead = async <T,>(fn: () => Promise<T>) => {
    try {
      const value = await fn();
      return { value, error: null as unknown };
    } catch (error) {
      return { value: null as T | null, error };
    }
  };

  const verifyIssuerAccredited = async (payload: any, signal: { aborted: boolean }) => {
    setIssuerAccredited("");
    setIssuerActive("");
    setIssuerOffchain("");
    setIssuerSchemaOnchain("");
    setIssuerSchemaRegistry("");
    setIssuerSchemaOffchain("");
    setIssuerCredDefOnchain("");
    setIssuerCredDefOffchain("");
    setIssuerStatusListOnchain("");
    setIssuerStatusListOffchain("");
    setIssuerDidDoc("");
    setIssuerAccreditationDoc("");
    setIssuerIssuanceTiming("");
    setIssuerAccreditedDid("");
    setIssuerAccreditedError("");
    setIssuerActiveError("");
    setIssuerSchemaOnchainError("");
    setIssuerSchemaRegistryError("");
    setIssuerSchemaOffchainError("");
    setIssuerCredDefOnchainError("");
    setIssuerCredDefOffchainError("");
    setIssuerStatusListOnchainError("");
    setIssuerStatusListOffchainError("");
    setIssuerOffchainError("");
    setIssuerDidDocError("");
    setIssuerAccreditationError("");
    setIssuerIssuanceTimingError("");
    setIssuerSchemaId("");
    setIssuerCredDefId("");
    if (!payload) return;
    try {
      const vc = extractFirstCredential(payload);
      if (!vc) throw new Error("No VerifiableCredential found in verifier response.");
      const issuerDid = normalizeDid(extractIssuerDid(vc));
      if (!issuerDid) throw new Error("Issuer DID missing in VC.");
      const schemaIds = extractSchemaIds(vc).map((id) => id.trim()).filter(Boolean);
      const schemaId = schemaIds[0] || "";
      const credDefId = extractCredDefId(vc).trim();
      let credDefDocHash = "";
      let credDefDocHashError = "";
      const credDefDoc = extractCredDefDoc(vc);
      if (credDefId) {
        if (isHexString(credDefId, 32) || /^[0-9a-fA-F]{64}$/.test(credDefId)) {
          credDefDocHash = normalizeHash32(credDefId);
        } else if (/^https?:\/\//i.test(credDefId)) {
          try {
            const res = await fetch(credDefId, { cache: "no-store" });
            if (!res.ok) throw new Error(`GET ${credDefId} -> ${res.status}`);
            const credDefDocRemote = await res.json();
            credDefDocHash = canonicalKeccak(credDefDocRemote);
          } catch (e) {
            credDefDocHashError = e instanceof Error ? e.message : String(e);
          }
        } else if (credDefDoc) {
          try {
            credDefDocHash = canonicalKeccak(credDefDoc);
          } catch (e) {
            credDefDocHashError = e instanceof Error ? e.message : String(e);
          }
        } else {
          credDefDocHashError = "Credential definition ID is not a URL or bytes32 hash.";
        }
      } else if (credDefDoc) {
        try {
          credDefDocHash = canonicalKeccak(credDefDoc);
        } catch (e) {
          credDefDocHashError = e instanceof Error ? e.message : String(e);
        }
      }
      if (credDefDocHash) {
        credDefDocHash = normalizeHash32(credDefDocHash);
      }
      const contract = await getTirContract();
      const localDidHash = keccak256(toUtf8Bytes(issuerDid));
      const didKeyRead = await safeContractRead(() => contract.didKey(issuerDid));
      const didHash =
        typeof didKeyRead.value === "string" && didKeyRead.value
          ? didKeyRead.value
          : localDidHash;
      const contractAddress = await contract.getAddress();
      const network = await (contract.runner as BrowserProvider | undefined)?.getNetwork?.();
      console.log("[Verifier] TIR contract", {
        contractAddress,
        chainId: network?.chainId?.toString?.() ?? "",
        name: network?.name ?? "",
      });
      console.log("[Verifier] did hash", {
        issuerDid,
        localDidHash,
        contractDidHash: didHash,
        didKeyError: didKeyRead.error ? String(didKeyRead.error) : "",
      });
      const nowSeconds = Math.floor(Date.now() / 1000);
      const isWithinWindow = (from: number, until: number) =>
        from <= nowSeconds && (until === 0 || until >= nowSeconds);
      let okAccredited = false;
      let okActive = false;
      let onchainError = "";
      let coreActive = false;
      let accActiveFromCore = false;
      let onchainAccHash = "";
      let onchainMetadataURI = "";
      let issuerValidFromSeconds = 0;
      let accValidFromSeconds = 0;

      const coreRead = await safeContractRead(() => contract.getIssuerCore(didHash));
      if (coreRead.value) {
        const core = coreRead.value as unknown as Record<string, unknown> & any[];
        console.log("[Verifier] getIssuerCore raw", core);
        const exists = Boolean(core?.exists ?? core?.[0]);
        const status = Number(core?.issuerStatus ?? core?.[1] ?? 0);
        const validFrom = Number(core?.validFrom ?? core?.[2] ?? 0);
        const validUntil = Number(core?.validUntil ?? core?.[3] ?? 0);
        const accStatus = Number(core?.accreditationStatus ?? core?.[5] ?? 0);
        const accValidFrom = Number(core?.accreditationValidFrom ?? core?.[6] ?? 0);
        const accValidUntil = Number(core?.accreditationValidUntil ?? core?.[7] ?? 0);
        coreActive = exists && status === 1 && isWithinWindow(validFrom, validUntil);
        accActiveFromCore = accStatus === 1 && isWithinWindow(accValidFrom, accValidUntil);
        issuerValidFromSeconds = validFrom;
        accValidFromSeconds = accValidFrom;
        const rawAccHash = core?.accreditationHash ?? core?.[4] ?? "";
        try {
          onchainAccHash = typeof rawAccHash === "string" ? rawAccHash : hexlify(rawAccHash as any);
        } catch {
          onchainAccHash = "";
        }
        onchainMetadataURI =
          typeof core?.metadataURI === "string"
            ? core.metadataURI
            : typeof core?.[8] === "string"
              ? core[8]
              : "";
        console.log("[Verifier] getIssuerCore", {
          didHash,
          exists,
          status,
          validFrom,
          validUntil,
          accStatus,
          accValidFrom,
          accValidUntil,
          onchainAccHash,
          onchainMetadataURI,
        });
      } else if (coreRead.error && !isNoDataError(coreRead.error)) {
        onchainError = coreRead.error instanceof Error ? coreRead.error.message : String(coreRead.error);
        console.warn("[Verifier] getIssuerCore error", coreRead.error);
      } else if (coreRead.error) {
        onchainError =
          "TIR getIssuerCore returned no data. Check network/contract address and that the DID was enrolled.";
        console.warn("[Verifier] getIssuerCore decode error", coreRead.error);
      }

      const accRead = await safeContractRead(() => contract.isAccreditedNowHash(didHash));
      if (typeof accRead.value === "boolean") {
        okAccredited = accRead.value;
        okActive = coreRead.value ? coreActive : accRead.value;
      } else if (coreRead.value) {
        okActive = coreActive;
        okAccredited = coreActive && accActiveFromCore;
      } else if (accRead.error && !isNoDataError(accRead.error)) {
        onchainError = accRead.error instanceof Error ? accRead.error.message : String(accRead.error);
      }
      const schemaHashes = await resolveJsonHashList(schemaIds);
      const credDefHash = credDefDocHash || "";

      console.log("[Verifier] on-chain checks input", {
        issuerDid,
        didHash,
        schemaIds,
        schemaHashes,
        credDefId,
        credDefHash: credDefHash || "",
      });
      let okSchema = false;
      let okCredDef = true;
      const schemaCandidates = schemaHashes.length ? schemaHashes : [ZERO_HASH];
      const credInput = credDefHash ? credDefHash : ZERO_HASH;
      let trustedError: unknown = null;
      for (const schemaHash of schemaCandidates) {
        const trustedRead = await safeContractRead(() =>
          contract.isTrustedIssuerForHash(didHash, schemaHash, credInput)
        );
        if (typeof trustedRead.value === "boolean") {
          if (trustedRead.value) {
            okSchema = true;
            break;
          }
        } else if (trustedRead.error && !isNoDataError(trustedRead.error)) {
          trustedError = trustedRead.error;
        }
      }
      if (!okSchema) {
        let schemaAllowed = schemaHashes.length === 0;
        if (schemaHashes.length) {
          for (const schemaHash of schemaHashes) {
            const schemaRead = await safeContractRead(() => contract.canIssueSchemaForHash(didHash, schemaHash));
            if (typeof schemaRead.value === "boolean") {
              if (schemaRead.value) {
                schemaAllowed = true;
                break;
              }
            } else if (schemaRead.error && !isNoDataError(schemaRead.error)) {
              onchainError = schemaRead.error instanceof Error ? schemaRead.error.message : String(schemaRead.error);
              schemaAllowed = false;
            }
          }
        }
        let credAllowed = true;
        if (credDefHash) {
          const credRead = await safeContractRead(() => contract.canIssueCredDefForHash(didHash, credDefHash));
          if (typeof credRead.value === "boolean") {
            credAllowed = credRead.value;
          } else if (credRead.error && !isNoDataError(credRead.error)) {
            onchainError = credRead.error instanceof Error ? credRead.error.message : String(credRead.error);
            credAllowed = false;
          }
        }
        okSchema = schemaAllowed && credAllowed;
        okCredDef = credAllowed;
        if (trustedError && !onchainError) {
          onchainError = trustedError instanceof Error ? trustedError.message : String(trustedError);
        }
      }
      if (signal.aborted) return;
      setIssuerAccreditedDid(issuerDid);
      setIssuerSchemaId(schemaId);
      setIssuerCredDefId(credDefId);
      setIssuerActive(okActive ? "valid" : "invalid");
      setIssuerAccredited(okAccredited && okActive ? "valid" : "invalid");
      setIssuerSchemaOnchain(okSchema && okCredDef ? "valid" : "invalid");
      if (!signal.aborted) {
        if (!okActive) {
          setIssuerActiveError("Issuer not active on-chain or outside validity window.");
        }
        if (okActive && !okAccredited) {
          setIssuerAccreditedError("Issuer accreditation not active on-chain.");
        }
        if (!okSchema || !okCredDef) {
          setIssuerSchemaOnchainError("Issuer not trusted for schema/credDef on-chain.");
        }
        if (onchainError) {
          setIssuerAccreditedError(onchainError);
        }
      }

      try {
        const tsr = await getTsrContract();
        const schemaChecks: { id: string; ok: boolean; reason?: string }[] = [];
        for (const schemaId of schemaIds) {
          const urlHash = keccak256(toUtf8Bytes(schemaId));
          let ok = false;
          let reason = "";
          const primary = await safeContractRead(() => tsr.getSchema(urlHash));
          if (primary.value) {
            const status = Number((primary.value as any)?.status ?? (primary.value as any)?.[3] ?? 0);
            ok = status === 1;
            if (!ok) reason = "Schema status not active.";
          } else {
            try {
              const res = await fetch(schemaId, { cache: "no-store" });
              if (!res.ok) throw new Error(`GET ${schemaId} -> ${res.status}`);
              const schemaDoc = await res.json();
              const docHash = canonicalKeccak(schemaDoc);
              const fallback = await safeContractRead(() => tsr.getSchema(docHash));
              if (fallback.value) {
                const status = Number((fallback.value as any)?.status ?? (fallback.value as any)?.[3] ?? 0);
                ok = status === 1;
                if (!ok) reason = "Schema status not active.";
              } else {
                reason = "Schema not found in TSR.";
              }
            } catch (e) {
              reason = e instanceof Error ? e.message : String(e);
            }
          }
          schemaChecks.push({ id: schemaId, ok, reason });
        }
        if (!signal.aborted) {
          const allOk = schemaChecks.length ? schemaChecks.every((s) => s.ok) : true;
          setIssuerSchemaRegistry(allOk ? "valid" : "invalid");
          if (!allOk) {
            const reasons = schemaChecks.filter((s) => !s.ok).map((s) => `${s.id}: ${s.reason || "invalid"}`);
            setIssuerSchemaRegistryError(reasons.join(" | "));
          }
        }
      } catch (e) {
        if (!signal.aborted) {
          setIssuerSchemaRegistry("invalid");
          setIssuerSchemaRegistryError(e instanceof Error ? e.message : String(e));
        }
      }

      try {
        if (!credDefId) {
          setIssuerCredDefOnchain("valid");
        } else {
          const cdr = await getCdrContract();
          let ok = false;
          let reason = "";
          if (!credDefDocHash) {
            ok = false;
            reason = credDefDocHashError || "Credential definition hash missing.";
          } else {
            console.log("[Verifier] CDR isActive call", {
              credDefId,
              credDefHash: credDefDocHash,
            });
            const activeRead = await safeContractRead(() => cdr.isActive(credDefDocHash));
            console.log("[Verifier] CDR isActive response", {
              credDefId,
              credDefHash: credDefDocHash,
              value: activeRead.value,
              error: activeRead.error ? String(activeRead.error) : "",
            });
            if (typeof activeRead.value === "boolean") {
              ok = activeRead.value;
              if (!ok) reason = "CDR isActive returned false.";
            } else if (activeRead.error && !isNoDataError(activeRead.error)) {
              reason = activeRead.error instanceof Error ? activeRead.error.message : String(activeRead.error);
            } else {
              reason = "CDR isActive returned no data.";
            }
            if (ok) {
              try {
                console.log("[Verifier] CDR getCredDef call", {
                  credDefId,
                  credDefHash: credDefDocHash,
                });
                const primary = await safeContractRead(() => cdr.getCredDef(credDefDocHash));
                console.log("[Verifier] CDR getCredDef response", {
                  credDefId,
                  credDefHash: credDefDocHash,
                  value: primary.value,
                  error: primary.error ? String(primary.error) : "",
                });
                const extractSchemaHash = (value: any) => (value?.schemaHash ?? value?.[2] ?? "") as string;
                if (primary.value) {
                  const onchainSchemaHash = normalizeHash32(String(extractSchemaHash(primary.value) || ""));
                  if (onchainSchemaHash && schemaIds.length) {
                    const schemaDocHashes: string[] = [];
                    for (const schemaId of schemaIds) {
                      const res = await fetch(schemaId, { cache: "no-store" });
                      if (!res.ok) throw new Error(`GET ${schemaId} -> ${res.status}`);
                      const schemaDoc = await res.json();
                      schemaDocHashes.push(normalizeHash32(canonicalKeccak(schemaDoc)));
                    }
                    if (!schemaDocHashes.includes(onchainSchemaHash)) {
                      ok = false;
                      reason = "CDR schemaHash does not match VC schema.";
                    }
                  }
                } else if (primary.error && !isNoDataError(primary.error)) {
                  ok = false;
                  reason = primary.error instanceof Error ? primary.error.message : String(primary.error);
                }
              } catch (e) {
                ok = false;
                reason = e instanceof Error ? e.message : String(e);
              }
            }
          }
          if (!signal.aborted) {
            setIssuerCredDefOnchain(ok ? "valid" : "invalid");
            if (!ok) setIssuerCredDefOnchainError(reason || "Credential definition invalid on-chain.");
          }
        }
      } catch (e) {
        if (!signal.aborted) {
          setIssuerCredDefOnchain("invalid");
          setIssuerCredDefOnchainError(e instanceof Error ? e.message : String(e));
        }
      }

      try {
        const statusEntry = pickStatusEntry(vc);
        const listUrl = resolveStatusListUrl(statusEntry);
        const purposeRaw = String(statusEntry?.statusPurpose || statusEntry?.purpose || "").toLowerCase();
        if (!statusEntry || !listUrl) {
          if (!signal.aborted) {
            setIssuerStatusListOnchain("");
            setIssuerStatusListOffchain("");
          }
        } else if (!credDefDocHash) {
          if (!signal.aborted) {
            setIssuerStatusListOnchain("invalid");
            setIssuerStatusListOffchain("invalid");
            setIssuerStatusListOnchainError(credDefDocHashError || "Credential definition hash missing.");
          }
        } else {
          const purposeEnum = purposeRaw === "suspension" ? 1 : 0;
          const statusr = await getStatusRContract();
          const listIdRead = await safeContractRead(() =>
            statusr.deriveListId(localDidHash, credDefDocHash, purposeEnum)
          );
          const listId = typeof listIdRead.value === "string" ? listIdRead.value : "";
          if (!listId) {
            throw new Error("Status list ID derivation failed.");
          }
          const listRead = await safeContractRead(() => statusr.getStatusList(listId));
          if (!listRead.value) {
            const reason = listRead.error && !isNoDataError(listRead.error)
              ? (listRead.error instanceof Error ? listRead.error.message : String(listRead.error))
              : "Status list not found in StatusR.";
            if (!signal.aborted) {
              setIssuerStatusListOnchain("invalid");
              setIssuerStatusListOnchainError(reason);
              setIssuerStatusListOffchain("invalid");
              setIssuerStatusListOffchainError(reason);
            }
          } else {
            const status = Number((listRead.value as any)?.status ?? (listRead.value as any)?.[6] ?? 0);
            const onchainHash = normalizeHash32(
              String((listRead.value as any)?.listHash ?? (listRead.value as any)?.[4] ?? "")
            );
            const onchainUri = String((listRead.value as any)?.listURI ?? (listRead.value as any)?.[5] ?? "");
            const onchainOk = status === 1;
            if (!signal.aborted) {
              setIssuerStatusListOnchain(onchainOk ? "valid" : "invalid");
              if (!onchainOk) setIssuerStatusListOnchainError("Status list not active on-chain.");
              if (onchainOk && onchainUri && onchainUri !== listUrl) {
                setIssuerStatusListOnchain("invalid");
                setIssuerStatusListOnchainError("Status list URI mismatch on-chain.");
              }
            }
            try {
              const res = await fetch(listUrl, { cache: "no-store" });
              if (!res.ok) throw new Error(`GET ${listUrl} -> ${res.status}`);
              const listDoc = await res.json();
              const listHash = normalizeHash32(canonicalKeccak(listDoc));
              const docPurpose = String(listDoc?.credentialSubject?.statusPurpose || "").toLowerCase();
              let ok = listHash === onchainHash;
              let reason = ok ? "" : "Status list hash mismatch.";
              if (ok && purposeRaw && docPurpose && docPurpose !== purposeRaw) {
                ok = false;
                reason = "Status list purpose mismatch.";
              }
              if (!signal.aborted) {
                setIssuerStatusListOffchain(ok ? "valid" : "invalid");
                if (!ok) setIssuerStatusListOffchainError(reason || "Status list invalid off-chain.");
              }
            } catch (e) {
              if (!signal.aborted) {
                setIssuerStatusListOffchain("invalid");
                setIssuerStatusListOffchainError(e instanceof Error ? e.message : String(e));
              }
            }
          }
        }
      } catch (e) {
        if (!signal.aborted) {
          setIssuerStatusListOnchain("invalid");
          setIssuerStatusListOffchain("invalid");
          setIssuerStatusListOnchainError(e instanceof Error ? e.message : String(e));
        }
      }

      let entryDidDocUrl = "";
      try {
        const allVaUrl = resolveAllVaUrl();
        const res = await fetch(allVaUrl, { cache: "no-store" });
        if (!res.ok) throw new Error(`GET ${allVaUrl} -> ${res.status}`);
        const text = await res.text();
        const json = text.trim() ? JSON.parse(text) : {};
        let entry: Record<string, unknown> | null = null;
        if (Array.isArray(json)) {
          entry =
            (json.find(
              (item) =>
                item &&
                typeof item === "object" &&
                typeof (item as any).did === "string" &&
                String((item as any).did).split("#")[0].split("?")[0] === issuerDid
            ) as Record<string, unknown>) || null;
        } else if (json && typeof json === "object") {
          const values = Object.values(json as Record<string, unknown>);
          entry =
            (values.find(
              (item) =>
                item &&
                typeof item === "object" &&
                typeof (item as any).did === "string" &&
                String((item as any).did).split("#")[0].split("?")[0] === issuerDid
            ) as Record<string, unknown>) || null;
        }
        const offchainStatus = String(entry?.status || "");
        const allowedSchemas = Array.isArray(entry?.allowedSchemas)
          ? (entry?.allowedSchemas as unknown[]).filter((s) => typeof s === "string") as string[]
          : Array.isArray(entry?.credentialSchemas)
            ? (entry?.credentialSchemas as unknown[]).filter((s) => typeof s === "string") as string[]
            : [];
        const allowedCredDefs = Array.isArray(entry?.allowedCredDefs)
          ? (entry?.allowedCredDefs as unknown[]).filter((s) => typeof s === "string") as string[]
          : Array.isArray(entry?.credentialDefinitions)
            ? (entry?.credentialDefinitions as unknown[]).filter((s) => typeof s === "string") as string[]
            : [];
        entryDidDocUrl = typeof entry?.didDocUrl === "string" ? entry?.didDocUrl : "";
        const offchainAuthorized = offchainStatus === "accredited";
        const offchainSchemaOk = schemaIds.length
          ? allowedSchemas.length
            ? schemaIds.some((id) => allowedSchemas.includes(id))
            : true
          : true;
        const offchainCredDefOk = credDefId
          ? allowedCredDefs.length
            ? allowedCredDefs.includes(credDefId)
            : true
          : true;
        if (!signal.aborted) {
          setIssuerOffchain(offchainAuthorized ? "valid" : "invalid");
          setIssuerSchemaOffchain(offchainSchemaOk && offchainCredDefOk ? "valid" : "invalid");
          setIssuerCredDefOffchain(offchainCredDefOk ? "valid" : "invalid");
          if (!offchainAuthorized) {
            setIssuerOffchainError("Issuer not accredited in allVA.json.");
          }
          if (!offchainSchemaOk || !offchainCredDefOk) {
            setIssuerSchemaOffchainError("Issuer not allowed for schema/credDef in allVA.json.");
          }
          if (!offchainCredDefOk) {
            setIssuerCredDefOffchainError("Credential definition not allowed in allVA.json.");
          }
        }
      } catch (e) {
        if (!signal.aborted) {
          setIssuerOffchainError(e instanceof Error ? e.message : String(e));
          setIssuerOffchain("invalid");
          setIssuerSchemaOffchain("invalid");
          setIssuerCredDefOffchain("invalid");
        }
      }

      try {
        const didDocUrl = entryDidDocUrl || resolveDidDocUrl(issuerDid);
        const res = await fetch(didDocUrl, { cache: "no-store" });
        if (!res.ok) throw new Error(`GET ${didDocUrl} -> ${res.status}`);
        const doc = await res.json();
        const docId = typeof doc?.id === "string" ? doc.id : "";
        const okDoc = docId ? docId.split("#")[0].split("?")[0] === issuerDid : true;
        if (!signal.aborted) {
          setIssuerDidDoc(okDoc ? "valid" : "invalid");
        }
      } catch (e) {
        if (!signal.aborted) {
          setIssuerDidDocError(e instanceof Error ? e.message : String(e));
          setIssuerDidDoc("invalid");
        }
      }

      try {
        const accUrl = normalizeAccreditationUrl(onchainMetadataURI || resolveAccreditationVcUrl(issuerDid));
        console.log("[Verifier] accreditation VC fetch", {
          issuerDid,
          onchainMetadataURI,
          accUrl,
          onchainAccHash: normalizeHash32(onchainAccHash),
        });
        const res = await fetch(accUrl, { cache: "no-store" });
        if (!res.ok) throw new Error(`GET ${accUrl} -> ${res.status}`);
        const vcDoc = await res.json();
        const ctx = Array.isArray(vcDoc?.["@context"]) ? vcDoc["@context"] : [];
        const types = Array.isArray(vcDoc?.type) ? vcDoc.type : vcDoc?.type ? [vcDoc.type] : [];
        const issuer = normalizeDid(
          typeof vcDoc?.issuer === "string" ? vcDoc.issuer : vcDoc?.issuer?.id || ""
        );
        const subjectId = normalizeDid(vcDoc?.credentialSubject?.id || "");
        if (!ctx.includes("https://www.w3.org/2018/credentials/v1")) {
          throw new Error("Accreditation VC missing VC context.");
        }
        if (!types.includes("VerifiableCredential") || !types.includes("VerifiableAccreditation")) {
          throw new Error("Accreditation VC type mismatch.");
        }
        if (issuer && issuer !== issuerDid) {
          throw new Error("Accreditation VC issuer mismatch.");
        }
        if (subjectId && subjectId !== issuerDid) {
          throw new Error("Accreditation VC subject mismatch.");
        }
        const onchainHash = normalizeHash32(onchainAccHash);
        const computed = normalizeHash32(canonicalKeccak(vcDoc));
        console.log("[Verifier] accreditation hash", {
          accUrl,
          computed,
          onchainAccHash: onchainHash,
          rawOnchainAccHash: onchainAccHash,
        });
        if (!isHexString(onchainHash, 32)) {
          throw new Error("On-chain accreditation hash missing.");
        }
        if (computed !== onchainHash) {
          throw new Error("Accreditation hash mismatch.");
        }
        if (!signal.aborted) {
          setIssuerAccreditationDoc("valid");
        }
      } catch (e) {
        if (!signal.aborted) {
          setIssuerAccreditationError(e instanceof Error ? e.message : String(e));
          setIssuerAccreditationDoc("invalid");
        }
      }

      const vcIssuedAt = toUnixSecondsSafe(extractIssuanceDate(vc));
      const authorizedFrom = Math.max(issuerValidFromSeconds || 0, accValidFromSeconds || 0);
      if (!signal.aborted) {
        if (vcIssuedAt === null) {
          setIssuerIssuanceTiming("invalid");
          setIssuerIssuanceTimingError("Credential issuanceDate missing or invalid.");
        } else if (authorizedFrom && vcIssuedAt < authorizedFrom) {
          setIssuerIssuanceTiming("invalid");
          setIssuerIssuanceTimingError("Credential issued before issuer was authorized.");
        } else {
          setIssuerIssuanceTiming("valid");
        }
      }
    } catch (e) {
      if (signal.aborted) return;
      setIssuerAccreditedError(e instanceof Error ? e.message : String(e));
    }
  };

  useEffect(() => {
    let aborted = false;
    const runLocalStatusCheck = async () => {
      setLocalStatusError("");
      setLocalStatusResult(null);
      if (!statusResult) return;
      try {
        setLocalStatusLoading(true);
        const vc = extractFirstCredential(statusResult);
        if (!vc) throw new Error("No VerifiableCredential found in verifier response.");
        const entry = pickStatusEntry(vc);
        if (!entry) throw new Error("credentialStatus missing or no StatusList2021Entry.");
        const listUrl = resolveStatusListUrl(entry);
        if (!listUrl) throw new Error("statusListCredential missing.");
        const index = resolveStatusIndex(entry);
        if (!Number.isFinite(index)) throw new Error("statusListIndex missing.");

        let encodedList = entry.encodedList || entry.bitstring || "";
        let source: "embedded" | "fetched" = "embedded";
        if (!encodedList) {
          source = "fetched";
          const res = await fetch(listUrl, { cache: "no-store" });
          if (!res.ok) throw new Error(`GET ${listUrl} -> ${res.status}`);
          const obj = await res.json();
          encodedList =
            obj?.credentialSubject?.bitstring ||
            obj?.credentialSubject?.encodedList ||
            obj?.bitstring ||
            obj?.encodedList ||
            "";
        }
        if (!encodedList || typeof encodedList !== "string") {
          throw new Error("encodedList/bitstring missing.");
        }
        const gzBytes = decodeBase64ToBytes(encodedList);
        const raw = await gunzipIfNeeded(gzBytes);
        const bit = bitAtIndex(raw, index);
        if (!aborted) {
          setLocalStatusResult({
            statusListCredential: listUrl,
            statusListIndex: index,
            statusPurpose: entry.statusPurpose || "",
            bit,
            verdict: bit === 0 ? "VALID (bit 0)" : "REVOKED (bit 1)",
            source,
          });
        }
      } catch (e) {
        if (!aborted) setLocalStatusError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!aborted) setLocalStatusLoading(false);
      }
    };
    runLocalStatusCheck();
    return () => {
      aborted = true;
    };
  }, [statusResult]);

  useEffect(() => {
    const signal = { aborted: false };
    verifyIssuerAccredited(statusResult, signal);
    return () => {
      signal.aborted = true;
    };
  }, [statusResult]);

  useEffect(() => {
    if (!lastCheckedState || !statusListVerdict) return;
    setVerificationLog((prev) =>
      prev.map((item) =>
        item.state === lastCheckedState ? { ...item, statusListVerdict } : item
      )
    );
  }, [lastCheckedState, statusListVerdict]);

  useEffect(() => {
    if (!lastCheckedState || !issuerAccredited) return;
    setVerificationLog((prev) =>
      prev.map((item) =>
        item.state === lastCheckedState
          ? {
              ...item,
              issuerAccreditedVerdict: issuerAccredited,
              issuerDid: issuerAccreditedDid || item.issuerDid,
              issuerActiveVerdict: issuerActive || item.issuerActiveVerdict,
              issuerOffchainVerdict: issuerOffchain || item.issuerOffchainVerdict,
              issuerSchemaOnchainVerdict: issuerSchemaOnchain || item.issuerSchemaOnchainVerdict,
              issuerSchemaOffchainVerdict: issuerSchemaOffchain || item.issuerSchemaOffchainVerdict,
              issuerCredDefOnchainVerdict: issuerCredDefOnchain || item.issuerCredDefOnchainVerdict,
              issuerCredDefOffchainVerdict: issuerCredDefOffchain || item.issuerCredDefOffchainVerdict,
              issuerStatusListOnchainVerdict: issuerStatusListOnchain || item.issuerStatusListOnchainVerdict,
              issuerStatusListOffchainVerdict: issuerStatusListOffchain || item.issuerStatusListOffchainVerdict,
              issuerDidDocVerdict: issuerDidDoc || item.issuerDidDocVerdict,
              issuerAccreditationVerdict: issuerAccreditationDoc || item.issuerAccreditationVerdict,
              issuerSchemaId: issuerSchemaId || item.issuerSchemaId,
              issuerCredDefId: issuerCredDefId || item.issuerCredDefId,
            }
          : item
      )
    );
  }, [
    lastCheckedState,
    issuerAccredited,
    issuerAccreditedDid,
    issuerActive,
    issuerOffchain,
    issuerSchemaOnchain,
    issuerSchemaOffchain,
    issuerCredDefOnchain,
    issuerCredDefOffchain,
    issuerStatusListOnchain,
    issuerStatusListOffchain,
    issuerDidDoc,
    issuerAccreditationDoc,
    issuerSchemaId,
    issuerCredDefId,
  ]);

  const handleStartVerification = async () => {
    try {
      setError("");
      setStatusResult(null);
      setLoadingInit(true);
      const headers: Record<string, string> = {
        accept: "text/plain",
        "content-type": "application/json",
        ...(authorizeBaseUrl ? { authorizeBaseUrl } : {}),
        ...(responseMode ? { responseMode } : {}),
        ...(successRedirectUri ? { successRedirectUri } : {}),
        ...(errorRedirectUri ? { errorRedirectUri } : {}),
        ...(statusCallbackUri ? { statusCallbackUri } : {}),
        ...(sessionTtl ? { sessionTtl } : {}),
      };

      const body = {
        request_credentials: [
          {
            type: requestCredentialType,
            format: requestCredentialFormat,
          },
        ],
        ...(vpPoliciesArr.length ? { vp_policies: vpPoliciesArr } : {}),
        ...(vcPoliciesArr.length ? { vc_policies: vcPoliciesArr } : {}),
      };

      const res = await fetch(joinUrl(VERIFIER_API_BASE, "/openid4vc/verify"), {
        method: "POST",
        headers,
        credentials: "include",
        body: JSON.stringify(body),
      });
      const text = await res.text();
      if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
      setAuthUrl(text);
      const createdState = parseStateFromAuthUrl(text);
      setStateParam(createdState);
      if (createdState) {
        const ttlSeconds = Number(sessionTtl);
        const expiresAt = Number.isFinite(ttlSeconds) && ttlSeconds > 0 ? Date.now() + ttlSeconds * 1000 : undefined;
        const entry: VerificationEntry = {
          id: createdState,
          createdAt: new Date().toISOString(),
          authUrl: text,
          state: createdState,
          status: "pending",
          result: "unknown",
          expiresAt,
        };
        setVerificationLog((prev) => [entry, ...prev]);
      }
      toast({ title: "Verification started", description: "Share the authorization URL with the holder." });
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingInit(false);
    }
  };

  const handleCheckStatus = async () => {
    if (!stateParam) {
      setError("No state found. Start a verification first.");
      return;
    }
    const checkedState = stateParam;
    setLastCheckedState(checkedState);
    try {
      setError("");
      setLoadingStatus(true);
      const res = await fetch(joinUrl(VERIFIER_API_BASE, `/openid4vc/session/${encodeURIComponent(stateParam)}`), {
        method: "GET",
        credentials: "include",
      });
      const text = await res.text();
      let json: any = null;
      try {
        json = text ? JSON.parse(text) : null;
      } catch {
        json = text;
      }
      if (!res.ok) throw new Error(text || `HTTP ${res.status}`);
      setStatusResult(json);
      const result = (() => {
        const pick = (obj: any): unknown => {
          if (!obj || typeof obj !== "object") return undefined;
          if (obj.verificationResult !== undefined) return obj.verificationResult;
          if (obj.verification_result !== undefined) return obj.verification_result;
          if (obj.result !== undefined && typeof obj.result === "object") {
            if (obj.result.verificationResult !== undefined) return obj.result.verificationResult;
            if (obj.result.verification_result !== undefined) return obj.result.verification_result;
          }
          if (obj.session !== undefined) return pick(obj.session);
          return undefined;
        };
        return pick(json);
      })();
      const reason = (() => {
        if (result !== false) return "";
        const root = json as any;
        return (
          root?.error ||
          root?.message ||
          root?.detail ||
          root?.result?.error ||
          root?.result?.message ||
          root?.result?.detail ||
          "Verification failed"
        );
      })();
      const verificationVerdict = result === true ? "valid" : result === false ? "invalid" : undefined;
      if (checkedState) {
        setVerificationLog((prev) =>
          prev.map((item) =>
            item.state === checkedState
              ? {
                  ...item,
                  status: result === true ? "verified" : result === false ? "failed" : item.status,
                  result: result === true ? "ok" : result === false ? "not_ok" : "unknown",
                  reason: result === false ? reason : "",
                  verificationVerdict: verificationVerdict || item.verificationVerdict,
                }
              : item
          )
        );
      }
      setAuthUrl("");
      setStateParam("");
      setSuccessRedirectUri("");
      setErrorRedirectUri("");
      setStatusCallbackUri("");
      setSessionTtl("");
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingStatus(false);
    }
  };

  const copy = async (value: string) => {
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
        toast({ title: "Copied", description: "Text copied to clipboard" });
        return;
      }
      const el = document.createElement("textarea");
      el.value = value;
      el.style.position = "fixed";
      el.style.opacity = "0";
      document.body.appendChild(el);
      el.focus();
      el.select();
      document.execCommand("copy");
      document.body.removeChild(el);
      toast({ title: "Copied", description: "Text copied to clipboard" });
    } catch (e) {
      toast({ variant: "destructive", title: "Copy failed", description: e instanceof Error ? e.message : String(e) });
    }
  };

  return (
    <MainLayout>
      <PageHeader
        icon={ShieldCheck}
        title="Verifier"
        description="Start OpenID4VC verification"
      />

      <div className="container mx-auto px-4 py-8 space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <StatCard icon={ShieldCheck} label="Verifications" value={verificationLog.length} />
          <StatCard icon={Clock} label="Session TTL" value={formatCountdown(sessionTtlMs)} />
          <StatCard icon={CheckCircle} label="VP policies" value={vpPoliciesArr.length} />
          <StatCard icon={XCircle} label="VC policies" value={vcPoliciesArr.length} />
        </div>

        {error && (
          <div className="p-3 rounded-lg border border-destructive/30 bg-destructive/10 text-destructive text-sm">
            {error}
          </div>
        )}

        <DataCard
          title="1. Start a verification"
          description="Send the request to the verifier and get the holder URL"
        >
          <div className="grid md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <Label>authorizeBaseUrl</Label>
              <Input value={authorizeBaseUrl} onChange={(e) => setAuthorizeBaseUrl(e.target.value)} placeholder="openid4vp://authorize" />
            </div>
            <div className="space-y-2">
              <Label>responseMode</Label>
              <Input value={responseMode} onChange={(e) => setResponseMode(e.target.value)} placeholder="(optional)" />
            </div>
            <div className="space-y-2">
              <Label>successRedirectUri</Label>
              <Input value={successRedirectUri} onChange={(e) => setSuccessRedirectUri(e.target.value)} placeholder="(optional)" />
            </div>
            <div className="space-y-2">
              <Label>errorRedirectUri</Label>
              <Input value={errorRedirectUri} onChange={(e) => setErrorRedirectUri(e.target.value)} placeholder="(optional)" />
            </div>
            <div className="space-y-2">
              <Label>statusCallbackUri</Label>
              <Input value={statusCallbackUri} onChange={(e) => setStatusCallbackUri(e.target.value)} placeholder="(optional)" />
            </div>
            <div className="space-y-2">
              <Label>sessionTtl</Label>
              <Input value={sessionTtl} onChange={(e) => setSessionTtl(e.target.value)} placeholder="e.g. 60000" />
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-4 mt-4">
            <div className="space-y-2">
              <Label>Request credential type</Label>
              <Input value={requestCredentialType} onChange={(e) => setRequestCredentialType(e.target.value)} />
            </div>
            <div className="space-y-2">
              <Label>Request credential format</Label>
              <Input value={requestCredentialFormat} onChange={(e) => setRequestCredentialFormat(e.target.value)} />
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-4 mt-4">
            <div className="space-y-2">
              <Label>VP policies</Label>
              <div className="flex flex-wrap gap-2">
                {vpPolicyOptions.map((p) => (
                  <Button
                    key={p.id}
                    variant={vpPolicies.has(p.id) ? "default" : "outline"}
                    size="sm"
                    onClick={() => togglePolicy(setVpPolicies)(p.id)}
                  >
                    {p.label}
                  </Button>
                ))}
              </div>
            </div>
            <div className="space-y-2">
              <Label>VC policies</Label>
              <div className="flex flex-wrap gap-2">
                {vcPolicyOptions.map((p) => (
                  <Button
                    key={p.id}
                    variant={vcPolicies.has(p.id) ? "default" : "outline"}
                    size="sm"
                    onClick={() => togglePolicy(setVcPolicies)(p.id)}
                  >
                    {p.label}
                  </Button>
                ))}
              </div>
            </div>
          </div>

          <div className="flex gap-3 mt-6">
            <Button onClick={handleStartVerification} disabled={loadingInit} className="flex-1">
              <Play className="w-4 h-4 mr-2" />
              {loadingInit ? "Starting..." : "Start verification"}
            </Button>
            <Button variant="outline" onClick={() => setStatusResult(null)}>
              Clear
            </Button>
          </div>

          {authUrl && (
            <div className="mt-4 space-y-2">
              <Label className="text-xs text-muted-foreground">Authorization URL</Label>
              <div className="flex gap-2">
                <Input value={authUrl} readOnly className="font-mono text-xs" />
                <Button variant="outline" size="sm" onClick={() => copy(authUrl)}>
                  <Copy className="w-4 h-4 mr-1" />
                  Copy
                </Button>
              </div>
              {stateParam && (
                <p className="text-xs text-muted-foreground">
                  State: <span className="font-mono">{stateParam}</span>
                </p>
              )}
            </div>
          )}
        </DataCard>

        <DataCard title="2. Check status" description="Query the session state">
          <div className="flex items-center gap-2">
            <Input
              value={stateParam}
              onChange={(e) => setStateParam(e.target.value)}
              placeholder="state"
              className="font-mono"
            />
            <Button onClick={handleCheckStatus} disabled={loadingStatus}>
              <RefreshCw className="w-4 h-4 mr-2" />
              {loadingStatus ? "Checking..." : "Check status"}
            </Button>
            <Button variant="outline" onClick={() => setStatusResult(null)}>
              Clear result
            </Button>
          </div>

          {statusResult && (
            <div className="mt-4 space-y-2">
              {verificationVerdict && (
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge variant={verificationVerdict === "valid" ? "default" : "destructive"}>
                    {verificationVerdict === "valid" ? "Verification OK" : "Verification failed"}
                  </Badge>
                  {statusListVerdict && (
                    <Badge variant={statusListVerdict === "valid" ? "default" : "destructive"}>
                      Status list: {statusListVerdict === "valid" ? "valid" : "revoked"}
                    </Badge>
                  )}
                  {issuerActive && (
                    <Badge variant={issuerActive === "valid" ? "default" : "destructive"}>
                      Issuer active: {issuerActive === "valid" ? "yes" : "no"}
                    </Badge>
                  )}
              {issuerAccredited && (
                <Badge variant={issuerAccredited === "valid" ? "default" : "destructive"}>
                  Issuer accredited: {issuerAccredited === "valid" ? "yes" : "no"}
                </Badge>
              )}
              {issuerDidDoc && (
                <Badge variant={issuerDidDoc === "valid" ? "default" : "destructive"}>
                  DID Document: {issuerDidDoc === "valid" ? "ok" : "missing"}
                </Badge>
              )}
              {issuerAccreditationDoc && (
                <Badge variant={issuerAccreditationDoc === "valid" ? "default" : "destructive"}>
                  Accreditation VC: {issuerAccreditationDoc === "valid" ? "ok" : "invalid"}
                </Badge>
              )}
              {issuerIssuanceTiming && (
                <Badge variant={issuerIssuanceTiming === "valid" ? "default" : "destructive"}>
                  Issuance timing: {issuerIssuanceTiming === "valid" ? "ok" : "invalid"}
                </Badge>
              )}
              {issuerOffchain && (
                <Badge variant={issuerOffchain === "valid" ? "default" : "destructive"}>
                  Off-chain issuer: {issuerOffchain === "valid" ? "yes" : "no"}
                </Badge>
              )}
              {issuerSchemaOnchain && (
                <Badge variant={issuerSchemaOnchain === "valid" ? "default" : "destructive"}>
                  On-chain schema: {issuerSchemaOnchain === "valid" ? "yes" : "no"}
                </Badge>
              )}
              {issuerSchemaRegistry && (
                <Badge variant={issuerSchemaRegistry === "valid" ? "default" : "destructive"}>
                  Schema registry: {issuerSchemaRegistry === "valid" ? "ok" : "invalid"}
                </Badge>
              )}
              {issuerSchemaOffchain && (
                <Badge variant={issuerSchemaOffchain === "valid" ? "default" : "destructive"}>
                  Off-chain schema: {issuerSchemaOffchain === "valid" ? "yes" : "no"}
                </Badge>
              )}
              {issuerCredDefOnchain && (
                <Badge variant={issuerCredDefOnchain === "valid" ? "default" : "destructive"}>
                  On-chain CDR: {issuerCredDefOnchain === "valid" ? "yes" : "no"}
                </Badge>
              )}
              {issuerCredDefOffchain && (
                <Badge variant={issuerCredDefOffchain === "valid" ? "default" : "destructive"}>
                  Off-chain CDR: {issuerCredDefOffchain === "valid" ? "yes" : "no"}
                </Badge>
              )}
              {issuerStatusListOnchain && (
                <Badge variant={issuerStatusListOnchain === "valid" ? "default" : "destructive"}>
                  On-chain StatusR: {issuerStatusListOnchain === "valid" ? "yes" : "no"}
                </Badge>
              )}
              {issuerStatusListOffchain && (
                <Badge variant={issuerStatusListOffchain === "valid" ? "default" : "destructive"}>
                  Off-chain StatusR: {issuerStatusListOffchain === "valid" ? "yes" : "no"}
                </Badge>
              )}
            </div>
          )}
              {issuerAccreditedError && (
                <p className="text-xs text-destructive">{issuerAccreditedError}</p>
              )}
              {issuerActiveError && (
                <p className="text-xs text-destructive">{issuerActiveError}</p>
              )}
              {issuerSchemaOnchainError && (
                <p className="text-xs text-destructive">{issuerSchemaOnchainError}</p>
              )}
              {issuerSchemaRegistryError && (
                <p className="text-xs text-destructive">{issuerSchemaRegistryError}</p>
              )}
              {issuerOffchainError && (
                <p className="text-xs text-destructive">{issuerOffchainError}</p>
              )}
              {issuerSchemaOffchainError && (
                <p className="text-xs text-destructive">{issuerSchemaOffchainError}</p>
              )}
              {issuerCredDefOnchainError && (
                <p className="text-xs text-destructive">{issuerCredDefOnchainError}</p>
              )}
              {issuerCredDefOffchainError && (
                <p className="text-xs text-destructive">{issuerCredDefOffchainError}</p>
              )}
              {issuerStatusListOnchainError && (
                <p className="text-xs text-destructive">{issuerStatusListOnchainError}</p>
              )}
              {issuerStatusListOffchainError && (
                <p className="text-xs text-destructive">{issuerStatusListOffchainError}</p>
              )}
              {issuerDidDocError && (
                <p className="text-xs text-destructive">{issuerDidDocError}</p>
              )}
              {issuerAccreditationError && (
                <p className="text-xs text-destructive">{issuerAccreditationError}</p>
              )}
              {issuerIssuanceTimingError && (
                <p className="text-xs text-destructive">{issuerIssuanceTimingError}</p>
              )}
              {issuerAccreditedDid && (
                <div className="text-xs text-muted-foreground">
                  Issuer DID: <span className="font-mono break-all">{issuerAccreditedDid}</span>
                </div>
              )}
              {issuerSchemaId && (
                <div className="text-xs text-muted-foreground">
                  Schema ID: <span className="font-mono break-all">{issuerSchemaId}</span>
                </div>
              )}
              {issuerCredDefId && (
                <div className="text-xs text-muted-foreground">
                  CredDef ID: <span className="font-mono break-all">{issuerCredDefId}</span>
                </div>
              )}
              {combinedVerdict && (
                <div className="flex items-center gap-2">
                  <Label className="text-xs text-muted-foreground">Final result</Label>
                  <Badge variant={combinedVerdict === "valid" ? "default" : "destructive"}>
                    {combinedVerdict === "valid" ? "VALID" : "INVALID"}
                  </Badge>
                </div>
              )}
              <Label className="text-xs text-muted-foreground">Verifier response</Label>
              <Textarea readOnly value={JSON.stringify(statusResult, null, 2)} className="font-mono text-xs min-h-[220px]" />
            </div>
          )}
        </DataCard>

        <DataCard
          title="Local status check"
          description="Verify status list locally (independent from verifier API)"
        >
          {localStatusLoading && <p className="text-xs text-muted-foreground">Checking status list…</p>}
          {localStatusError && <p className="text-xs text-destructive">{localStatusError}</p>}
          {localStatusResult && (
            <div className="space-y-2 text-sm">
              <div>
                Status list:{" "}
                <span className="font-mono text-xs break-all">{localStatusResult.statusListCredential}</span>
              </div>
              <div>Index: {localStatusResult.statusListIndex}</div>
              <div>Purpose: {localStatusResult.statusPurpose || "—"}</div>
              <div>Source: {localStatusResult.source}</div>
              <Badge variant={localStatusResult.bit === 1 ? "destructive" : "default"}>
                {localStatusResult.verdict}
              </Badge>
            </div>
          )}
          {!statusResult && !localStatusLoading && !localStatusError && !localStatusResult && (
            <p className="text-xs text-muted-foreground">No status result yet.</p>
          )}
        </DataCard>

        <DataCard
          title="Verification History"
          description="All verification requests created in this session"
        >
          {verificationLog.length === 0 ? (
            <p className="text-sm text-muted-foreground">No verifications created yet.</p>
          ) : (
            <div className="space-y-3">
              {verificationLog.map((entry) => {
                const finalVerdict =
                  entry.verificationVerdict &&
                  entry.statusListVerdict &&
                  entry.issuerAccreditedVerdict &&
                  entry.issuerActiveVerdict &&
                  entry.issuerOffchainVerdict &&
                  entry.issuerSchemaOnchainVerdict &&
                  entry.issuerSchemaOffchainVerdict &&
                  entry.issuerCredDefOnchainVerdict &&
                  entry.issuerCredDefOffchainVerdict &&
                  entry.issuerStatusListOnchainVerdict &&
                  entry.issuerStatusListOffchainVerdict &&
                  entry.issuerDidDocVerdict
                    ? entry.verificationVerdict === "valid" &&
                      entry.statusListVerdict === "valid" &&
                      entry.issuerAccreditedVerdict === "valid" &&
                      entry.issuerActiveVerdict === "valid" &&
                      entry.issuerOffchainVerdict === "valid" &&
                      entry.issuerSchemaOnchainVerdict === "valid" &&
                      entry.issuerSchemaOffchainVerdict === "valid" &&
                      entry.issuerCredDefOnchainVerdict === "valid" &&
                      entry.issuerCredDefOffchainVerdict === "valid" &&
                      entry.issuerStatusListOnchainVerdict === "valid" &&
                      entry.issuerStatusListOffchainVerdict === "valid" &&
                      entry.issuerDidDocVerdict === "valid"
                      ? "valid"
                      : "invalid"
                    : "";
                return (
                  <div key={entry.id} className="p-3 rounded-lg border border-border/60 bg-muted/20">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm font-mono break-all">{entry.state}</p>
                        <p className="text-xs text-muted-foreground">
                          Created: {new Date(entry.createdAt).toLocaleString()}
                        </p>
                    </div>
                    <div className="text-right space-y-1">
                      <div className="flex items-center justify-end gap-2 flex-wrap">
                        <Badge
                          variant={
                            entry.status === "verified"
                                ? "default"
                                : entry.status === "failed"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.status}
                          </Badge>
                          <Badge
                            variant={
                              entry.result === "ok"
                                ? "default"
                                : entry.result === "not_ok"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.result === "ok" ? "OK" : entry.result === "not_ok" ? "Not OK" : "Unknown"}
                          </Badge>
                          <Badge
                            variant={
                              entry.statusListVerdict === "valid"
                                ? "default"
                                : entry.statusListVerdict === "revoked"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.statusListVerdict
                              ? `Status list: ${entry.statusListVerdict}`
                              : "Status list: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerActiveVerdict === "valid"
                                ? "default"
                                : entry.issuerActiveVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerActiveVerdict
                              ? `Issuer active: ${entry.issuerActiveVerdict === "valid" ? "yes" : "no"}`
                              : "Issuer active: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerAccreditedVerdict === "valid"
                                ? "default"
                                : entry.issuerAccreditedVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerAccreditedVerdict
                              ? `Issuer accredited: ${entry.issuerAccreditedVerdict === "valid" ? "yes" : "no"}`
                              : "Issuer accredited: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerOffchainVerdict === "valid"
                                ? "default"
                                : entry.issuerOffchainVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerOffchainVerdict
                              ? `Off-chain issuer: ${entry.issuerOffchainVerdict === "valid" ? "yes" : "no"}`
                              : "Off-chain issuer: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerSchemaOnchainVerdict === "valid"
                                ? "default"
                                : entry.issuerSchemaOnchainVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerSchemaOnchainVerdict
                              ? `On-chain schema: ${entry.issuerSchemaOnchainVerdict === "valid" ? "yes" : "no"}`
                              : "On-chain schema: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerSchemaOffchainVerdict === "valid"
                                ? "default"
                                : entry.issuerSchemaOffchainVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerSchemaOffchainVerdict
                              ? `Off-chain schema: ${entry.issuerSchemaOffchainVerdict === "valid" ? "yes" : "no"}`
                              : "Off-chain schema: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerCredDefOnchainVerdict === "valid"
                                ? "default"
                                : entry.issuerCredDefOnchainVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerCredDefOnchainVerdict
                              ? `On-chain CDR: ${entry.issuerCredDefOnchainVerdict === "valid" ? "yes" : "no"}`
                              : "On-chain CDR: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerCredDefOffchainVerdict === "valid"
                                ? "default"
                                : entry.issuerCredDefOffchainVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerCredDefOffchainVerdict
                              ? `Off-chain CDR: ${entry.issuerCredDefOffchainVerdict === "valid" ? "yes" : "no"}`
                              : "Off-chain CDR: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerStatusListOnchainVerdict === "valid"
                                ? "default"
                                : entry.issuerStatusListOnchainVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerStatusListOnchainVerdict
                              ? `On-chain StatusR: ${entry.issuerStatusListOnchainVerdict === "valid" ? "yes" : "no"}`
                              : "On-chain StatusR: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerStatusListOffchainVerdict === "valid"
                                ? "default"
                                : entry.issuerStatusListOffchainVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerStatusListOffchainVerdict
                              ? `Off-chain StatusR: ${entry.issuerStatusListOffchainVerdict === "valid" ? "yes" : "no"}`
                              : "Off-chain StatusR: —"}
                          </Badge>
                          <Badge
                            variant={
                              entry.issuerDidDocVerdict === "valid"
                                ? "default"
                                : entry.issuerDidDocVerdict === "invalid"
                                ? "destructive"
                                : "secondary"
                            }
                          >
                            {entry.issuerDidDocVerdict
                              ? `DID Document: ${entry.issuerDidDocVerdict === "valid" ? "ok" : "missing"}`
                              : "DID Document: —"}
                          </Badge>
                          {finalVerdict && (
                            <Badge variant={finalVerdict === "valid" ? "default" : "destructive"}>
                              {finalVerdict === "valid" ? "FINAL VALID" : "FINAL INVALID"}
                            </Badge>
                          )}
                        </div>
                        {entry.issuerDid && (
                          <p className="text-xs text-muted-foreground">
                            Issuer DID: <span className="font-mono break-all">{entry.issuerDid}</span>
                          </p>
                        )}
                      </div>
                    </div>
                    {entry.reason && (
                      <div className="mt-1 text-xs text-destructive">{entry.reason}</div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </DataCard>
      </div>
    </MainLayout>
  );
}
