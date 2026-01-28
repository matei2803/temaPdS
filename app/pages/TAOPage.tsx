import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Building2, Check, Plus, Search, Shield, Users } from "lucide-react";
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
import { cn } from "@/lib/utils";
import { BrowserProvider, Contract, Eip1193Provider, isHexString, keccak256, toUtf8Bytes } from "ethers";
import { canonicalize } from "json-canonicalize";
import tirAbi from "../../smart_contracts/abi_TIR.json";
import didrAbi from "../../smart_contracts/abi_DIDR.json";

const STATUS_LIST_BITS = 131072;

type IssuerStatus = "pending" | "accredited" | "suspended" | "revoked";

type IssuerRow = {
  id: string;
  name: string;
  did: string;
  status: IssuerStatus;
  credentialTypes: string[];
  accreditedAt: string;
  allowedSchemas: string[];
  allowedCredDefs: string[];
  didDocUrl: string;
};

type AccreditationStatus = "Active" | "Suspended" | "Revoked";

type DidrHashAlg =
  | "Keccak256CanonicalJson"
  | "Keccak256JwsCompact";

type DidrStatus = "Active" | "Suspended" | "Revoked";

type TirStatus = "Active" | "Suspended" | "Revoked";

export default function TAOPage() {
  const defaultPostUrlBase = import.meta.env.VITE_URL
    ? `http://${import.meta.env.VITE_URL}/dev/vc/accreditation`
    : "http://192.168.93.134/dev/vc/accreditation";
  const [addIssuerOpen, setAddIssuerOpen] = useState(false);
  const [enrollOpen, setEnrollOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [walletAccount, setWalletAccount] = useState<string | null>(null);
  const [issuers, setIssuers] = useState<IssuerRow[]>([]);
  const [publishingVa, setPublishingVa] = useState(false);
  const [loadingDidr, setLoadingDidr] = useState(false);
  const [loadingTir, setLoadingTir] = useState(false);

  const [newIssuer, setNewIssuer] = useState({
    name: "",
    did: "",
    credentialTypesCsv: "",
    schemaIdsCsv: "",
    credDefIdsCsv: "",
    taoDid: "",
    rolesCsv: "",
    postUrlBase: defaultPostUrlBase,
    version: "1.0.0",
    validFrom: new Date().toISOString().slice(0, 16),
    validUntil: "",
  });

  const [selectedIssuer, setSelectedIssuer] = useState<IssuerRow | null>(null);
  const [didrForm, setDidrForm] = useState({
    did: "",
    docUrl: "",
    docHash: "",
    hashAlg: "Keccak256CanonicalJson" as DidrHashAlg,
    status: "Active" as DidrStatus,
    validFrom: new Date().toISOString().slice(0, 16),
    validUntil: "",
    metadataURI: "",
  });
  const [tirForm, setTirForm] = useState({
    did: "",
    metadataURI: "",
    validFrom: new Date().toISOString().slice(0, 16),
    validUntil: "",
    status: "Active" as TirStatus,
    accreditationStatus: "Active" as AccreditationStatus,
    accreditationValidFrom: new Date().toISOString().slice(0, 16),
    accreditationValidUntil: "",
    accreditationMetadataURI: "",
    capabilitiesCsv: "",
    schemaIdsCsv: "",
    credDefIdsCsv: "",
  });

  const { toast } = useToast();
  const tirAddress = import.meta.env.VITE_TIR_CONTRACT_ADDRESS as string | undefined;
  const didrAddress = import.meta.env.VITE_DIDR_CONTRACT_ADDRESS as string | undefined;

  const resolveAccreditationBase = (override?: string) => {
    if (override) return override.replace(/\/$/, "");
    const host = import.meta.env.VITE_URL || "192.168.93.134";
    return `http://${host}/dev/vc/accreditation`;
  };

  const resolveStatusBase = () => {
    const host = import.meta.env.VITE_URL || "192.168.93.134";
    return `http://${host}/dev/status`;
  };

  const getAllVaUrl = (overrideBase?: string) => `${resolveAccreditationBase(overrideBase)}/allVA.json`;

  const normalizeIssuerStatus = (value: unknown): IssuerStatus => {
    if (value === "accredited" || value === "suspended" || value === "revoked" || value === "pending") {
      return value;
    }
    return "pending";
  };

  const parseAllVaJson = (json: unknown): IssuerRow[] => {
    if (Array.isArray(json)) {
      return json
        .map((item, idx) => {
          if (!item || typeof item !== "object") return null;
          const entry = item as Record<string, unknown>;
          const name = typeof entry.name === "string" ? entry.name : "";
          const did = typeof entry.did === "string" ? entry.did : "";
          if (!did) return null;
          const allowedSchemas = Array.isArray(entry.allowedSchemas)
            ? entry.allowedSchemas.filter((t) => typeof t === "string")
            : Array.isArray(entry.credentialSchemas)
              ? entry.credentialSchemas.filter((t) => typeof t === "string")
              : [];
          const allowedCredDefs = Array.isArray(entry.allowedCredDefs)
            ? entry.allowedCredDefs.filter((t) => typeof t === "string")
            : Array.isArray(entry.credentialDefinitions)
              ? entry.credentialDefinitions.filter((t) => typeof t === "string")
              : [];
          const didDocUrl =
            (typeof entry.didDocUrl === "string" && entry.didDocUrl) ||
            (typeof entry.didDocumentUrl === "string" && entry.didDocumentUrl) ||
            "";
          return {
            id: `issuer-${did || idx}`,
            name: name || "Trusted Issuer",
            did,
            status: normalizeIssuerStatus(entry.status),
            credentialTypes: Array.isArray(entry.credentialTypes)
              ? (entry.credentialTypes.filter((t) => typeof t === "string") as string[])
              : [],
            accreditedAt: typeof entry.accreditedAt === "string" ? entry.accreditedAt : "—",
            allowedSchemas: allowedSchemas as string[],
            allowedCredDefs: allowedCredDefs as string[],
            didDocUrl,
          } as IssuerRow;
        })
        .filter((row): row is IssuerRow => Boolean(row));
    }
    if (json && typeof json === "object") {
      return Object.entries(json as Record<string, unknown>)
        .map(([name, value], idx) => {
          if (value && typeof value === "object") {
            const entry = value as Record<string, unknown>;
            const did = typeof entry.did === "string" ? entry.did : "";
            if (!did) return null;
            const allowedSchemas = Array.isArray(entry.allowedSchemas)
              ? entry.allowedSchemas.filter((t) => typeof t === "string")
              : Array.isArray(entry.credentialSchemas)
                ? entry.credentialSchemas.filter((t) => typeof t === "string")
                : [];
            const allowedCredDefs = Array.isArray(entry.allowedCredDefs)
              ? entry.allowedCredDefs.filter((t) => typeof t === "string")
              : Array.isArray(entry.credentialDefinitions)
                ? entry.credentialDefinitions.filter((t) => typeof t === "string")
                : [];
            const didDocUrl =
              (typeof entry.didDocUrl === "string" && entry.didDocUrl) ||
              (typeof entry.didDocumentUrl === "string" && entry.didDocumentUrl) ||
              "";
            return {
              id: `issuer-${did || idx}`,
              name: name || "Trusted Issuer",
              did,
              status: normalizeIssuerStatus(entry.status),
              credentialTypes: Array.isArray(entry.credentialTypes)
                ? (entry.credentialTypes.filter((t) => typeof t === "string") as string[])
                : [],
              accreditedAt: typeof entry.accreditedAt === "string" ? entry.accreditedAt : "—",
              allowedSchemas: allowedSchemas as string[],
              allowedCredDefs: allowedCredDefs as string[],
              didDocUrl,
            } as IssuerRow;
          }
          if (typeof value === "string") {
            return {
              id: `issuer-${value || idx}`,
              name: name || "Trusted Issuer",
              did: value,
              status: "pending",
              credentialTypes: [],
              accreditedAt: "—",
              allowedSchemas: [],
              allowedCredDefs: [],
              didDocUrl: "",
            } as IssuerRow;
          }
          return null;
        })
        .filter((row): row is IssuerRow => Boolean(row));
    }
    return [];
  };

  const loadAllVa = async () => {
    const url = getAllVaUrl();
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) {
      if (res.status === 404) {
        setIssuers([]);
        return;
      }
      throw new Error(`GET ${url} -> ${res.status}`);
    }
    const text = await res.text();
    const json = text.trim() ? JSON.parse(text) : [];
    setIssuers(parseAllVaJson(json));
  };

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      try {
        await loadAllVa();
      } catch (error) {
        if (!cancelled) {
          const message = error instanceof Error ? error.message : "Failed to load allVA.json.";
          toast({ title: "allVA.json error", description: message, variant: "destructive" });
        }
      }
    };
    run();
    return () => {
      cancelled = true;
    };
  }, [toast]);

  const putJSON = async (url: string, body: unknown, contentType = "application/json") => {
    const res = await fetch(url, {
      method: "PUT",
      headers: { "Content-Type": contentType },
      body: typeof body === "string" ? body : JSON.stringify(body),
    });
    if (!res.ok) {
      throw new Error(`PUT ${url} -> HTTP ${res.status}`);
    }
    return url;
  };

  const upsertAllVaEntry = async (entry: IssuerRow, baseOverride?: string) => {
    const allVaUrl = getAllVaUrl(baseOverride);
    let json: unknown = {};
    const res = await fetch(allVaUrl, { cache: "no-store" });
    if (res.ok) {
      const text = await res.text();
      json = text.trim() ? JSON.parse(text) : {};
    } else if (res.status !== 404) {
      throw new Error(`GET ${allVaUrl} -> ${res.status}`);
    }

    let nextJson: unknown;
    if (Array.isArray(json)) {
      const nextArray = json.filter((item) => item && typeof item === "object") as Record<string, unknown>[];
      const idx = nextArray.findIndex(
        (item) =>
          (typeof item.name === "string" && item.name === entry.name) ||
          (typeof item.did === "string" && item.did === entry.did),
      );
      const nextItem = {
        name: entry.name,
        did: entry.did,
        status: entry.status,
        credentialTypes: entry.credentialTypes,
        accreditedAt: entry.accreditedAt,
        allowedSchemas: entry.allowedSchemas,
        allowedCredDefs: entry.allowedCredDefs,
        didDocUrl: entry.didDocUrl,
      };
      if (idx >= 0) nextArray[idx] = nextItem;
      else nextArray.push(nextItem);
      nextJson = nextArray;
    } else if (json && typeof json === "object") {
      const nextObject = { ...(json as Record<string, unknown>) };
      const key = entry.name || entry.did;
      nextObject[key] = {
        did: entry.did,
        status: entry.status,
        credentialTypes: entry.credentialTypes,
        accreditedAt: entry.accreditedAt,
        allowedSchemas: entry.allowedSchemas,
        allowedCredDefs: entry.allowedCredDefs,
        didDocUrl: entry.didDocUrl,
      };
      nextJson = nextObject;
    } else {
      const key = entry.name || entry.did;
      nextJson = {
        [key]: {
          did: entry.did,
          status: entry.status,
          credentialTypes: entry.credentialTypes,
          accreditedAt: entry.accreditedAt,
          allowedSchemas: entry.allowedSchemas,
          allowedCredDefs: entry.allowedCredDefs,
          didDocUrl: entry.didDocUrl,
        },
      };
    }

    await putJSON(allVaUrl, nextJson);
    setIssuers(parseAllVaJson(nextJson));
  };

  const getDidShort = (did: string) => {
    const parts = did.split(":");
    return parts[parts.length - 1] || did;
  };

  const toUnixSeconds = (value: string, fallbackToNow = false) => {
    if (!value) return fallbackToNow ? Math.floor(Date.now() / 1000) : 0;
    const parsed = Date.parse(value);
    if (Number.isNaN(parsed)) {
      throw new Error("Invalid date format.");
    }
    return Math.floor(parsed / 1000);
  };

  const parseList = (value: string) =>
    value
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);

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

  const bytesToBase64Url = (bytes: Uint8Array) => {
    let bin = "";
    bytes.forEach((b) => {
      bin += String.fromCharCode(b);
    });
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };

  const buildEmptyStatusListCredential = (url: string, issuerDid: string) => {
    const byteLen = Math.ceil(STATUS_LIST_BITS / 8);
    const encodedList = bytesToBase64Url(new Uint8Array(byteLen));
    return {
      "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/vc/status-list/2021/v1",
      ],
      id: url,
      type: ["VerifiableCredential", "StatusList2021Credential"],
      issuer: issuerDid,
      issuanceDate: new Date().toISOString(),
      credentialSubject: {
        id: `${url}#list`,
        type: "StatusList2021",
        statusPurpose: "revocation",
        encodedList,
      },
    };
  };


  const ensureStatusList = async (url: string, issuerDid: string) => {
    const res = await fetch(url, { cache: "no-store" });
    if (res.ok) return;
    if (res.status !== 404) {
      throw new Error(`GET ${url} -> ${res.status}`);
    }
    const statusList = buildEmptyStatusListCredential(url, issuerDid);
    await putJSON(url, statusList);
  };

  const getNextStatusIndexFromAllVa = async (baseOverride?: string) => {
    const allVaUrl = getAllVaUrl(baseOverride);
    const res = await fetch(allVaUrl, { cache: "no-store" });
    if (!res.ok) {
      if (res.status === 404) return 0;
      throw new Error(`GET ${allVaUrl} -> ${res.status}`);
    }
    const text = await res.text();
    const json = text.trim() ? JSON.parse(text) : [];
    if (Array.isArray(json)) return json.length;
    if (json && typeof json === "object") return Object.keys(json as Record<string, unknown>).length;
    return 0;
  };

  const getProvider = () => {
    const ethereum = (window as { ethereum?: Eip1193Provider }).ethereum;
    if (!ethereum) {
      throw new Error("No wallet detected. Install MetaMask or another EVM wallet.");
    }
    return new BrowserProvider(ethereum);
  };

  const getTirContract = async () => {
    if (!tirAddress || tirAddress === "0x0000000000000000000000000000000000000000") {
      throw new Error("Missing VITE_TIR_CONTRACT_ADDRESS in .env.");
    }
    const provider = getProvider();
    const signer = await provider.getSigner();
    return new Contract(tirAddress, tirAbi, signer);
  };

  const getDidrContract = async () => {
    if (!didrAddress || didrAddress === "0x0000000000000000000000000000000000000000") {
      throw new Error("Missing VITE_DIDR_CONTRACT_ADDRESS in .env.");
    }
    const provider = getProvider();
    const signer = await provider.getSigner();
    return new Contract(didrAddress, didrAbi, signer);
  };

  const handleConnectWallet = async () => {
    try {
      const provider = getProvider();
      const accounts = (await provider.send("eth_requestAccounts", [])) as string[];
      setWalletAccount(accounts?.[0] ?? null);
      toast({
        title: "Wallet connected",
        description: accounts?.[0] ? `Connected as ${accounts[0]}` : "Wallet connected.",
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to connect wallet.";
      toast({ title: "Wallet error", description: message, variant: "destructive" });
    }
  };

  const parseDidrHashAlg = (alg: DidrHashAlg) => {
    switch (alg) {
      case "Keccak256CanonicalJson":
        return 1;
      case "Keccak256JwsCompact":
        return 3;
      default:
        return 0;
    }
  };

  const parseStatusEnum = (status: DidrStatus | TirStatus | AccreditationStatus) => {
    return status === "Active" ? 1 : status === "Suspended" ? 2 : 3;
  };

  const computeDidrDocHashFromUrl = async (url: string, alg: DidrHashAlg) => {
    if (!url.trim()) throw new Error("DID document URL is required.");
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) throw new Error(`Failed to fetch DID document (${res.status}).`);
    const text = await res.text();
    if (alg === "Keccak256JwsCompact") {
      return keccak256(toUtf8Bytes(text));
    }
    const obj = JSON.parse(text);
    const canonical = canonicalize(obj);
    return keccak256(toUtf8Bytes(canonical));
  };

  const handleGenerateAccreditationVc = async () => {
    try {
      setPublishingVa(true);
      const taoDid = newIssuer.taoDid.trim();
      if (!taoDid) throw new Error("TAO DID is required to generate accreditation VC.");
      const issuerName = newIssuer.name.trim();
      if (!issuerName) throw new Error("Organization name is required.");
      const issuerDid = newIssuer.did.trim();
      if (!issuerDid) throw new Error("Issuer DID is required.");
      const issuerShort = getDidShort(issuerDid);

      const accValidFrom = toUnixSeconds(newIssuer.validFrom, true);
      const accValidUntil = toUnixSeconds(newIssuer.validUntil, false);
      const postBase = newIssuer.postUrlBase || resolveAccreditationBase();
      const version = newIssuer.version.trim() || "1.0.0";
      const vcUrl = `${postBase.replace(/\/$/, "")}/${issuerShort}/${version}.json`;
      const statusBase = resolveStatusBase();
      const taoShort = getDidShort(taoDid);
      const taoStatusListUrl = `${statusBase}/${taoShort}/revocation/${version}.json`;
      const issuerStatusListUrl = `${statusBase}/${issuerShort}/revocation/${version}.json`;
      const didDocUrl = `http://${import.meta.env.VITE_URL || "192.168.93.134"}/dev/did/${issuerShort}/${version}.json`;
      const statusListIndex = await getNextStatusIndexFromAllVa(newIssuer.postUrlBase);
      await ensureStatusList(taoStatusListUrl, taoDid);
      await ensureStatusList(issuerStatusListUrl, issuerDid);
      const roles = parseList(newIssuer.rolesCsv);
      const capabilities = parseList(newIssuer.credentialTypesCsv).map((cap) => {
        const trimmed = cap.trim();
        const canon = trimmed.toLowerCase().replace(/\s+/g, " ");
        return trimmed.startsWith("http")
          ? { credentialDefinition: trimmed, capability: canon }
          : { capability: canon };
      });
      const allowedSchemas = parseList(newIssuer.schemaIdsCsv);
      const allowedCredDefs = parseList(newIssuer.credDefIdsCsv);

      const vc = {
        "@context": [
          "https://www.w3.org/2018/credentials/v1",
          "https://w3id.org/vc/status-list/2021/v1",
        ],
        id: vcUrl,
        type: ["VerifiableCredential", "VerifiableAccreditation"],
        issuer: taoDid,
        issuanceDate: new Date(accValidFrom * 1000).toISOString(),
        expirationDate: accValidUntil ? new Date(accValidUntil * 1000).toISOString() : undefined,
        credentialSubject: {
          id: issuerDid,
          roles,
          accreditedFor: capabilities,
          ...(allowedSchemas.length ? { credentialSchemas: allowedSchemas } : {}),
          ...(allowedCredDefs.length ? { credentialDefinitions: allowedCredDefs } : {}),
        },
        credentialStatus: [
          {
            id: `${taoStatusListUrl}#${statusListIndex}`,
            type: "StatusList2021Entry",
            statusPurpose: "revocation",
            statusListIndex: String(statusListIndex),
            statusListCredential: taoStatusListUrl,
          },
        ],
        evidence: import.meta.env.VITE_URL
          ? [{ type: "RegistryAttestation", evidenceDocument: `http://${import.meta.env.VITE_URL}/dev/creddefs` }]
          : [],
        termsOfUse: [],
      };

      await putJSON(vcUrl, vc);

      await upsertAllVaEntry(
        {
          id: `issuer-${issuerDid}`,
          name: issuerName,
          did: issuerDid,
          status: "pending",
          credentialTypes: parseList(newIssuer.credentialTypesCsv),
          accreditedAt: "—",
          allowedSchemas,
          allowedCredDefs,
          didDocUrl,
        },
        newIssuer.postUrlBase,
      );

      toast({
        title: "Accreditation VC published",
        description: `VC published at ${vcUrl}`,
      });
      setAddIssuerOpen(false);
      setNewIssuer({
        name: "",
        did: "",
        credentialTypesCsv: "",
        schemaIdsCsv: "",
        credDefIdsCsv: "",
        taoDid: "",
        rolesCsv: "",
        postUrlBase: defaultPostUrlBase,
        version: "1.0.0",
        validFrom: new Date().toISOString().slice(0, 16),
        validUntil: "",
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Failed to publish accreditation VC.";
      toast({ title: "Accreditation VC error", description: message, variant: "destructive" });
    } finally {
      setPublishingVa(false);
    }
  };

  const openEnrollDialog = (issuer: IssuerRow) => {
    const didShort = getDidShort(issuer.did);
    const base = resolveAccreditationBase();
    const vcUrl = `${base}/${didShort}/1.0.0.json`;
    const didDocUrl = `http://${import.meta.env.VITE_URL || "192.168.93.134"}/dev/did/${didShort}/1.0.0.json`;
    setSelectedIssuer(issuer);
    setDidrForm({
      did: issuer.did,
      docUrl: issuer.didDocUrl || didDocUrl,
      docHash: "",
      hashAlg: "Keccak256CanonicalJson",
      status: "Active",
      validFrom: new Date().toISOString().slice(0, 16),
      validUntil: "",
      metadataURI: "",
    });
    setTirForm({
      did: issuer.did,
      metadataURI: vcUrl,
      validFrom: new Date().toISOString().slice(0, 16),
      validUntil: "",
      status: "Active",
      accreditationStatus: "Active",
      accreditationValidFrom: new Date().toISOString().slice(0, 16),
      accreditationValidUntil: "",
      accreditationMetadataURI: vcUrl,
      capabilitiesCsv: issuer.credentialTypes.join(", "),
      schemaIdsCsv: issuer.allowedSchemas.join(", "),
      credDefIdsCsv: issuer.allowedCredDefs.join(", "),
    });
    setEnrollOpen(true);
  };

  const fetchAccreditationHash = async (metadataURI: string) => {
    const normalizedUri = (() => {
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
    })();
    const res = await fetch(normalizedUri, { cache: "no-store" });
    if (!res.ok) {
      throw new Error(`Failed to fetch accreditation VC (${res.status}).`);
    }
    const payload = await res.json();
    const computedHash = normalizeHash32(canonicalKeccak(payload));
    if (!computedHash || !isHexString(computedHash, 32)) {
      throw new Error("Accreditation hash is invalid.");
    }
    return computedHash;
  };

  const handlePublishDidr = async () => {
    if (!didrForm.did) return;
    try {
      setLoadingDidr(true);
      const contract = await getDidrContract();
      const didHash = keccak256(toUtf8Bytes(didrForm.did));
      if (!didrForm.docHash.trim() && !didrForm.docUrl.trim()) {
        throw new Error("DID document URL or hash is required.");
      }
      const docHash = didrForm.docHash.trim()
        ? didrForm.docHash.trim()
        : await computeDidrDocHashFromUrl(didrForm.docUrl, didrForm.hashAlg);
      if (!isHexString(docHash, 32)) {
        throw new Error("Invalid DID document hash.");
      }
      const validFrom = toUnixSeconds(didrForm.validFrom, true);
      const validUntil = toUnixSeconds(didrForm.validUntil, false);
      const statusEnum = parseStatusEnum("Active");
      const algEnum = parseDidrHashAlg(didrForm.hashAlg);
      const commitment = await contract.getCommitment(didHash);
      const exists = Boolean(commitment?.[0]);
      const tx = exists
        ? await contract.updateDidDocumentCommitment(
            didHash,
            docHash,
            algEnum,
            validFrom,
            validUntil,
            statusEnum,
            didrForm.metadataURI,
          )
        : await contract.commitDidDocument(
            didHash,
            docHash,
            algEnum,
            validFrom,
            validUntil,
            statusEnum,
            didrForm.metadataURI,
          );
      await tx.wait();
      setDidrForm((prev) => ({ ...prev, docHash }));
      toast({ title: "DIDR updated" });
    } catch (error) {
      const message = error instanceof Error ? error.message : "DIDR transaction failed.";
      toast({ title: "DIDR error", description: message, variant: "destructive" });
    } finally {
      setLoadingDidr(false);
    }
  };

  const handlePublishTir = async () => {
    if (!selectedIssuer) return;
    try {
      setLoadingTir(true);
      const contract = await getTirContract();
      const did = tirForm.did;
      const validFrom = toUnixSeconds(tirForm.validFrom, true);
      const validUntil = toUnixSeconds(tirForm.validUntil, false);
      const accValidFrom = toUnixSeconds(tirForm.accreditationValidFrom, true);
      const accValidUntil = toUnixSeconds(tirForm.accreditationValidUntil, false);
      const accStatus = parseStatusEnum(tirForm.accreditationStatus);
      const accHash = await fetchAccreditationHash(tirForm.accreditationMetadataURI);
      const caps = parseList(tirForm.capabilitiesCsv).map((cap) => keccak256(toUtf8Bytes(cap)));
      const schemaIds = await resolveJsonHashList(parseList(tirForm.schemaIdsCsv));
      const credDefs = await resolveJsonHashList(parseList(tirForm.credDefIdsCsv));

      console.log("[TIR] upsertIssuerWithAccreditationAndScope payload", {
        did,
        core: {
          validFrom,
          validUntil,
          metadataURI: tirForm.metadataURI,
          addCapabilities: caps,
          removeCapabilities: [],
        },
        accreditation: {
          hash: accHash,
          validFrom: accValidFrom,
          validUntil: accValidUntil,
          status: accStatus,
          metadataURI: tirForm.accreditationMetadataURI,
        },
        scope: {
          schemaIdHashes: schemaIds,
          schemaAllowed: true,
          credDefIdHashes: credDefs,
          credDefAllowed: true,
        },
      });

      const tx = await contract.upsertIssuerWithAccreditationAndScope(
        did,
        {
          validFrom,
          validUntil,
          metadataURI: tirForm.metadataURI,
          addCapabilities: caps,
          removeCapabilities: [],
        },
        {
          hash: accHash,
          validFrom: accValidFrom,
          validUntil: accValidUntil,
          status: accStatus,
          metadataURI: tirForm.accreditationMetadataURI,
        },
        {
          schemaIdHashes: schemaIds,
          schemaAllowed: true,
          credDefIdHashes: credDefs,
          credDefAllowed: true,
        },
      );
      await tx.wait();

      const accreditedAt = new Date().toISOString().slice(0, 10);
      await upsertAllVaEntry({
        ...selectedIssuer,
        status: "accredited",
        accreditedAt,
        didDocUrl: didrForm.docUrl || selectedIssuer.didDocUrl,
      });
      toast({ title: "TIR updated", description: "Issuer accredited on-chain." });
      setEnrollOpen(false);
    } catch (error) {
      const message = error instanceof Error ? error.message : "TIR transaction failed.";
      toast({ title: "TIR error", description: message, variant: "destructive" });
    } finally {
      setLoadingTir(false);
    }
  };

  const filteredIssuers = useMemo(
    () =>
      issuers.filter(
        (issuer) =>
          issuer.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
          issuer.did.toLowerCase().includes(searchQuery.toLowerCase()),
      ),
    [issuers, searchQuery],
  );

  return (
    <MainLayout>
      <PageHeader
        icon={Building2}
        title="Trusted Accreditation Organization"
        description="Manage trusted issuers"
      >
        <Button variant="outline" onClick={handleConnectWallet}>
          {walletAccount ? `Wallet ${walletAccount.slice(0, 6)}...` : "Connect Wallet"}
        </Button>
        <Dialog open={addIssuerOpen} onOpenChange={setAddIssuerOpen}>
          <DialogTrigger asChild>
            <Button variant="gradient">
              <Plus className="w-4 h-4 mr-2" />
              Add Trusted Issuer
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Add Trusted Issuer</DialogTitle>
              <DialogDescription>
                Create the Verifiable Accreditation VC and add the issuer to allVA.json as pending.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 mt-4">
              <div className="space-y-2">
                <Label>Organization Name</Label>
                <Input
                  placeholder="University of..."
                  value={newIssuer.name}
                  onChange={(e) => setNewIssuer({ ...newIssuer, name: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>Issuer DID</Label>
                <Input
                  placeholder="did:ebsi:..."
                  value={newIssuer.did}
                  onChange={(e) => setNewIssuer({ ...newIssuer, did: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>Credential Types (Capabilities)</Label>
                <Textarea
                  placeholder="University Diploma, Academic Certificate, ..."
                  value={newIssuer.credentialTypesCsv}
                  onChange={(e) => setNewIssuer({ ...newIssuer, credentialTypesCsv: e.target.value })}
                  rows={3}
                />
              </div>
              <div className="space-y-2">
                <Label>Allowed VC Schemas (CSV)</Label>
                <Textarea
                  placeholder="https://.../schema.json, https://.../another.json"
                  value={newIssuer.schemaIdsCsv}
                  onChange={(e) => setNewIssuer({ ...newIssuer, schemaIdsCsv: e.target.value })}
                  rows={3}
                />
              </div>
              <div className="space-y-2">
                <Label>Allowed Credential Definitions (CSV)</Label>
                <Textarea
                  placeholder="https://.../creddef.json, urn:creddef:..."
                  value={newIssuer.credDefIdsCsv}
                  onChange={(e) => setNewIssuer({ ...newIssuer, credDefIdsCsv: e.target.value })}
                  rows={3}
                />
              </div>
              <div className="space-y-2">
                <Label>TAO DID (issuer of accreditation VC)</Label>
                <Input
                  placeholder="did:ebsi:..."
                  value={newIssuer.taoDid}
                  onChange={(e) => setNewIssuer({ ...newIssuer, taoDid: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>Roles (CSV)</Label>
                <Input
                  placeholder="issuer, institution"
                  value={newIssuer.rolesCsv}
                  onChange={(e) => setNewIssuer({ ...newIssuer, rolesCsv: e.target.value })}
                />
              </div>
              <div className="space-y-2">
                <Label>Post URL base</Label>
                <Input
                  placeholder="http://host/dev/vc/accreditation"
                  value={newIssuer.postUrlBase}
                  onChange={(e) => setNewIssuer({ ...newIssuer, postUrlBase: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Version</Label>
                  <Input
                    placeholder="1.0.0"
                    value={newIssuer.version}
                    onChange={(e) => setNewIssuer({ ...newIssuer, version: e.target.value })}
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Valid From</Label>
                  <Input
                    type="datetime-local"
                    value={newIssuer.validFrom}
                    onChange={(e) => setNewIssuer({ ...newIssuer, validFrom: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>Valid Until (optional)</Label>
                  <Input
                    type="datetime-local"
                    value={newIssuer.validUntil}
                    onChange={(e) => setNewIssuer({ ...newIssuer, validUntil: e.target.value })}
                  />
                </div>
              </div>
              <Button onClick={handleGenerateAccreditationVc} className="w-full" disabled={publishingVa}>
                <Shield className="w-4 h-4 mr-2" />
                {publishingVa ? "Publishing..." : "Generate & Publish VA"}
              </Button>
            </div>
          </DialogContent>
        </Dialog>

        <Dialog open={enrollOpen} onOpenChange={setEnrollOpen}>
          <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Enroll Trusted Issuer (DIDR + TIR)</DialogTitle>
              <DialogDescription>
                Publish DIDR commitment first, then authorize issuer in TIR. All contract actions are available below.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-6 mt-4">
              <div className="space-y-2">
                <Label>Issuer DID</Label>
                <Input value={didrForm.did} onChange={(e) => setDidrForm({ ...didrForm, did: e.target.value })} />
              </div>
              <div className="space-y-2">
                <Label>DID Document URL</Label>
                <Input
                  value={didrForm.docUrl}
                  onChange={(e) => setDidrForm({ ...didrForm, docUrl: e.target.value })}
                  placeholder="http://.../dev/did/<issuer>/1.0.0.json"
                />
                <p className="text-xs text-muted-foreground">
                  Hash is computed automatically from this URL.
                </p>
              </div>
              <div className="space-y-2">
                <Label>DID Document Hash (optional)</Label>
                <Input
                  value={didrForm.docHash}
                  onChange={(e) => setDidrForm({ ...didrForm, docHash: e.target.value })}
                  placeholder="0x..."
                />
                <p className="text-xs text-muted-foreground">
                  If empty, hash is computed from DID document URL using selected algorithm.
                </p>
              </div>
              <div className="grid md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>DIDR Hash Algorithm</Label>
                  <Select
                    value={didrForm.hashAlg}
                    onValueChange={(value) => setDidrForm({ ...didrForm, hashAlg: value as DidrHashAlg })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select algorithm" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Keccak256CanonicalJson">Keccak256 Canonical JSON</SelectItem>
                      <SelectItem value="Keccak256JwsCompact">Keccak256 JWS Compact</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>DIDR Status</Label>
                  <Select
                    value={didrForm.status}
                    onValueChange={(value) => setDidrForm({ ...didrForm, status: value as DidrStatus })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Active">Active</SelectItem>
                      <SelectItem value="Suspended">Suspended</SelectItem>
                      <SelectItem value="Revoked">Revoked</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="grid md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>DIDR Valid From</Label>
                  <Input
                    type="datetime-local"
                    value={didrForm.validFrom}
                    onChange={(e) => setDidrForm({ ...didrForm, validFrom: e.target.value })}
                  />
                </div>
                <div className="space-y-2">
                  <Label>DIDR Valid Until</Label>
                  <Input
                    type="datetime-local"
                    value={didrForm.validUntil}
                    onChange={(e) => setDidrForm({ ...didrForm, validUntil: e.target.value })}
                  />
                </div>
              </div>
              <div className="space-y-2">
                <Label>DIDR Metadata URI</Label>
                <Input
                  value={didrForm.metadataURI}
                  onChange={(e) => setDidrForm({ ...didrForm, metadataURI: e.target.value })}
                  placeholder="ipfs://... or https://..."
                />
              </div>
              <div className="flex flex-wrap gap-2">
                <Button onClick={handlePublishDidr} disabled={loadingDidr}>
                  {loadingDidr ? "Publishing DIDR..." : "Publish DIDR"}
                </Button>
              </div>

              <div className="border-t border-border/60 pt-4 space-y-4">
                <div className="space-y-2">
                  <Label>TIR Issuer DID</Label>
                  <Input value={tirForm.did} onChange={(e) => setTirForm({ ...tirForm, did: e.target.value })} />
                </div>
                <div className="space-y-2">
                  <Label>TIR Metadata URI</Label>
                  <Input
                    value={tirForm.metadataURI}
                    onChange={(e) => setTirForm({ ...tirForm, metadataURI: e.target.value })}
                    placeholder="https://.../va.json"
                  />
                </div>
                <div className="grid md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label>TIR Valid From</Label>
                    <Input
                      type="datetime-local"
                      value={tirForm.validFrom}
                      onChange={(e) => setTirForm({ ...tirForm, validFrom: e.target.value })}
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>TIR Valid Until</Label>
                    <Input
                      type="datetime-local"
                      value={tirForm.validUntil}
                      onChange={(e) => setTirForm({ ...tirForm, validUntil: e.target.value })}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label>TIR Issuer Status</Label>
                  <Select
                    value={tirForm.status}
                    onValueChange={(value) => setTirForm({ ...tirForm, status: value as TirStatus })}
                  >
                    <SelectTrigger>
                      <SelectValue placeholder="Select status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Active">Active</SelectItem>
                      <SelectItem value="Suspended">Suspended</SelectItem>
                      <SelectItem value="Revoked">Revoked</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Capabilities (CSV)</Label>
                  <Textarea
                    rows={3}
                    value={tirForm.capabilitiesCsv}
                    onChange={(e) => setTirForm({ ...tirForm, capabilitiesCsv: e.target.value })}
                  />
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button onClick={handlePublishTir} disabled={loadingTir}>
                    {loadingTir ? "Publishing TIR..." : "Publish TIR"}
                  </Button>
                </div>

                <div className="space-y-2">
                  <Label>Schema IDs (CSV)</Label>
                  <Textarea
                    rows={3}
                    value={tirForm.schemaIdsCsv}
                    onChange={(e) => setTirForm({ ...tirForm, schemaIdsCsv: e.target.value })}
                  />
                </div>

                <div className="space-y-2">
                  <Label>Credential Definition IDs (CSV)</Label>
                  <Textarea
                    rows={3}
                    value={tirForm.credDefIdsCsv}
                    onChange={(e) => setTirForm({ ...tirForm, credDefIdsCsv: e.target.value })}
                  />
                </div>

                <div className="border-t border-border/60 pt-4 space-y-4">
                  <div className="space-y-2">
                    <Label>Accreditation VC URL</Label>
                    <Input
                      value={tirForm.accreditationMetadataURI}
                      onChange={(e) =>
                        setTirForm({ ...tirForm, accreditationMetadataURI: e.target.value })
                      }
                      placeholder="http://.../vc.json"
                    />
                  </div>
                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label>Accreditation Valid From</Label>
                      <Input
                        type="datetime-local"
                        value={tirForm.accreditationValidFrom}
                        onChange={(e) =>
                          setTirForm({ ...tirForm, accreditationValidFrom: e.target.value })
                        }
                      />
                    </div>
                    <div className="space-y-2">
                      <Label>Accreditation Valid Until</Label>
                      <Input
                        type="datetime-local"
                        value={tirForm.accreditationValidUntil}
                        onChange={(e) =>
                          setTirForm({ ...tirForm, accreditationValidUntil: e.target.value })
                        }
                      />
                    </div>
                  </div>
                  <div className="space-y-2">
                    <Label>Accreditation Status</Label>
                    <Select
                      value={tirForm.accreditationStatus}
                      onValueChange={(value) =>
                        setTirForm({ ...tirForm, accreditationStatus: value as AccreditationStatus })
                      }
                    >
                      <SelectTrigger>
                        <SelectValue placeholder="Select status" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="Active">Active</SelectItem>
                        <SelectItem value="Suspended">Suspended</SelectItem>
                        <SelectItem value="Revoked">Revoked</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </PageHeader>

      <div className="container mx-auto px-4 py-8">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          <StatCard icon={Users} label="Total Issuers" value={issuers.length} />
          <StatCard icon={Check} label="Accredited" value={issuers.filter((i) => i.status === "accredited").length} />
          <StatCard icon={AlertTriangle} label="Pending Review" value={issuers.filter((i) => i.status === "pending").length} />
        </div>

        <DataCard
          title="Trusted Issuers Registry"
          description="All trusted issuers from allVA.json"
          actions={
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search issuers..."
                className="pl-9 w-64"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          }
        >
          {filteredIssuers.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Organization</TableHead>
                    <TableHead>DID</TableHead>
                    <TableHead>Credential Types</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Accredited</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredIssuers.map((issuer) => (
                    <TableRow key={issuer.id}>
                      <TableCell>
                        <div className="flex items-center gap-3">
                          <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center">
                            <Building2 className="w-5 h-5 text-primary" />
                          </div>
                          <span className="font-medium">{issuer.name}</span>
                        </div>
                      </TableCell>
                      <TableCell className="font-mono text-sm">{issuer.did}</TableCell>
                      <TableCell>
                        {issuer.credentialTypes.length ? (
                          <div className="flex flex-wrap gap-1">
                            {issuer.credentialTypes.map((type) => (
                              <Badge key={type} variant="secondary" className="text-xs">
                                {type}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge
                          className={cn(
                            issuer.status === "accredited"
                              ? "bg-success/10 text-success border-success/30"
                              : issuer.status === "revoked"
                                ? "bg-destructive/10 text-destructive border-destructive/30"
                                : issuer.status === "suspended"
                                  ? "bg-warning/10 text-warning border-warning/30"
                                  : "bg-muted/50 text-muted-foreground border-muted",
                          )}
                        >
                          {issuer.status}
                        </Badge>
                      </TableCell>
                      <TableCell>{issuer.accreditedAt}</TableCell>
                      <TableCell className="text-right">
                        {issuer.status === "pending" ? (
                          <Button variant="outline" size="sm" onClick={() => openEnrollDialog(issuer)}>
                            <Check className="w-4 h-4 mr-1" />
                            Accreditate
                          </Button>
                        ) : (
                          <Button variant="ghost" size="sm" onClick={() => openEnrollDialog(issuer)}>
                            Manage
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <EmptyState
              icon={Building2}
              title="No issuers found"
              description={searchQuery ? "Try a different search term" : "Add your first trusted issuer"}
              actionLabel={searchQuery ? undefined : "Add Issuer"}
              onAction={searchQuery ? undefined : () => setAddIssuerOpen(true)}
            />
          )}
        </DataCard>
      </div>
    </MainLayout>
  );
}
