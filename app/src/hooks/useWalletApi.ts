import { useEffect, useMemo } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { walletApi } from "@/lib/wallet-api";
import { getStoredToken, getStoredWalletId } from "@/lib/api";
import type { CredentialEntry, DidEntry, KeyEntry, SessionResponse, UserInfo, WalletSummary } from "@/types/wallet";

const queryKeys = {
  session: ["wallet", "session"] as const,
  userInfo: ["wallet", "user-info"] as const,
  wallets: ["wallet", "list"] as const,
  dids: (walletId: string) => ["wallet", walletId, "dids"] as const,
  keys: (walletId: string) => ["wallet", walletId, "keys"] as const,
  credentials: (walletId: string) => ["wallet", walletId, "credentials"] as const,
};

export const useWalletSession = () =>
  useQuery<SessionResponse>({
    queryKey: queryKeys.session,
    queryFn: () => walletApi.getSession(),
    staleTime: 60_000,
  });

export const useUserInfo = (enabled = true) =>
  useQuery<UserInfo>({
    queryKey: queryKeys.userInfo,
    queryFn: () => walletApi.getUserInfo(),
    enabled,
    staleTime: 60_000,
  });

export const useWallets = (enabled = true) =>
  useQuery<WalletSummary[]>({
    queryKey: queryKeys.wallets,
    queryFn: () => walletApi.listWallets(getStoredToken()),
    enabled,
  });

export const useWalletResources = (walletId?: string) => {
  const enabled = Boolean(walletId);

  const didsQuery = useQuery<DidEntry[]>({
    queryKey: walletId ? queryKeys.dids(walletId) : ["wallet", "dids"],
    queryFn: () => walletApi.listDids(walletId!, getStoredToken()),
    enabled,
  });

  const keysQuery = useQuery<KeyEntry[]>({
    queryKey: walletId ? queryKeys.keys(walletId) : ["wallet", "keys"],
    queryFn: () => walletApi.listKeys(walletId!, getStoredToken()),
    enabled,
  });

  const credentialsQuery = useQuery<CredentialEntry[]>({
    queryKey: walletId ? queryKeys.credentials(walletId) : ["wallet", "credentials"],
    queryFn: () => walletApi.listCredentials(walletId!, getStoredToken()),
    enabled,
  });

  return { didsQuery, keysQuery, credentialsQuery };
};

export const useCreateDid = (walletId?: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: { type: "ebsi" | "key" | "web"; options?: Record<string, string> }) =>
      walletApi.createDid(walletId!, params.type, params.options, getStoredToken()),
    onSuccess: () => {
      if (walletId) qc.invalidateQueries({ queryKey: queryKeys.dids(walletId) });
    },
  });
};

export const useGenerateKey = (walletId?: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: { keyType: string; backend?: string; alias?: string }) =>
      walletApi.generateKey(walletId!, { backend: params.backend, keyType: params.keyType, alias: params.alias }, getStoredToken()),
    onSuccess: () => {
      if (walletId) qc.invalidateQueries({ queryKey: queryKeys.keys(walletId) });
    },
  });
};

export const useAcceptCredentialOffer = (walletId?: string) => {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (params: { offer: string; did?: string; pinOrTxCode?: string; requireUserInput?: string }) =>
      walletApi.acceptCredentialOffer(walletId!, params.offer, {
        did: params.did,
        pinOrTxCode: params.pinOrTxCode,
        requireUserInput: params.requireUserInput,
      }),
    onSuccess: () => {
      if (walletId) qc.invalidateQueries({ queryKey: queryKeys.credentials(walletId) });
    },
  });
};

export const usePrimaryWallet = () => {
  const session = useWalletSession();
  const hasSession = Boolean(session.data?.sessionId);
  const storedWalletId = getStoredWalletId();
  const wallets = useWallets(hasSession || Boolean(storedWalletId));
  const primaryWalletId = useMemo(
    () => wallets.data?.[0]?.id || storedWalletId || "",
    [wallets.data, storedWalletId],
  );

  useEffect(() => {
    const first = wallets.data?.[0]?.id;
    if (first) {
      try {
        localStorage.setItem("wallet_id", first);
      } catch {
        // localStorage not available (ignore)
      }
    }
  }, [wallets.data]);

  return { session, wallets, primaryWalletId };
};
