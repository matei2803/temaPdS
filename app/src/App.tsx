import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route, Navigate, Outlet, useLocation, useNavigate, useParams } from "react-router-dom";
import { useEffect, useState } from "react";
import Index from "./pages/Index";
import WalletPage from "./pages/WalletPage";
import IssuerPage from "./pages/IssuerPage";
import VerifierPage from "./pages/VerifierPage";
import TAOPage from "./pages/TAOPage";
import NotFound from "./pages/NotFound";
import LoginPage from "./pages/LoginPage";
import { walletApi } from "@/lib/wallet-api";
import { getStoredToken, getStoredWalletId } from "@/lib/api";
import { buildUserPath, extractUserId } from "@/lib/auth";

const queryClient = new QueryClient();
const normalizeDid = (did: string) => did.trim().toLowerCase().split("#")[0].split("?")[0];

const AuthGate = () => {
  const { userId } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      const token = getStoredToken();
      if (!token) {
        navigate("/login", { replace: true });
        return;
      }
      let actualId = "";
      try {
        const info = await walletApi.getUserInfo();
        actualId = extractUserId(info) || localStorage.getItem("wallet_user_id") || "";
        if (!actualId) throw new Error("User ID missing");
        localStorage.setItem("wallet_user_id", actualId);
      } catch {
        localStorage.removeItem("wallet_token");
        localStorage.removeItem("wallet_id");
        localStorage.removeItem("wallet_keycloak_user_id");
        localStorage.removeItem("wallet_user");
        localStorage.removeItem("wallet_user_id");
        localStorage.removeItem("wallet_is_issuer");
        navigate("/login", { replace: true });
        return;
      }

      if (userId !== actualId) {
        const rest = location.pathname.split("/").slice(2).join("/") || "wallet";
        navigate(buildUserPath(actualId, rest) + location.search, { replace: true });
        return;
      }

      let walletId = getStoredWalletId();
      let wallets: { id: string }[] = [];
      try {
        wallets = await walletApi.listWallets(token);
      } catch {
        wallets = [];
      }
      if (!walletId) {
        walletId = wallets[0]?.id || "";
        if (walletId) localStorage.setItem("wallet_id", walletId);
      }

      let isIssuer = false;
      try {
        const checks = await Promise.all(
          wallets.map(async (w) => {
            const [dids, issuersRaw] = await Promise.all([
              walletApi.listDids(w.id, token),
              walletApi.listIssuers(w.id, token),
            ]);
            const didSet = new Set(
              dids
                .map((d) => normalizeDid(d.did || d.id || ""))
                .filter(Boolean)
            );
            const issuers = Array.isArray(issuersRaw) ? issuersRaw : [];
            return issuers.some((item: any) => {
              const cand = typeof item === "object" ? item.did : "";
              return typeof cand === "string" && didSet.has(normalizeDid(cand));
            });
          })
        );
        isIssuer = checks.some(Boolean);
      } catch {
        isIssuer = false;
      }

      try {
        localStorage.setItem("wallet_is_issuer", isIssuer ? "1" : "0");
      } catch {
        // ignore storage errors
      }
      if (!isIssuer) {
        const walletPath = buildUserPath(actualId, "wallet");
        if (location.pathname !== walletPath) {
          navigate(walletPath + location.search, { replace: true });
          return;
        }
      }
      if (!cancelled) setChecking(false);
    };
    run();
    return () => {
      cancelled = true;
    };
  }, [userId, location.pathname, location.search, navigate]);

  if (checking) {
    return <div className="min-h-screen flex items-center justify-center text-muted-foreground">Checking session…</div>;
  }

  return <Outlet />;
};

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/login" replace />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/:userId" element={<AuthGate />}>
            <Route index element={<Index />} />
            <Route path="wallet" element={<WalletPage />} />
            <Route path="issuer" element={<IssuerPage />} />
            <Route path="verifier" element={<VerifierPage />} />
            <Route path="tao" element={<TAOPage />} />
            <Route path="*" element={<NotFound />} />
          </Route>
          <Route path="*" element={<NotFound />} />
        </Routes>
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
