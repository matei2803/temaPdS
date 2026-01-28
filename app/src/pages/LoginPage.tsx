import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Shield, LogIn, UserPlus, Activity, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useToast } from "@/hooks/use-toast";
import { walletApi, resolveWalletBase } from "@/lib/wallet-api";
import { buildUserPath, extractUserId } from "@/lib/auth";
import type { AuthPayload } from "@/types/wallet";

const persistAuth = (payload: AuthPayload, user?: Record<string, unknown>) => {
  if (payload.token) localStorage.setItem("wallet_token", payload.token);
  if (payload.id) localStorage.setItem("wallet_id", payload.id);
  if (payload.keycloakUserId) localStorage.setItem("wallet_keycloak_user_id", payload.keycloakUserId);
  if (user) localStorage.setItem("wallet_user", JSON.stringify(user));
};

export default function LoginPage() {
  const navigate = useNavigate();
  const { toast } = useToast();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [email, setEmail] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [mode, setMode] = useState<"login" | "register">("login");
  const [probeResult, setProbeResult] = useState("");

  const baseUrl = resolveWalletBase() || "(same-origin)";

  const onAuthSuccess = async (auth: AuthPayload, extraUser?: Record<string, unknown>) => {
    persistAuth(auth, { username, ...extraUser });
    let userId = auth.id || "";
    try {
      const info = await walletApi.getUserInfo();
      const extracted = extractUserId(info);
      if (extracted) {
        userId = extracted;
        localStorage.setItem("wallet_user_id", extracted);
        localStorage.setItem("wallet_user_info", JSON.stringify(info));
      }
    } catch {
      // fallback to auth.id
    }
    toast({ title: "Autentificat", description: "Te-am logat cu succes." });
    if (userId) {
      navigate(buildUserPath(userId, "wallet"), { replace: true });
    } else {
      navigate("/login", { replace: true });
    }
  };

  const loginMutation = useMutation({
    mutationFn: () => walletApi.loginKeycloak({ username, password }),
    onSuccess: (auth) => onAuthSuccess(auth),
    onError: (err) => {
      const msg = err instanceof Error ? err.message : "Login failed";
      toast({ variant: "destructive", title: "Eroare autentificare", description: msg });
    },
  });

  const registerMutation = useMutation({
    mutationFn: async () => {
      if (password !== confirmPassword) throw new Error("Parolele nu coincid.");
      await walletApi.createKeycloakAccount({ username, password, email });
      const auth = await walletApi.loginKeycloak({ username, password });
      return auth;
    },
    onSuccess: (auth) => onAuthSuccess(auth, { email }),
    onError: (err) => {
      const msg = err instanceof Error ? err.message : "Nu am putut crea contul.";
      toast({ variant: "destructive", title: "Eroare creare cont", description: msg });
    },
  });

  const probeMutation = useMutation({
    mutationFn: () => walletApi.probeKeycloakToken(),
    onSuccess: (res) => setProbeResult(JSON.stringify(res, null, 2)),
    onError: (err) => {
      const msg = err instanceof Error ? err.message : "Probe failed";
      setProbeResult(`Eroare: ${msg}`);
    },
  });

  const logoutMutation = useMutation({
    mutationFn: () => walletApi.logoutKeycloak(),
    onSettled: () => {
      localStorage.removeItem("wallet_token");
      localStorage.removeItem("wallet_id");
      localStorage.removeItem("wallet_keycloak_user_id");
      localStorage.removeItem("wallet_user");
      toast({ title: "Delogat", description: "Sesiunea a fost inchisa." });
    },
  });

  const busy = loginMutation.isPending || registerMutation.isPending;

  return (
    <div className="min-h-screen bg-gradient-to-br from-[#1f1c1c] via-[#1a1717] to-[#0f0d0d] flex items-center justify-center px-4 py-10 relative overflow-hidden">
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute -left-10 top-10 h-64 w-64 bg-[#910f0f]/30 blur-3xl rounded-full" />
        <div className="absolute right-0 bottom-0 h-72 w-72 bg-[#b63030]/25 blur-3xl rounded-full" />
      </div>

      <Card className="relative max-w-4xl w-full border-border/60 bg-[#201c1c]/90 shadow-2xl">
        <CardHeader className="flex flex-row items-start justify-between gap-4 pb-4">
          <div>
            <p className="text-sm text-muted-foreground uppercase tracking-widest flex items-center gap-2">
              <Shield className="w-4 h-4 text-primary" />
              Keycloak Auth
            </p>
            <CardTitle className="text-3xl mt-2">Wallet Login</CardTitle>
            <p className="text-muted-foreground mt-1">
              Autentificare sau creare cont.
            </p>
          </div>
          <div className="text-right text-xs text-muted-foreground">
            <div>API base</div>
            <code className="px-2 py-1 rounded bg-black/30 border border-border/60 text-primary/80">
              {baseUrl}
            </code>
          </div>
        </CardHeader>

        <CardContent className="grid md:grid-cols-2 gap-8">
          <div>
            <Tabs value={mode} onValueChange={(val) => setMode(val as "login" | "register")}>
              <TabsList className="grid grid-cols-2 bg-black/30 border border-border/60">
                <TabsTrigger value="login">Log in</TabsTrigger>
                <TabsTrigger value="register">Create account</TabsTrigger>
              </TabsList>

              <TabsContent value="login" className="mt-6">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="login-username">Username</Label>
                    <Input
                      id="login-username"
                      placeholder="user"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="login-password">Password</Label>
                    <Input
                      id="login-password"
                      type="password"
                      placeholder="********"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="current-password"
                    />
                  </div>
                  <Button
                    className="w-full gap-2"
                    onClick={() => loginMutation.mutate()}
                    disabled={busy}
                  >
                    {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <LogIn className="w-4 h-4" />}
                    {busy ? "Signing in..." : "Sign in"}
                  </Button>
                </div>
              </TabsContent>

              <TabsContent value="register" className="mt-6">
                <div className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="register-username">Username</Label>
                    <Input
                      id="register-username"
                      placeholder="newuser"
                      value={username}
                      onChange={(e) => setUsername(e.target.value)}
                      autoComplete="username"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="register-email">Email</Label>
                    <Input
                      id="register-email"
                      type="email"
                      placeholder="you@example.com"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      autoComplete="email"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="register-password">Password</Label>
                    <Input
                      id="register-password"
                      type="password"
                      placeholder="********"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      autoComplete="new-password"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="register-confirm">Confirm password</Label>
                    <Input
                      id="register-confirm"
                      type="password"
                      placeholder="********"
                      value={confirmPassword}
                      onChange={(e) => setConfirmPassword(e.target.value)}
                      autoComplete="new-password"
                    />
                  </div>
                  <Button
                    className="w-full gap-2"
                    variant="secondary"
                    onClick={() => registerMutation.mutate()}
                    disabled={busy}
                  >
                    {busy ? <RefreshCw className="w-4 h-4 animate-spin" /> : <UserPlus className="w-4 h-4" />}
                    {busy ? "Creating..." : "Create account"}
                  </Button>
                </div>
              </TabsContent>
            </Tabs>
          </div>

          <div className="space-y-4">
            <div className="p-4 rounded-xl border border-border/60 bg-black/20">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-muted-foreground">Utilities</p>
                  <h4 className="text-lg font-semibold">Debug endpoints</h4>
                </div>
                <Activity className="w-5 h-5 text-primary" />
              </div>
              <div className="grid gap-3 mt-4">
                <Button
                  variant="outline"
                  className="justify-start gap-2"
                  onClick={() => probeMutation.mutate()}
                  disabled={probeMutation.isPending}
                >
                  {probeMutation.isPending ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <Shield className="w-4 h-4" />
                  )}
                  Test /wallet-api/auth/keycloak/token
                </Button>
                <Button
                  variant="outline"
                  className="justify-start gap-2"
                  onClick={() => logoutMutation.mutate()}
                >
                  <LogIn className="w-4 h-4 rotate-180" />
                  Force logout & clear local
                </Button>
              </div>
              {probeResult && (
                <Textarea
                  readOnly
                  value={probeResult}
                  className="mt-3 h-40 font-mono text-xs bg-black/30 border-border/60"
                />
              )}
            </div>
            <div className="text-sm text-muted-foreground">
              Dupa autentificare, tokenul si ID-ul sunt stocate local (wallet_token, wallet_id, wallet_keycloak_user_id).
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
