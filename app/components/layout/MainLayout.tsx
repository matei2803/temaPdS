import { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import { Wallet, FileCheck, ShieldCheck, Building2, Menu, X } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";

interface MainLayoutProps {
  children: ReactNode;
}

export function MainLayout({ children }: MainLayoutProps) {
  const location = useLocation();
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const pathParts = location.pathname.split("/").filter(Boolean);
  const userId = pathParts[0] || "";
  const base = userId ? `/${userId}` : "";
  const isIssuer = (() => {
    try {
      return localStorage.getItem("wallet_is_issuer") === "1";
    } catch {
      return false;
    }
  })();
  const navItems = [
    { path: `${base}/wallet`, label: "Wallet", icon: Wallet },
    ...(isIssuer
      ? [
          { path: `${base}/issuer`, label: "Issuer", icon: FileCheck },
          { path: `${base}/verifier`, label: "Verifier", icon: ShieldCheck },
          { path: `${base}/tao`, label: "TAO", icon: Building2 },
        ]
      : []),
  ];
  const homePath = userId ? `${base}/wallet` : "/login";

  return (
    <div className="min-h-screen bg-background grid-pattern">
      {/* Background glow effect */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-primary/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-accent/5 rounded-full blur-3xl" />
      </div>

      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
        <div className="container mx-auto px-4">
          <div className="flex h-16 items-center justify-between">
            <Link to={homePath} className="flex items-center gap-3 group">
              <div className="w-10 h-10 rounded-xl bg-gradient-primary flex items-center justify-center shadow-lg group-hover:shadow-primary/30 transition-shadow">
                <span className="text-primary-foreground font-bold text-lg">M</span>
              </div>
              <span className="text-xl font-bold tracking-tight">
                My <span className="text-gradient">Application</span>
              </span>
            </Link>

            {/* Desktop Navigation */}
            <nav className="hidden md:flex items-center gap-1">
              {navItems.map((item) => {
                const isActive = location.pathname === item.path;
                return (
                  <Link key={item.path} to={item.path}>
                    <Button
                      variant={isActive ? "glow" : "ghost"}
                      className={cn(
                        "gap-2 transition-all duration-200",
                        isActive && "animate-pulse-glow"
                      )}
                    >
                      <item.icon className="w-4 h-4" />
                      {item.label}
                    </Button>
                  </Link>
                );
              })}
            </nav>

            {/* Mobile menu button */}
            <Button
              variant="ghost"
              size="icon"
              className="md:hidden"
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            >
              {mobileMenuOpen ? <X /> : <Menu />}
            </Button>
          </div>
        </div>

        {/* Mobile Navigation */}
        {mobileMenuOpen && (
          <nav className="md:hidden border-t border-border/50 bg-background/95 backdrop-blur-xl animate-fade-in">
            <div className="container mx-auto px-4 py-4 flex flex-col gap-2">
              {navItems.map((item) => {
                const isActive = location.pathname === item.path;
                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    onClick={() => setMobileMenuOpen(false)}
                  >
                    <Button
                      variant={isActive ? "glow" : "ghost"}
                      className="w-full justify-start gap-3"
                    >
                      <item.icon className="w-5 h-5" />
                      {item.label}
                    </Button>
                  </Link>
                );
              })}
            </div>
          </nav>
        )}
      </header>

      {/* Main Content */}
      <main className="relative z-10">
        {children}
      </main>
    </div>
  );
}
