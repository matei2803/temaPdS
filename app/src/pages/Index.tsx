import { Link, useLocation } from "react-router-dom";
import { Wallet, FileCheck, ShieldCheck, Building2, ArrowRight, Sparkles } from "lucide-react";
import { MainLayout } from "@/components/layout/MainLayout";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const features = [
  {
    icon: Wallet,
    title: "Wallet",
    description: "Create DIDs, manage keys, and store your verifiable credentials securely.",
    path: "wallet",
    color: "from-primary to-primary/50",
  },
  {
    icon: FileCheck,
    title: "Issuer",
    description: "Issue verifiable credentials to holders with customizable schemas.",
    path: "issuer",
    color: "from-accent to-accent/50",
  },
  {
    icon: ShieldCheck,
    title: "Verifier",
    description: "Request and verify credentials with secure presentation exchange.",
    path: "verifier",
    color: "from-success to-success/50",
  },
  {
    icon: Building2,
    title: "TAO",
    description: "Manage trusted issuers as a Trusted Accreditation Organization.",
    path: "tao",
    color: "from-warning to-warning/50",
  },
];

export default function Index() {
  const location = useLocation();
  const userId = location.pathname.split("/").filter(Boolean)[0] || "";
  const base = userId ? `/${userId}` : "";
  return (
    <MainLayout>
      <div className="container mx-auto px-4 py-16">
        {/* Hero Section */}
        <div className="text-center max-w-3xl mx-auto mb-16 animate-fade-in">
          <div className="inline-flex items-center gap-2 px-4 py-2 bg-primary/10 border border-primary/30 rounded-full text-sm text-primary mb-6">
            <Sparkles className="w-4 h-4" />
            Verifiable Credentials Simulator
          </div>
          <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6">
            Experience the Future of{" "}
            <span className="text-gradient">Digital Identity</span>
          </h1>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Create wallets, issue credentials, verify presentations, and manage trusted issuers.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mt-8">
            <Link to={`${base}/wallet`}>
              <Button variant="gradient" size="lg" className="gap-2">
                Get Started
                <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
            <Link to={`${base}/issuer`}>
              <Button variant="outline" size="lg">
                Issue Credentials
              </Button>
            </Link>
          </div>
        </div>

        {/* Features Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-5xl mx-auto">
          {features.map((feature, index) => (
            <Link
              key={feature.path}
              to={`${base}/${feature.path}`}
              className="group animate-fade-in"
              style={{ animationDelay: `${index * 100}ms` }}
            >
              <div className="h-full bg-gradient-card border border-border/50 rounded-2xl p-6 card-shadow transition-all duration-300 hover:border-primary/30 hover:scale-[1.02]">
                <div className={cn(
                  "w-14 h-14 rounded-xl bg-gradient-to-br flex items-center justify-center mb-4 transition-transform group-hover:scale-110",
                  feature.color
                )}>
                  <feature.icon className="w-7 h-7 text-primary-foreground" />
                </div>
                <h3 className="text-xl font-semibold mb-2 group-hover:text-primary transition-colors">
                  {feature.title}
                </h3>
                <p className="text-muted-foreground">{feature.description}</p>
                <div className="flex items-center gap-2 mt-4 text-primary opacity-0 group-hover:opacity-100 transition-opacity">
                  <span className="text-sm font-medium">Explore</span>
                  <ArrowRight className="w-4 h-4" />
                </div>
              </div>
            </Link>
          ))}
        </div>

        {/* Info Section */}
        <div className="mt-20 text-center max-w-2xl mx-auto">
          <h2 className="text-2xl font-bold mb-4">Powered by me</h2>
          <p className="text-muted-foreground">
            This simulator uses walt.id's open-source SSI infrastructure to demonstrate 
            the complete flow of verifiable credentials in the EBSI like ecosystem.
          </p>
        </div>
      </div>
    </MainLayout>
  );
}
