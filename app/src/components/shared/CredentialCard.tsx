import { FileCheck, Calendar, User, MoreVertical } from "lucide-react";
import { cn } from "@/lib/utils";

interface CredentialCardProps {
  type: string;
  issuer: string;
  issuedAt: string;
  status: "valid" | "expired" | "revoked";
  onClick?: () => void;
  className?: string;
}

export function CredentialCard({ 
  type, 
  issuer, 
  issuedAt, 
  status, 
  onClick,
  className 
}: CredentialCardProps) {
  return (
    <div className={cn(
      "bg-gradient-card border border-border/50 rounded-xl p-5 card-shadow transition-all duration-200 hover:border-primary/30 group cursor-pointer",
      className
    )} onClick={onClick}>
      <div className="flex items-start justify-between">
        <div className="w-12 h-12 rounded-xl bg-primary/10 flex items-center justify-center">
          <FileCheck className="w-6 h-6 text-primary" />
        </div>
        <span className={cn(
          "text-xs font-medium px-2.5 py-1 rounded-full",
          status === "valid" && "bg-success/10 text-success",
          status === "expired" && "bg-warning/10 text-warning",
          status === "revoked" && "bg-destructive/10 text-destructive"
        )}>
          {status.charAt(0).toUpperCase() + status.slice(1)}
        </span>
      </div>
      
        <div className="mt-4">
        <h4 className="font-semibold text-lg">{type}</h4>
        <div className="mt-3 space-y-2 text-sm text-muted-foreground">
          <div className="flex items-center gap-2">
            <User className="w-4 h-4" />
            <span className="truncate max-w-[220px]" title={issuer}>Issued by {issuer}</span>
          </div>
          <div className="flex items-center gap-2">
            <Calendar className="w-4 h-4" />
            <span className="truncate max-w-[200px]" title={issuedAt}>{issuedAt}</span>
          </div>
        </div>
      </div>
    </div>
  );
}
