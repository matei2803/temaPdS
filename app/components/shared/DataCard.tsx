import { ReactNode } from "react";
import { cn } from "@/lib/utils";

interface DataCardProps {
  title: string;
  description?: string;
  children: ReactNode;
  actions?: ReactNode;
  className?: string;
}

export function DataCard({ title, description, children, actions, className }: DataCardProps) {
  return (
    <div className={cn(
      "bg-gradient-card border border-border/50 rounded-xl overflow-hidden card-shadow",
      className
    )}>
      <div className="px-6 py-4 border-b border-border/50 flex items-center justify-between">
        <div>
          <h3 className="font-semibold">{title}</h3>
          {description && <p className="text-sm text-muted-foreground mt-0.5">{description}</p>}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      <div className="p-6">
        {children}
      </div>
    </div>
  );
}
