import type { ReactNode } from "react";
import { Badge } from "@/components/ui/badge";

interface PagePlaceholderProps {
  title: string;
  description: string;
  milestone: string;
  children?: ReactNode;
}

// Clean placeholder shell used until each page is built out in W4-W9.
export function PagePlaceholder({
  title,
  description,
  milestone,
  children,
}: PagePlaceholderProps) {
  return (
    <div className="flex flex-col gap-6 p-6">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        <Badge variant="secondary">{milestone}</Badge>
      </div>
      <p className="max-w-2xl text-sm text-muted-foreground">{description}</p>
      {children}
    </div>
  );
}
