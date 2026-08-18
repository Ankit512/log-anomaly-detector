import * as React from "react";
import { cn } from "@/lib/utils";
import { sevVar } from "@/lib/severity";

export function Badge({ className, ...props }: React.HTMLAttributes<HTMLSpanElement>) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[10.5px] font-semibold",
        className,
      )}
      {...props}
    />
  );
}

/** Severity pill: tint + ring of the severity hue with theme ink for the text.
 *  A solid severity fill cannot carry one readable ink across all four hues in
 *  either theme; the severity WORD inside the pill is the primary signal. */
export function SeverityBadge({ severity }: { severity: string }) {
  const v = sevVar(severity);
  return (
    <Badge
      style={{
        backgroundColor: `color-mix(in srgb, ${v} 22%, transparent)`,
        borderColor: v,
      }}
    >
      {severity.toUpperCase()}
    </Badge>
  );
}
