/** The severity status palette, referenced through theme tokens so light and
 *  dark both apply without re-render. Charts must use these in `style`, never
 *  in SVG presentation attributes (var() is invalid there and renders black).
 *  Color is never the sole signal — always pair it with the name or count. */
export const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;
export type Severity = (typeof SEV_ORDER)[number];

export const SEV_VAR: Record<string, string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

export const sevVar = (sev: string) => SEV_VAR[sev.toUpperCase()] ?? "hsl(var(--muted-foreground))";
