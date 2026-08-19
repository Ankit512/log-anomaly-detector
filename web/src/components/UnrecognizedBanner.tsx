import { Card, CardContent } from "@/components/ui/card";
import type { ConsoleState } from "@/lib/api";

/** The honest banner shown when a run parsed nothing — an unrecognized format
 *  or empty input. Zeros then mean "nothing was read", NOT "nothing was
 *  found", so this must never be mistaken for an all-clear. Shared by the
 *  Alerts page and the Overview so the copy stays identical on both surfaces. */
export function UnrecognizedBanner({ state }: { state: Pick<ConsoleState,
  "unrecognized" | "emptyInput" | "linesParsed" | "linesUnparsed"> }) {
  if (!state.unrecognized && !state.emptyInput) return null;

  const total = (state.linesParsed ?? 0) + (state.linesUnparsed ?? 0);

  return (
    <Card className="border-dashed" style={{ borderColor: "var(--sev-medium)" }}>
      <CardContent className="p-4 text-[12.5px] text-muted-foreground">
        {state.emptyInput ? (
          <>
            <b className="text-foreground">Empty input — nothing to analyze.</b>{" "}
            No lines were read, so this run is <b>not</b> evidence the log is clean.
          </>
        ) : (
          <>
            <b className="text-foreground">Log format not recognized — 0 lines parsed
            {total > 0 ? ` (0 of ${total.toLocaleString()} lines recognized)` : ""}.</b>{" "}
            No rule evaluated a single line, so this run is <b>not</b> evidence the log is clean.
          </>
        )}
      </CardContent>
    </Card>
  );
}
