import { Card, CardContent } from "@/components/ui/card";

/** The uniform placeholder for sections whose backend does not exist yet.
 *  Honest by design: it names the phase instead of showing invented data. */
export function Placeholder({ title }: { title: string }) {
  return (
    <Card className="border-dashed">
      <CardContent className="p-8 text-center">
        <div className="text-[15px] font-semibold">{title}</div>
        <p className="mx-auto mt-1 max-w-md text-[12.5px] text-muted-foreground">
          Coming in a later phase. This section needs backend subsystems that do
          not exist yet, so nothing is shown here rather than invented data.
        </p>
      </CardContent>
    </Card>
  );
}
