import { useEffect, useRef, type ReactNode } from "react";
import { X } from "lucide-react";

/** A minimal accessible modal dialog, hand-rolled to match the app's existing
 *  shadcn-style components (which use only @radix-ui/react-slot — no
 *  react-dialog dep). Backdrop click and Escape close it; focus moves in on
 *  open; role="dialog" + aria-modal for assistive tech. */
export function Dialog({ open, onClose, title, children }:
  { open: boolean; onClose: () => void; title: string; children: ReactNode }) {
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", onKey);
    // Move focus into the dialog so keyboard users land inside it.
    panelRef.current?.focus();
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-start justify-center bg-black/40 p-4 pt-[12vh]"
      onMouseDown={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        ref={panelRef}
        role="dialog" aria-modal="true" aria-label={title} tabIndex={-1}
        className="w-full max-w-[440px] rounded-lg bg-card p-4 shadow-[0_16px_48px_-12px_rgba(26,32,51,0.4)] outline-none"
      >
        <div className="mb-3 flex items-center gap-2">
          <h2 className="text-[15px] font-semibold">{title}</h2>
          <button
            onClick={onClose} aria-label="Close dialog"
            className="ml-auto inline-flex h-6 w-6 items-center justify-center rounded-md text-muted-foreground hover:bg-background"
          >
            <X className="h-[15px] w-[15px]" aria-hidden />
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
