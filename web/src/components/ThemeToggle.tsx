import { Moon, Sun } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useUi } from "@/store/ui";

/** Flips the `dark` class on <html>; light is the default, the choice is
 *  persisted, and index.html applies it pre-paint on the next visit. */
export function ThemeToggle() {
  const theme = useUi((s) => s.theme);
  const toggleTheme = useUi((s) => s.toggleTheme);
  const dark = theme === "dark";
  return (
    <Button
      variant="outline"
      size="sm"
      onClick={toggleTheme}
      aria-label={dark ? "Switch to light mode" : "Switch to dark mode"}
      title="Theme is saved for your next visit"
    >
      {dark ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
      {dark ? "Light" : "Dark"}
    </Button>
  );
}
