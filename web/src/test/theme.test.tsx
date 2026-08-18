import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useUi, applyThemeClass } from "@/store/ui";
import { renderApp, mockFetch } from "./helpers";

describe("theme toggle", () => {
  beforeEach(() => {
    mockFetch({});
    localStorage.clear();
    useUi.setState({ theme: "light" });
    applyThemeClass("light");
  });

  it("light is the default", () => {
    renderApp(<ThemeToggle />);
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(screen.getByRole("button", { name: /switch to dark mode/i })).toBeInTheDocument();
  });

  it("toggling applies the dark class and persists the choice", async () => {
    renderApp(<ThemeToggle />);
    await userEvent.click(screen.getByRole("button", { name: /switch to dark mode/i }));
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    expect(localStorage.getItem("itsoc-theme")).toBe("dark");

    await userEvent.click(screen.getByRole("button", { name: /switch to light mode/i }));
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(localStorage.getItem("itsoc-theme")).toBe("light");
  });
});
