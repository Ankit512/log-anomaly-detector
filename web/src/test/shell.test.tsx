import { screen, within } from "@testing-library/react";
import App from "@/App";
import { NAV } from "@/components/layout/AppShell";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("uniform v6 app shell", () => {
  beforeEach(() => mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS }));

  it("renders every nav item, with unbuilt sections honestly titled", async () => {
    renderApp(<App />);
    for (const item of ["Overview", "Alerts", "Incidents", "Threat Intel",
                        "Assets", "Reports", "Cases", "Settings", "Logout"]) {
      expect(screen.getByText(item)).toBeInTheDocument();
    }
    // Unbuilt nav items carry an honest "not built yet" title; derive the
    // expected count from NAV so this stays correct as pages are built.
    const nav = screen.getByRole("navigation", { name: "Main" });
    const unbuilt = NAV.filter((n) => !n.ready).length;
    expect(within(nav).getAllByTitle(/not built yet/i).length).toBe(unbuilt);
    // Logout is an honest local action (a link to /logout), not a fake auth flow.
    expect(screen.getByText("Logout").closest("a")).toHaveAttribute("href", "/logout");
  });

  it("renders the v6 header actions on every page", async () => {
    renderApp(<App />);
    expect(screen.getByRole("heading", { name: "SOC Dashboard" })).toBeInTheDocument();
    expect(screen.getByText("Upload Logs")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /refresh/i })).toBeInTheDocument();
    // Filters exists but is honestly disabled until filtering is built.
    expect(screen.getByRole("button", { name: /filters/i })).toBeDisabled();
    expect(screen.getByRole("button", { name: /switch to dark mode/i })).toBeInTheDocument();
  });

  it("an unknown route renders the honest placeholder inside the same shell", async () => {
    // Use the catch-all (a genuinely unknown path) so this holds regardless of
    // which section pages have been built.
    renderApp(<App />, { route: "/no-such-page" });
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByText(/coming in a later phase/i)).toBeInTheDocument();
    expect(screen.getByText(/rather than invented data/i)).toBeInTheDocument();
  });
});
