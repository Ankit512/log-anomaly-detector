import { screen, within } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("uniform v6 app shell", () => {
  beforeEach(() => mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS }));

  it("renders every nav item, with unbuilt sections honestly titled", async () => {
    renderApp(<App />);
    for (const item of ["Overview", "Alerts", "Incidents", "Threat Intel",
                        "Assets", "Reports", "Cases", "Settings", "Logout"]) {
      expect(screen.getByText(item)).toBeInTheDocument();
    }
    // v6 drops the "soon" pills: unbuilt nav items carry a title instead, and
    // Logout is a disabled button with its own honest title.
    const nav = screen.getByRole("navigation", { name: "Main" });
    // Cases + Settings remain unbuilt (Incidents/Threat Intel/Assets/Reports
    // are now real pages); those two still carry the honest "not built yet" title.
    expect(within(nav).getAllByTitle(/not built yet/i).length).toBe(2);
    expect(screen.getByText("Logout").closest("button")).toBeDisabled();
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

  it("placeholder routes render inside the same shell, honestly", async () => {
    // Cases is still a placeholder (Incidents et al. are now built).
    renderApp(<App />, { route: "/cases" });
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByText(/coming in a later phase/i)).toBeInTheDocument();
    expect(screen.getByText(/rather than invented data/i)).toBeInTheDocument();
  });
});
