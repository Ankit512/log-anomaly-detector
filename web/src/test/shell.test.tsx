import { screen } from "@testing-library/react";
import App from "@/App";
import { renderApp, mockFetch, OVERVIEW } from "./helpers";

describe("uniform app shell", () => {
  beforeEach(() => mockFetch({ "/api/overview": OVERVIEW }));

  it("renders every nav item, with unbuilt sections marked", async () => {
    renderApp(<App />);
    for (const item of ["Overview", "Alerts", "Incidents", "Threat Intel",
                        "Assets", "Reports", "Cases", "Settings", "Logout"]) {
      expect(screen.getByText(item)).toBeInTheDocument();
    }
    // 7 unbuilt items carry the honest "soon" tag (6 nav + logout).
    expect(screen.getAllByText("soon").length).toBe(7);
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
  });

  it("renders the topbar with title, refresh and the theme toggle", async () => {
    renderApp(<App />);
    expect(screen.getByRole("heading", { name: "SOC Dashboard" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /refresh/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /switch to dark mode/i })).toBeInTheDocument();
  });

  it("placeholder routes render inside the same shell, honestly", async () => {
    renderApp(<App />, { route: "/incidents" });
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByText(/coming in a later phase/i)).toBeInTheDocument();
    expect(screen.getByText(/rather than invented data/i)).toBeInTheDocument();
  });
});
