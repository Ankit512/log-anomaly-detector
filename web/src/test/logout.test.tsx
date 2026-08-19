import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { useUi } from "@/store/ui";
import { renderApp, mockFetch, OVERVIEW, METRICS } from "./helpers";

describe("Logout page (honest, no fake auth)", () => {
  beforeEach(() => mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": METRICS }));

  it("states there is no session and does not fake an auth flow", async () => {
    renderApp(<App />, { route: "/logout" });
    expect(await screen.findByRole("heading", { name: /sign out/i })).toBeInTheDocument();
    expect(screen.getByText(/no account, no login, and no server session/i)).toBeInTheDocument();
    // No password/credential inputs — it is not an auth screen.
    expect(screen.queryByLabelText(/password/i)).not.toBeInTheDocument();
  });

  it("clears local UI state (theme back to light) on demand", async () => {
    useUi.setState({ theme: "dark", search: "leftover" });
    renderApp(<App />, { route: "/logout" });

    await userEvent.click(await screen.findByRole("button", { name: /clear local ui state/i }));

    expect(useUi.getState().theme).toBe("light");
    expect(useUi.getState().search).toBe("");
    expect(screen.getByText(/there was no session to end/i)).toBeInTheDocument();
    expect(document.documentElement.classList.contains("dark")).toBe(false);
  });
});
