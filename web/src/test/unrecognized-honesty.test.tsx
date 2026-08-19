import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import App from "@/App";
import { rawFileUrl, isBlobPageUrl } from "@/lib/rawUrl";
import { useJobs } from "@/store/jobs";
import { renderApp, mockFetch, OVERVIEW, consoleState } from "./helpers";

const ZERO_OVERVIEW = {
  ...OVERVIEW,
  kpis: { total: 0, critical: 0, high: 0, medium: 0, low: 0,
          deltas: { total: null, critical: null, high: null, medium: null, low: null } },
  severityDonut: [
    { bucket: "CRITICAL", count: 0, pct: 0 }, { bucket: "HIGH", count: 0, pct: 0 },
    { bucket: "MEDIUM", count: 0, pct: 0 }, { bucket: "LOW", count: 0, pct: 0 },
  ],
  alertsOverTime: { bins: [] }, mitreTactics: [], latestAlerts: [],
};

describe("FIX A — Overview honest banner on an unrecognized run", () => {
  it("shows the 'format not recognized' banner above the zero KPIs, not a false all-clear", async () => {
    mockFetch({
      "/api/overview": ZERO_OVERVIEW,
      "/api/metrics": { openIncidents: 0, mttdSeconds: null, mttdBasis: 0, mttrSeconds: null, mttrBasis: 0, assetsAtRisk: 0, usersAtRisk: 0, dataSources: 1 },
      "/console_state.json": consoleState([], { unrecognized: true, linesParsed: 0, linesUnparsed: 598 }),
    });
    renderApp(<App />);

    expect(await screen.findByText(/Log format not recognized/)).toBeInTheDocument();
    // The honest count and the "not clean" wording are both present.
    expect(screen.getByText(/0 of 598 lines recognized/)).toBeInTheDocument();
    expect(screen.getByText(/evidence the log is clean/)).toBeInTheDocument();
    // And the zeros are explained as "nothing parsed", not "nothing found".
    expect(screen.getByText(/nothing was parsed/i)).toBeInTheDocument();
  });

  it("does NOT show the banner for a normal run", async () => {
    mockFetch({
      "/api/overview": OVERVIEW,
      "/api/metrics": { openIncidents: 0, mttdSeconds: null, mttdBasis: 0, mttrSeconds: null, mttrBasis: 0, assetsAtRisk: 0, usersAtRisk: 0, dataSources: 1 },
      "/console_state.json": consoleState([], { unrecognized: false, linesParsed: 2000, linesUnparsed: 0 }),
    });
    renderApp(<App />);
    await screen.findByText("Total Alerts");
    expect(screen.queryByText(/Log format not recognized/)).not.toBeInTheDocument();
  });
});

describe("FIX B — notifier says 'couldn't parse', not 'analyzed — 0 findings'", () => {
  beforeEach(() => useJobs.getState()._reset());

  it("reports an unsupported-format run honestly on completion", async () => {
    let progressN = 0;
    mockFetch({
      "/api/overview": ZERO_OVERVIEW, "/api/metrics": { openIncidents: 0, mttdSeconds: null, mttdBasis: 0, mttrSeconds: null, mttrBasis: 0, assetsAtRisk: 0, usersAtRisk: 0, dataSources: 1 },
      "/api/runs": { current: null, runs: [] },
      "/api/analyze": { status: "running" },
      "/api/progress": () => (progressN++ === 0
        ? { status: "running", phase: "rules", done: 0, total: 0 }
        : { status: "done", phase: "done", findings: 0 }),
      "/console_state.json": consoleState([], { unrecognized: true, linesParsed: 0, linesUnparsed: 598 }),
    });
    renderApp(<App />);
    await screen.findByText(/Log format not recognized/);

    const file = new File(["<html>not a log</html>"], "page.html", { type: "text/html" });
    await userEvent.click(screen.getByRole("button", { name: /upload logs/i }));
    await userEvent.upload(screen.getByTestId("ingest-file"), file);

    expect(await screen.findByText(/Couldn't parse page\.html — 0 of 598 lines recognized/,
      undefined, { timeout: 6000 })).toBeInTheDocument();
    // Never the misleading clean-run phrasing.
    expect(screen.queryByText(/analyzed — 0 finding/)).not.toBeInTheDocument();
  }, 10000);
});

describe("FIX C — github/gitlab blob URL -> raw file URL", () => {
  it("converts a github blob URL to raw.githubusercontent.com", () => {
    expect(rawFileUrl("https://github.com/logpai/loghub/blob/master/Linux/Linux_2k.log"))
      .toBe("https://raw.githubusercontent.com/logpai/loghub/master/Linux/Linux_2k.log");
    expect(isBlobPageUrl("https://github.com/o/r/blob/main/a.log")).toBe(true);
  });

  it("converts a gitlab blob URL to /-/raw/ and leaves raw/other URLs unchanged", () => {
    expect(rawFileUrl("https://gitlab.com/g/p/-/blob/main/app.log"))
      .toBe("https://gitlab.com/g/p/-/raw/main/app.log");
    const raw = "https://raw.githubusercontent.com/o/r/main/a.log";
    expect(rawFileUrl(raw)).toBe(raw);
    expect(isBlobPageUrl(raw)).toBe(false);
    expect(rawFileUrl("not a url")).toBe("not a url");
  });

  it("shows an inline hint in the link field when a blob URL is pasted", async () => {
    mockFetch({ "/api/overview": OVERVIEW, "/api/metrics": { openIncidents: 0, mttdSeconds: null, mttdBasis: 0, mttrSeconds: null, mttrBasis: 0, assetsAtRisk: 0, usersAtRisk: 0, dataSources: 1 }, "/console_state.json": consoleState([]) });
    renderApp(<App />);
    await screen.findByText("Total Alerts");
    await userEvent.click(screen.getByRole("button", { name: /upload logs/i }));
    await userEvent.click(screen.getByRole("button", { name: /attach a link/i }));
    await userEvent.type(screen.getByLabelText("Log file URL"),
      "https://github.com/o/r/blob/main/app.log");
    expect(await screen.findByText(/web-page link, not the raw file/)).toBeInTheDocument();
    expect(screen.getByText("https://raw.githubusercontent.com/o/r/main/app.log")).toBeInTheDocument();
  });
});
