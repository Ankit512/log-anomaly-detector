import { Routes, Route } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { Overview } from "@/pages/Overview";
import { Alerts } from "@/pages/Alerts";
import { Incidents } from "@/pages/Incidents";
import { ThreatIntel } from "@/pages/ThreatIntel";
import { Assets } from "@/pages/Assets";
import { Reports } from "@/pages/Reports";
import { Placeholder } from "@/pages/Placeholder";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="incidents" element={<Incidents />} />
        <Route path="threat-intel" element={<ThreatIntel />} />
        <Route path="assets" element={<Assets />} />
        <Route path="reports" element={<Reports />} />
        <Route path="cases" element={<Placeholder title="Cases" />} />
        <Route path="settings" element={<Placeholder title="Settings" />} />
        <Route path="*" element={<Placeholder title="Not found" />} />
      </Route>
    </Routes>
  );
}
