import { Routes, Route } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { Overview } from "@/pages/Overview";
import { Alerts } from "@/pages/Alerts";
import { Incidents } from "@/pages/Incidents";
import { ThreatIntel } from "@/pages/ThreatIntel";
import { Assets } from "@/pages/Assets";
import { Reports } from "@/pages/Reports";
import { Cases } from "@/pages/Cases";
import { Settings } from "@/pages/Settings";
import { Collectors } from "@/pages/Collectors";
import { Logout } from "@/pages/Logout";
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
        <Route path="cases" element={<Cases />} />
        <Route path="settings" element={<Settings />} />
        <Route path="collectors" element={<Collectors />} />
        <Route path="logout" element={<Logout />} />
        <Route path="*" element={<Placeholder title="Not found" />} />
      </Route>
    </Routes>
  );
}
