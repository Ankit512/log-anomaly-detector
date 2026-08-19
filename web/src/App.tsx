import { Routes, Route } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { Overview } from "@/pages/Overview";
import { Alerts } from "@/pages/Alerts";
import { Cases } from "@/pages/Cases";
import { Settings } from "@/pages/Settings";
import { Logout } from "@/pages/Logout";
import { Placeholder } from "@/pages/Placeholder";

export default function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route index element={<Overview />} />
        <Route path="alerts" element={<Alerts />} />
        <Route path="incidents" element={<Placeholder title="Incidents" />} />
        <Route path="threat-intel" element={<Placeholder title="Threat Intel" />} />
        <Route path="assets" element={<Placeholder title="Assets" />} />
        <Route path="reports" element={<Placeholder title="Reports" />} />
        <Route path="cases" element={<Cases />} />
        <Route path="settings" element={<Settings />} />
        <Route path="logout" element={<Logout />} />
        <Route path="*" element={<Placeholder title="Not found" />} />
      </Route>
    </Routes>
  );
}
