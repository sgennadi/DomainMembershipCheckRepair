using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ServiceProcess;
using System.Text;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class CyberArkDiagnosticsResult
    {
        internal bool Detected;
        internal readonly List<string> Products = new List<string>();
        internal readonly List<string> Services = new List<string>();
        internal readonly List<string> Processes = new List<string>();
        internal string Privilege = String.Empty;
        internal readonly List<string> Notes = new List<string>();
    }

    internal static class CyberArkDiagnosticsService
    {
        internal static CyberArkDiagnosticsResult Analyze()
        {
            CyberArkDiagnosticsResult result = new CyberArkDiagnosticsResult();
            result.Privilege = ElevationHelper.IsAdministrator() ? "Elevated" : "Standard";

            ScanUninstall(RegistryView.Registry64, result);
            ScanUninstall(RegistryView.Registry32, result);

            try
            {
                foreach (ServiceController service in ServiceController.GetServices())
                {
                    string combined = (service.ServiceName + " " + service.DisplayName).ToLowerInvariant();
                    if (combined.Contains("cyberark") || combined.Contains("endpoint privilege") ||
                        combined.Contains("epm") || combined.Contains("viewfinity"))
                    {
                        result.Services.Add(service.ServiceName + " | " + service.DisplayName + " | " + service.Status);
                        result.Detected = true;
                    }
                    service.Dispose();
                }
            }
            catch { }

            try
            {
                foreach (Process p in Process.GetProcesses())
                {
                    string name = String.Empty;
                    try { name = p.ProcessName; } catch { }
                    string lower = (name ?? String.Empty).ToLowerInvariant();
                    if (lower.Contains("cyberark") || lower.Contains("vfagent") || lower.Contains("viewfinity"))
                    {
                        result.Processes.Add(name + " (PID " + p.Id + ")");
                        result.Detected = true;
                    }
                    p.Dispose();
                }
            }
            catch { }

            if (!result.Detected)
                result.Notes.Add("No CyberArk/EPM product, service, or process was identified by generic local discovery. Product-specific naming may differ.");
            if (!ElevationHelper.IsAdministrator())
                result.Notes.Add("Current process is Standard. Mutating actions will request elevation through Windows runas, which EPM can broker.");

            return result;
        }

        internal static string ToText(CyberArkDiagnosticsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("CyberArk / EPM health");
            sb.AppendLine("=====================");
            sb.AppendLine("Detected:  " + (r.Detected ? "Yes" : "No/Unknown"));
            sb.AppendLine("Privilege: " + r.Privilege);
            if (r.Products.Count > 0)
            {
                sb.AppendLine("Products:");
                foreach (string v in r.Products) sb.AppendLine("- " + v);
            }
            if (r.Services.Count > 0)
            {
                sb.AppendLine("Services:");
                foreach (string v in r.Services) sb.AppendLine("- " + v);
            }
            if (r.Processes.Count > 0)
            {
                sb.AppendLine("Processes:");
                foreach (string v in r.Processes) sb.AppendLine("- " + v);
            }
            foreach (string note in r.Notes) sb.AppendLine("NOTE: " + note);
            return sb.ToString();
        }

        private static void ScanUninstall(RegistryView view, CyberArkDiagnosticsResult result)
        {
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view))
                using (RegistryKey uninstall = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
                {
                    if (uninstall == null) return;
                    foreach (string sub in uninstall.GetSubKeyNames())
                    {
                        using (RegistryKey key = uninstall.OpenSubKey(sub))
                        {
                            if (key == null) continue;
                            string name = Convert.ToString(key.GetValue("DisplayName")) ?? String.Empty;
                            if (name.IndexOf("CyberArk", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                name.IndexOf("Endpoint Privilege", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                name.IndexOf("Viewfinity", StringComparison.OrdinalIgnoreCase) >= 0)
                            {
                                string version = Convert.ToString(key.GetValue("DisplayVersion")) ?? String.Empty;
                                string item = name + (version.Length > 0 ? " " + version : String.Empty);
                                if (!result.Products.Contains(item)) result.Products.Add(item);
                                result.Detected = true;
                            }
                        }
                    }
                }
            }
            catch { }
        }
    }
}
