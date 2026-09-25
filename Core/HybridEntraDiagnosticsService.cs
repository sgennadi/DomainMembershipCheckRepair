using System;
using System.Collections.Generic;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class HybridEntraDiagnosticsResult
    {
        internal bool DsregcmdAvailable;
        internal string AzureAdJoined = String.Empty;
        internal string EnterpriseJoined = String.Empty;
        internal string DomainJoined = String.Empty;
        internal string DomainName = String.Empty;
        internal string DeviceId = String.Empty;
        internal string TenantId = String.Empty;
        internal string TenantName = String.Empty;
        internal string DeviceAuthStatus = String.Empty;
        internal string AzureAdPrt = String.Empty;
        internal string WorkplaceJoined = String.Empty;
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class HybridEntraDiagnosticsService
    {
        internal static HybridEntraDiagnosticsResult Analyze()
        {
            HybridEntraDiagnosticsResult r = new HybridEntraDiagnosticsResult();
            CommandResult command = ProcessRunner.Run("dsregcmd.exe", "/status", 15000);

            if (!String.IsNullOrWhiteSpace(command.Error))
            {
                r.Findings.Add("dsregcmd.exe could not be started: " + command.Error);
                return r;
            }

            r.DsregcmdAvailable = command.Started;
            if (command.TimedOut)
            {
                r.Findings.Add("dsregcmd /status timed out.");
                return r;
            }

            Dictionary<string, string> values = Parse(command.StandardOutput);
            r.AzureAdJoined = Get(values, "AzureAdJoined");
            r.EnterpriseJoined = Get(values, "EnterpriseJoined");
            r.DomainJoined = Get(values, "DomainJoined");
            r.DomainName = Get(values, "DomainName");
            r.DeviceId = Get(values, "DeviceId");
            r.TenantId = Get(values, "TenantId");
            r.TenantName = Get(values, "TenantName");
            r.DeviceAuthStatus = Get(values, "DeviceAuthStatus");
            r.AzureAdPrt = Get(values, "AzureAdPrt");
            r.WorkplaceJoined = Get(values, "WorkplaceJoined");

            bool domainJoined = IsYes(r.DomainJoined);
            bool azureJoined = IsYes(r.AzureAdJoined);

            if (domainJoined && !azureJoined)
            {
                r.Findings.Add(
                    "CHECK: Windows reports DomainJoined=YES but AzureAdJoined is not YES. " +
                    "If this device is expected to be Microsoft Entra hybrid joined, continue hybrid-join troubleshooting after AD trust is healthy.");
            }

            if (azureJoined &&
                !String.IsNullOrWhiteSpace(r.DeviceAuthStatus) &&
                !r.DeviceAuthStatus.Equals("SUCCESS", StringComparison.OrdinalIgnoreCase))
            {
                r.Findings.Add(
                    "HIGH: AzureAdJoined=YES but DeviceAuthStatus is '" + r.DeviceAuthStatus +
                    "'. The device object/authentication state in Microsoft Entra should be checked.");
            }

            if (domainJoined &&
                !String.IsNullOrWhiteSpace(r.AzureAdPrt) &&
                !IsYes(r.AzureAdPrt))
            {
                r.Findings.Add(
                    "INFO: AzureAdPrt is not YES for the current interactive logon context. " +
                    "PRT state is user/session-specific and should be evaluated separately from machine domain trust.");
            }

            return r;
        }

        internal static string ToText(HybridEntraDiagnosticsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Hybrid Microsoft Entra diagnostics");
            sb.AppendLine("==================================");
            sb.AppendLine("dsregcmd available: " + (r.DsregcmdAvailable ? "Yes" : "No"));
            sb.AppendLine("DomainJoined:       " + First(r.DomainJoined, "(not returned)"));
            sb.AppendLine("DomainName:         " + First(r.DomainName, "(not returned)"));
            sb.AppendLine("AzureAdJoined:      " + First(r.AzureAdJoined, "(not returned)"));
            sb.AppendLine("EnterpriseJoined:   " + First(r.EnterpriseJoined, "(not returned)"));
            sb.AppendLine("WorkplaceJoined:    " + First(r.WorkplaceJoined, "(not returned)"));
            sb.AppendLine("DeviceId:           " + First(r.DeviceId, "(not returned)"));
            sb.AppendLine("TenantId:           " + First(r.TenantId, "(not returned)"));
            sb.AppendLine("TenantName:         " + First(r.TenantName, "(not returned)"));
            sb.AppendLine("DeviceAuthStatus:   " + First(r.DeviceAuthStatus, "(not returned)"));
            sb.AppendLine("AzureAdPrt:         " + First(r.AzureAdPrt, "(not returned)"));

            if (r.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Findings:");
                foreach (string finding in r.Findings)
                    sb.AppendLine("- " + finding);
            }

            return sb.ToString();
        }

        private static Dictionary<string, string> Parse(string text)
        {
            Dictionary<string, string> values =
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            string[] lines = (text ?? String.Empty)
                .Split(new string[] { "\r\n", "\n" }, StringSplitOptions.None);

            foreach (string raw in lines)
            {
                int separator = raw.IndexOf(':');
                if (separator <= 0)
                    continue;

                string key = raw.Substring(0, separator).Trim();
                string value = raw.Substring(separator + 1).Trim();

                if (key.Length > 0 && !values.ContainsKey(key))
                    values[key] = value;
            }

            return values;
        }

        private static string Get(Dictionary<string, string> values, string key)
        {
            string value;
            return values.TryGetValue(key, out value) ? value : String.Empty;
        }

        private static bool IsYes(string value)
        {
            return String.Equals(value, "YES", StringComparison.OrdinalIgnoreCase);
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
