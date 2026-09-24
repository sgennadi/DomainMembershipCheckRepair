using System;
using System.Collections.Generic;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class AdvancedDiagnosticsResult
    {
        internal DiagnosticsSnapshot Snapshot;
        internal NetSetupAnalysis NetSetup;
        internal DnsDiagnosticsResult Dns;
        internal DcMatrixResult DcMatrix;
        internal List<EventTimelineEntry> Events;
        internal CyberArkDiagnosticsResult CyberArk;
        internal AdComputerAccountInfo Account;
        internal List<string> RecoveryPlan;
    }

    internal static class AdvancedDiagnosticsService
    {
        internal static AdvancedDiagnosticsResult Analyze(
            string domain,
            string preferredDc,
            string computerName,
            string user,
            string password)
        {
            AdvancedDiagnosticsResult result = new AdvancedDiagnosticsResult();
            result.Snapshot = DiagnosticsService.Capture(domain, preferredDc);

            string effectiveDomain = !String.IsNullOrWhiteSpace(result.Snapshot.TargetDomain)
                ? result.Snapshot.TargetDomain
                : domain;
            string discoveredDc = result.Snapshot.DiscoveredDc;

            result.NetSetup = NetSetupLogAnalyzer.Analyze(DiagnosticsService.NetSetupLogPath);
            result.Dns = DnsDiagnosticsService.Analyze(effectiveDomain);
            result.DcMatrix = DcMatrixService.Analyze(
                effectiveDomain,
                discoveredDc,
                String.IsNullOrWhiteSpace(computerName) ? Environment.MachineName : computerName,
                user,
                password);
            result.Events = EventTimelineService.Collect(48);
            result.CyberArk = CyberArkDiagnosticsService.Analyze();

            if (!String.IsNullOrWhiteSpace(user) && password != null)
            {
                result.Account = AdDirectoryService.FindComputerAccount(
                    String.IsNullOrWhiteSpace(computerName) ? Environment.MachineName : computerName,
                    user,
                    password,
                    effectiveDomain,
                    preferredDc,
                    null);
            }

            result.RecoveryPlan = RecoveryPlanService.Build(
                result.Snapshot,
                result.NetSetup,
                result.Dns,
                result.DcMatrix,
                result.Account);

            return result;
        }

        internal static string ToText(AdvancedDiagnosticsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine(DiagnosticsService.ToText(r.Snapshot));
            sb.AppendLine();
            sb.AppendLine(NetSetupLogAnalyzer.ToText(r.NetSetup));
            sb.AppendLine();
            sb.AppendLine(DnsDiagnosticsService.ToText(r.Dns));
            sb.AppendLine();
            sb.AppendLine(DcMatrixService.ToText(r.DcMatrix));
            sb.AppendLine();
            sb.AppendLine(EventTimelineService.ToText(r.Events));
            sb.AppendLine();
            sb.AppendLine(CyberArkDiagnosticsService.ToText(r.CyberArk));

            if (r.Account != null && r.Account.LookupSucceeded)
            {
                sb.AppendLine();
                sb.AppendLine("AD Computer Account Analyzer");
                sb.AppendLine("============================");
                sb.AppendLine("Exists:          " + (r.Account.Exists ? "Yes" : "No"));
                if (r.Account.Exists)
                {
                    sb.AppendLine("DN:              " + First(r.Account.DistinguishedName, "(not returned)"));
                    sb.AppendLine("Owner:           " + First(r.Account.Owner, "(not returned)"));
                    sb.AppendLine("Enabled:         " + (r.Account.Enabled.HasValue ? (r.Account.Enabled.Value ? "Yes" : "No") : "(unknown)"));
                    sb.AppendLine("pwdLastSet:      " + First(r.Account.PwdLastSet, "(not returned)"));
                    sb.AppendLine("Last logon:      " + First(r.Account.LastLogonTimestamp, "(not returned)"));
                    sb.AppendLine("whenChanged:     " + First(r.Account.WhenChanged, "(not returned)"));
                    sb.AppendLine("objectGUID:      " + First(r.Account.ObjectGuid, "(not returned)"));
                    sb.AppendLine("Canonical name:  " + First(r.Account.CanonicalName, "(not returned)"));
                    sb.AppendLine("SPN count:       " + r.Account.ServicePrincipalNameCount);
                    sb.AppendLine("Child objects:   " + r.Account.ChildObjectCount);
                    sb.AppendLine("EncryptionTypes: " + (r.Account.SupportedEncryptionTypes.HasValue ? r.Account.SupportedEncryptionTypes.Value.ToString() : "(unknown)"));
                    if (!String.IsNullOrWhiteSpace(r.Account.ServicePrincipalNames))
                        sb.AppendLine("SPNs:            " + r.Account.ServicePrincipalNames);
                }
            }

            sb.AppendLine();
            sb.AppendLine(RecoveryPlanService.ToText(r.RecoveryPlan));
            return sb.ToString();
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
