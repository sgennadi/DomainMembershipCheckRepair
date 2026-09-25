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
        internal SiteSubnetDiagnosticsResult SiteSubnet;
        internal ProtocolDiagnosticsResult Protocols;
        internal List<EventTimelineEntry> Events;
        internal CyberArkDiagnosticsResult CyberArk;
        internal AdComputerAccountInfo Account;
        internal HardeningDiagnosticsResult Hardening;
        internal JoinPermissionsResult JoinPermissions;
        internal HybridEntraDiagnosticsResult HybridEntra;
        internal PolicySourceDiagnosticsResult PolicySources;
        internal SelfTestResult SelfTest;
        internal MachinePasswordAnalysis MachinePassword;
        internal List<RootCauseFinding> RootCauses;
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
            result.SiteSubnet = SiteSubnetDiagnosticsService.Analyze(
                effectiveDomain,
                discoveredDc,
                user,
                password);

            result.Protocols = ProtocolDiagnosticsService.Analyze(
                effectiveDomain,
                discoveredDc,
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

            result.Hardening = HardeningDiagnosticsService.Analyze(result.Account);

            result.JoinPermissions = JoinPermissionsAnalyzer.Analyze(
                effectiveDomain,
                discoveredDc,
                String.IsNullOrWhiteSpace(computerName) ? Environment.MachineName : computerName,
                user,
                password,
                result.Account);

            result.HybridEntra = HybridEntraDiagnosticsService.Analyze();
            result.PolicySources = PolicySourceAnalyzer.Analyze();
            result.SelfTest = SelfTestService.Run(effectiveDomain, discoveredDc);

            result.MachinePassword = MachinePasswordAnalyzer.Analyze(
                result.Account,
                result.Events,
                result.Snapshot.SecureChannelApplicable && !result.Snapshot.SecureChannelHealthy);

            result.RootCauses = RootCauseEngine.Analyze(
                result.Snapshot,
                result.NetSetup,
                result.Dns,
                result.DcMatrix,
                result.SiteSubnet,
                result.Protocols,
                result.Account,
                result.MachinePassword,
                result.Hardening,
                result.JoinPermissions,
                result.HybridEntra,
                result.PolicySources);

            result.RecoveryPlan = RecoveryPlanService.Build(
                result.Snapshot,
                result.NetSetup,
                result.Dns,
                result.DcMatrix,
                result.SiteSubnet,
                result.Protocols,
                result.Hardening,
                result.JoinPermissions,
                result.HybridEntra,
                result.PolicySources,
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
            sb.AppendLine(SiteSubnetDiagnosticsService.ToText(r.SiteSubnet));
            sb.AppendLine();
            sb.AppendLine(ProtocolDiagnosticsService.ToText(r.Protocols));
            sb.AppendLine();
            sb.AppendLine(EventTimelineService.ToText(r.Events));
            sb.AppendLine();
            sb.AppendLine(CyberArkDiagnosticsService.ToText(r.CyberArk));
            sb.AppendLine();
            sb.AppendLine(HardeningDiagnosticsService.ToText(r.Hardening));
            sb.AppendLine();
            sb.AppendLine(JoinPermissionsAnalyzer.ToText(r.JoinPermissions));
            sb.AppendLine();
            sb.AppendLine(HybridEntraDiagnosticsService.ToText(r.HybridEntra));
            sb.AppendLine();
            sb.AppendLine(PolicySourceAnalyzer.ToText(r.PolicySources));
            sb.AppendLine();
            sb.AppendLine(SelfTestService.ToText(r.SelfTest));
            sb.AppendLine();
            sb.AppendLine(MachinePasswordAnalyzer.ToText(r.MachinePassword));
            sb.AppendLine();
            sb.AppendLine(RootCauseEngine.ToText(r.RootCauses));

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
