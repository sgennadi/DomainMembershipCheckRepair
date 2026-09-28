using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

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
        internal LdapCompatibilityResult LdapCompatibility;
        internal RpcEndpointMapperResult RpcEndpoints;
        internal KerberosDeepResult KerberosDeep;
        internal List<EventTimelineEntry> Events;
        internal CyberArkDiagnosticsResult CyberArk;
        internal AdComputerAccountInfo Account;
        internal HardeningDiagnosticsResult Hardening;
        internal JoinPermissionsResult JoinPermissions;
        internal HybridEntraDiagnosticsResult HybridEntra;
        internal PolicySourceDiagnosticsResult PolicySources;
        internal ReplicationMetadataResult ReplicationMetadata;
        internal ReplicationTimelineResult ReplicationTimeline;
        internal IdentityConsistencyResult IdentityConsistency;
        internal SpnCollisionResult SpnCollisions;
        internal SmbKerberosAuthResult SmbKerberos;
        internal SelfTestResult SelfTest;
        internal MachinePasswordAnalysis MachinePassword;
        internal List<RootCauseFinding> RootCauses;
        internal List<string> RecoveryPlan;
        internal SmartNextActionResult NextAction;
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
            return Analyze(
                domain,
                preferredDc,
                computerName,
                user,
                password,
                CancellationToken.None,
                null);
        }

        internal static AdvancedDiagnosticsResult Analyze(
            string domain,
            string preferredDc,
            string computerName,
            string user,
            string password,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            AdvancedDiagnosticsResult result = new AdvancedDiagnosticsResult();

            Step(cancellationToken, progress, "Capturing Windows and domain state");
            result.Snapshot = DiagnosticsService.Capture(domain, preferredDc);

            string effectiveDomain = !String.IsNullOrWhiteSpace(result.Snapshot.TargetDomain)
                ? result.Snapshot.TargetDomain
                : domain;
            string discoveredDc = result.Snapshot.DiscoveredDc;
            string effectiveDc = DomainValidation.SelectDirectoryServer(
                preferredDc,
                discoveredDc);
            string effectiveComputerName = String.IsNullOrWhiteSpace(computerName)
                ? Environment.MachineName
                : computerName;

            Step(cancellationToken, progress, "Analyzing NetSetup.log");
            result.NetSetup = NetSetupLogAnalyzer.Analyze(DiagnosticsService.NetSetupLogPath);

            Step(cancellationToken, progress, "Checking DNS and DC Locator");
            result.Dns = DnsDiagnosticsService.Analyze(effectiveDomain);

            Step(cancellationToken, progress, "Comparing domain controllers and SPN state");
            result.DcMatrix = DcMatrixService.Analyze(
                effectiveDomain,
                effectiveDc,
                effectiveComputerName,
                user,
                password,
                cancellationToken,
                progress);

            Step(cancellationToken, progress, "Checking AD site and subnet");
            result.SiteSubnet = SiteSubnetDiagnosticsService.Analyze(
                effectiveDomain,
                effectiveDc,
                user,
                password);

            Step(cancellationToken, progress, "Running LDAP, Kerberos, RPC and SMB protocol tests");
            result.Protocols = ProtocolDiagnosticsService.Analyze(
                effectiveDomain,
                effectiveDc,
                user,
                password,
                cancellationToken,
                progress);

            Step(cancellationToken, progress, "Testing LDAP signing, LDAPS and certificate compatibility");
            result.LdapCompatibility = LdapCompatibilityAnalyzer.Analyze(
                effectiveDomain,
                effectiveDc,
                user,
                password,
                cancellationToken,
                progress);

            Step(cancellationToken, progress, "Enumerating RPC Endpoint Mapper and dynamic ports");
            result.RpcEndpoints = RpcEndpointMapperAnalyzer.Analyze(
                effectiveDomain,
                effectiveDc,
                user,
                password,
                cancellationToken,
                progress);

            Step(cancellationToken, progress, "Inspecting Kerberos tickets, encryption and KDC binding");
            result.KerberosDeep = KerberosDeepAnalyzer.Analyze(
                effectiveDomain,
                effectiveDc,
                user,
                password,
                cancellationToken,
                progress);

            Step(cancellationToken, progress, "Collecting relevant Windows events");
            result.Events = EventTimelineService.Collect(48);

            Step(cancellationToken, progress, "Inspecting CyberArk / EPM state");
            result.CyberArk = CyberArkDiagnosticsService.Analyze();

            Step(cancellationToken, progress, "Reading the AD computer account");
            if (!String.IsNullOrWhiteSpace(effectiveDomain) || !String.IsNullOrWhiteSpace(effectiveDc))
            {
                result.Account = AdDirectoryService.FindComputerAccount(
                    effectiveComputerName,
                    user,
                    password,
                    effectiveDomain,
                    effectiveDc,
                    null);
            }

            Step(cancellationToken, progress, "Evaluating hardening policy");
            result.Hardening = HardeningDiagnosticsService.Analyze(result.Account);

            string objectDn = result.Account != null &&
                              result.Account.LookupSucceeded &&
                              result.Account.Exists
                ? result.Account.DistinguishedName
                : String.Empty;

            Step(cancellationToken, progress, "Reading AD replication metadata");
            result.ReplicationMetadata = ReplicationMetadataService.Analyze(
                effectiveDomain,
                effectiveDc,
                objectDn,
                user,
                password,
                cancellationToken);

            string expectedFqdn = result.Account != null && !String.IsNullOrWhiteSpace(result.Account.DnsHostName)
                ? result.Account.DnsHostName
                : (!String.IsNullOrWhiteSpace(result.Snapshot.PhysicalDnsDomain)
                    ? effectiveComputerName + "." + result.Snapshot.PhysicalDnsDomain
                    : (!String.IsNullOrWhiteSpace(effectiveDomain)
                        ? effectiveComputerName + "." + effectiveDomain
                        : String.Empty));

            Step(cancellationToken, progress, "Comparing replication timeline across domain controllers");
            result.ReplicationTimeline = ReplicationTimelineAnalyzer.Analyze(
                result.DcMatrix,
                objectDn,
                user,
                password,
                cancellationToken,
                progress);

            Step(cancellationToken, progress, "Checking computer identity consistency and stale objects");
            result.IdentityConsistency = IdentityConsistencyAnalyzer.Analyze(
                effectiveDomain,
                effectiveDc,
                effectiveComputerName,
                expectedFqdn,
                user,
                password,
                cancellationToken);

            Step(cancellationToken, progress, "Checking SPN collisions");
            result.SpnCollisions = SpnCollisionAnalyzer.Analyze(
                effectiveDomain,
                effectiveDc,
                effectiveComputerName,
                user,
                password,
                cancellationToken);

            Step(cancellationToken, progress, "Testing SMB / Kerberos authentication");
            result.SmbKerberos = SmbKerberosAuthAnalyzer.Analyze(
                effectiveDomain,
                effectiveDc,
                user,
                password,
                cancellationToken);

            Step(cancellationToken, progress, "Evaluating domain join permissions");
            result.JoinPermissions = JoinPermissionsAnalyzer.Analyze(
                effectiveDomain,
                effectiveDc,
                effectiveComputerName,
                user,
                password,
                result.Account);

            Step(cancellationToken, progress, "Inspecting Hybrid Microsoft Entra state");
            result.HybridEntra = HybridEntraDiagnosticsService.Analyze();

            Step(cancellationToken, progress, "Inspecting policy sources");
            result.PolicySources = PolicySourceAnalyzer.Analyze();

            Step(cancellationToken, progress, "Running application self-test");
            result.SelfTest = SelfTestService.Run(effectiveDomain, effectiveDc);

            Step(cancellationToken, progress, "Comparing machine-password evidence");
            result.MachinePassword = MachinePasswordAnalyzer.Analyze(
                result.Account,
                result.Events,
                result.Snapshot.SecureChannelApplicable && !result.Snapshot.SecureChannelHealthy);

            Step(cancellationToken, progress, "Prioritizing root causes");
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
                result.PolicySources,
                result.ReplicationMetadata,
                result.ReplicationTimeline,
                result.IdentityConsistency,
                result.LdapCompatibility,
                result.RpcEndpoints,
                result.KerberosDeep,
                result.SpnCollisions,
                result.SmbKerberos);

            Step(cancellationToken, progress, "Building recovery plan");
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
                result.ReplicationMetadata,
                result.ReplicationTimeline,
                result.IdentityConsistency,
                result.LdapCompatibility,
                result.RpcEndpoints,
                result.KerberosDeep,
                result.SpnCollisions,
                result.SmbKerberos,
                result.Account);

            Step(cancellationToken, progress, "Selecting the next safe action");
            result.NextAction = SmartNextActionService.Analyze(result);

            Step(cancellationToken, progress, "Advanced diagnostics completed");
            return result;
        }

        private static void Step(
            CancellationToken cancellationToken,
            Action<string> progress,
            string text)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (progress != null)
                progress(text);
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
            sb.AppendLine(LdapCompatibilityAnalyzer.ToText(r.LdapCompatibility));
            sb.AppendLine();
            sb.AppendLine(RpcEndpointMapperAnalyzer.ToText(r.RpcEndpoints));
            sb.AppendLine();
            sb.AppendLine(KerberosDeepAnalyzer.ToText(r.KerberosDeep));
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
            sb.AppendLine(ReplicationMetadataService.ToText(r.ReplicationMetadata));
            sb.AppendLine();
            sb.AppendLine(ReplicationTimelineAnalyzer.ToText(r.ReplicationTimeline));
            sb.AppendLine();
            sb.AppendLine(IdentityConsistencyAnalyzer.ToText(r.IdentityConsistency));
            sb.AppendLine();
            sb.AppendLine(SpnCollisionAnalyzer.ToText(r.SpnCollisions));
            sb.AppendLine();
            sb.AppendLine(SmbKerberosAuthAnalyzer.ToText(r.SmbKerberos));
            sb.AppendLine();
            sb.AppendLine(SelfTestService.ToText(r.SelfTest));
            sb.AppendLine();
            sb.AppendLine(MachinePasswordAnalyzer.ToText(r.MachinePassword));
            sb.AppendLine();
            sb.AppendLine(RootCauseEngine.ToText(r.RootCauses));
            sb.AppendLine();
            sb.AppendLine(SmartNextActionService.ToText(r.NextAction));

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
