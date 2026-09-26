using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal static class AdvancedSupportBundleService
    {
        internal static string Export(
            AdvancedDiagnosticsResult advanced,
            string outputPath,
            bool includeApplicationLog)
        {
            return Export(
                advanced,
                outputPath,
                includeApplicationLog,
                CancellationToken.None,
                null);
        }

        internal static string Export(
            AdvancedDiagnosticsResult advanced,
            string outputPath,
            bool includeApplicationLog,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (advanced == null)
                throw new ArgumentNullException("advanced");

            string path = outputPath;
            if (String.IsNullOrWhiteSpace(path))
                path = Path.Combine(
                    Environment.CurrentDirectory,
                    "DomainMembershipSupport-" + Environment.MachineName + "-" +
                    DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".zip");

            path = Path.GetFullPath(path);
            string folder = Path.GetDirectoryName(path);
            if (!String.IsNullOrWhiteSpace(folder) && !Directory.Exists(folder))
                Directory.CreateDirectory(folder);

            string temp = Path.Combine(Path.GetTempPath(), "DomainMembershipCheckRepair", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);

            try
            {
                Report(progress, "Support Bundle: writing diagnostic reports");
                cancellationToken.ThrowIfCancellationRequested();
                Write(Path.Combine(temp, "advanced-diagnostics.txt"), AdvancedDiagnosticsService.ToText(advanced));
                Write(Path.Combine(temp, "advanced-diagnostics.json"), JsonReportSerializer.Serialize(advanced));
                Write(Path.Combine(temp, "diagnostics.json"), DiagnosticsService.ToJson(advanced.Snapshot));
                Write(Path.Combine(temp, "netsetup-analysis.txt"), NetSetupLogAnalyzer.ToText(advanced.NetSetup));
                Write(Path.Combine(temp, "dns-diagnostics.txt"), DnsDiagnosticsService.ToText(advanced.Dns));
                Write(Path.Combine(temp, "dc-matrix.txt"), DcMatrixService.ToText(advanced.DcMatrix));
                Write(Path.Combine(temp, "site-subnet.txt"), SiteSubnetDiagnosticsService.ToText(advanced.SiteSubnet));
                Write(Path.Combine(temp, "protocol-diagnostics.txt"), ProtocolDiagnosticsService.ToText(advanced.Protocols));
                Write(Path.Combine(temp, "ldap-compatibility.txt"), LdapCompatibilityAnalyzer.ToText(advanced.LdapCompatibility));
                Write(Path.Combine(temp, "rpc-endpoints.txt"), RpcEndpointMapperAnalyzer.ToText(advanced.RpcEndpoints));
                Write(Path.Combine(temp, "kerberos-deep.txt"), KerberosDeepAnalyzer.ToText(advanced.KerberosDeep));
                Write(Path.Combine(temp, "event-timeline.txt"), EventTimelineService.ToText(advanced.Events));
                Write(Path.Combine(temp, "cyberark-epm.txt"), CyberArkDiagnosticsService.ToText(advanced.CyberArk));
                Write(Path.Combine(temp, "hardening.txt"), HardeningDiagnosticsService.ToText(advanced.Hardening));
                Write(Path.Combine(temp, "join-permissions.txt"), JoinPermissionsAnalyzer.ToText(advanced.JoinPermissions));
                Write(Path.Combine(temp, "hybrid-entra.txt"), HybridEntraDiagnosticsService.ToText(advanced.HybridEntra));
                Write(Path.Combine(temp, "policy-sources.txt"), PolicySourceAnalyzer.ToText(advanced.PolicySources));
                Write(Path.Combine(temp, "replication-metadata.txt"), ReplicationMetadataService.ToText(advanced.ReplicationMetadata));
                Write(Path.Combine(temp, "replication-timeline.txt"), ReplicationTimelineAnalyzer.ToText(advanced.ReplicationTimeline));
                Write(Path.Combine(temp, "identity-consistency.txt"), IdentityConsistencyAnalyzer.ToText(advanced.IdentityConsistency));
                Write(Path.Combine(temp, "spn-collisions.txt"), SpnCollisionAnalyzer.ToText(advanced.SpnCollisions));
                Write(Path.Combine(temp, "smb-kerberos.txt"), SmbKerberosAuthAnalyzer.ToText(advanced.SmbKerberos));
                Write(Path.Combine(temp, "self-test.txt"), SelfTestService.ToText(advanced.SelfTest));
                Write(Path.Combine(temp, "machine-password.txt"), MachinePasswordAnalyzer.ToText(advanced.MachinePassword));
                Write(Path.Combine(temp, "root-causes.txt"), RootCauseEngine.ToText(advanced.RootCauses));
                Write(Path.Combine(temp, "next-safe-action.txt"), SmartNextActionService.ToText(advanced.NextAction));
                Write(Path.Combine(temp, "recovery-plan.txt"), RecoveryPlanService.ToText(advanced.RecoveryPlan));

                CollectCommand(temp, "ipconfig-all.txt", "ipconfig.exe", "/all", cancellationToken, progress);
                CollectCommand(temp, "route-print.txt", "route.exe", "print", cancellationToken, progress);
                CollectCommand(temp, "w32tm-status.txt", "w32tm.exe", "/query /status", cancellationToken, progress);
                CollectCommand(temp, "w32tm-source.txt", "w32tm.exe", "/query /source", cancellationToken, progress);
                CollectCommand(temp, "dsregcmd-status.txt", "dsregcmd.exe", "/status", cancellationToken, progress);
                CollectCommand(temp, "gpresult-computer.txt", "gpresult.exe", "/scope computer /z", cancellationToken, progress);

                string domain = advanced.Snapshot == null ? String.Empty : advanced.Snapshot.TargetDomain;
                if (!String.IsNullOrWhiteSpace(domain))
                {
                    CollectCommand(temp, "nltest-dsgetdc.txt", "nltest.exe", "/dsgetdc:" + domain, cancellationToken, progress);
                    CollectCommand(temp, "nltest-dclist.txt", "nltest.exe", "/dclist:" + domain, cancellationToken, progress);
                    CollectCommand(temp, "nltest-sc-query.txt", "nltest.exe", "/sc_query:" + domain, cancellationToken, progress);
                }

                if (File.Exists(DiagnosticsService.NetSetupLogPath))
                    Copy(DiagnosticsService.NetSetupLogPath, Path.Combine(temp, "NetSetup.log"));
                if (includeApplicationLog && File.Exists(DiagnosticsService.ApplicationLogPath))
                    Copy(DiagnosticsService.ApplicationLogPath, Path.Combine(temp, "DomainMembershipRepair.log"));

                string latestTransaction = TransactionJournalService.GetLatestJournalPath();
                if (!String.IsNullOrWhiteSpace(latestTransaction) && File.Exists(latestTransaction))
                    Copy(latestTransaction, Path.Combine(temp, "latest-transaction.json"));

                string latestHistory = DiagnosticHistoryService.GetLatestHistoryPath();
                if (!String.IsNullOrWhiteSpace(latestHistory) && File.Exists(latestHistory))
                    Copy(latestHistory, Path.Combine(temp, "latest-diagnostic-history.json"));

                string latestRecoveryPackage = AdRecycleBinRecoveryService.GetLatestRecoveryPackagePath();
                if (!String.IsNullOrWhiteSpace(latestRecoveryPackage) && File.Exists(latestRecoveryPackage))
                    Copy(latestRecoveryPackage, Path.Combine(temp, "latest-ad-recovery-package.json"));

                Write(
                    Path.Combine(temp, "README.txt"),
                    "Advanced support bundle generated by DomainMembershipCheckRepair.\r\n" +
                    "Entered passwords are never written by the application.\r\n" +
                    "Windows logs and command output can contain environment-specific hostnames, domains, addresses, usernames, or other operational metadata. Review before sharing.\r\n");

                cancellationToken.ThrowIfCancellationRequested();
                Report(progress, "Support Bundle: creating ZIP archive");
                if (File.Exists(path))
                    File.Delete(path);
                ZipFile.CreateFromDirectory(temp, path, CompressionLevel.Optimal, false);
                cancellationToken.ThrowIfCancellationRequested();
                return path;
            }
            finally
            {
                try { Directory.Delete(temp, true); } catch { }
            }
        }

        private static void CollectCommand(
            string folder,
            string name,
            string exe,
            string args,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Report(progress, "Support Bundle: " + name);
            CommandResult result = ProcessRunner.Run(exe, args, 10000, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            string output = result.CombinedOutput;

            if (result.TimedOut)
                output += Environment.NewLine + "[Command timed out]";
            if (!String.IsNullOrWhiteSpace(result.Error))
                output += Environment.NewLine + "[Runner error] " + result.Error;
            if (result.Started && !result.TimedOut)
                output += Environment.NewLine + "[Exit code] " + result.ExitCode;

            Write(Path.Combine(folder, name), output);
        }

        private static void Report(Action<string> progress, string text)
        {
            if (progress != null)
                progress(text);
        }

        private static void Copy(string source, string destination)
        {
            try { File.Copy(source, destination, true); }
            catch (Exception ex) { Write(destination + ".copy-error.txt", ex.Message); }
        }

        private static void Write(string path, string text)
        {
            File.WriteAllText(path, text ?? String.Empty, new UTF8Encoding(false));
        }
    }
}
