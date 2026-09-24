using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class DiagnosticsSnapshot
    {
        internal DateTime GeneratedAt;
        internal string ComputerName;
        internal string RuntimeSummary;
        internal string PhysicalDnsDomain;
        internal bool PendingRename;
        internal string PendingComputerName;
        internal int MembershipApiStatus;
        internal NetJoinStatus JoinStatus;
        internal string JoinedDomain;
        internal bool SecureChannelApplicable;
        internal bool SecureChannelHealthy;
        internal int SecureChannelStatus;
        internal string TrustedDc;
        internal string TargetDomain;
        internal string PreferredDirectoryServer;
        internal bool DiscoveryAttempted;
        internal bool DiscoverySucceeded;
        internal int DiscoveryStatus;
        internal string DiscoveredDnsDomain;
        internal string DiscoveredDc;
        internal string ForestName;
        internal bool NetSetupLogPresent;
        internal DateTime? NetSetupLogModified;
        internal HealthDiagnosticsSnapshot Health;
        internal int ResultCode;
    }

    internal static class DiagnosticsService
    {
        internal const string ApplicationLogPath = @"C:\Windows\Logs\DomainMembershipRepair.log";
        internal const string NetSetupLogPath = @"C:\Windows\Debug\NetSetup.log";

        internal static DiagnosticsSnapshot Capture(string explicitTargetDomain, string preferredDirectoryServer)
        {
            DiagnosticsSnapshot snapshot = new DiagnosticsSnapshot();
            snapshot.GeneratedAt = DateTime.Now;
            snapshot.ComputerName = Environment.MachineName;
            snapshot.RuntimeSummary = BuildInfo.RuntimeSummary;
            snapshot.PhysicalDnsDomain = NativeMethods.GetPhysicalDnsDomain();
            snapshot.PreferredDirectoryServer = DomainValidation.NormalizeDirectoryServer(preferredDirectoryServer);

            string pending;
            snapshot.PendingRename = HasPendingRename(out pending);
            snapshot.PendingComputerName = pending;

            JoinInformation join = NativeMethods.GetJoinInformation();
            snapshot.MembershipApiStatus = join.StatusCode;
            snapshot.JoinStatus = join.Status;
            snapshot.JoinedDomain = join.Name ?? String.Empty;

            if (join.StatusCode != NativeMethods.NERR_Success)
            {
                snapshot.ResultCode = 1;
            }
            else if (join.Status == NetJoinStatus.NetSetupDomainName && !String.IsNullOrWhiteSpace(join.Name))
            {
                snapshot.SecureChannelApplicable = true;
                TrustCheckResult trust = NativeMethods.VerifySecureChannel(join.Name);
                snapshot.SecureChannelHealthy = trust.Healthy;
                snapshot.SecureChannelStatus = trust.StatusCode;
                snapshot.TrustedDc = trust.TrustedDc;
                snapshot.ResultCode = trust.Healthy ? 0 : 2;
            }
            else
            {
                snapshot.SecureChannelApplicable = false;
                snapshot.ResultCode = 4;
            }

            snapshot.TargetDomain = ResolveTargetDomain(explicitTargetDomain, join);
            if (!String.IsNullOrWhiteSpace(snapshot.TargetDomain))
            {
                snapshot.DiscoveryAttempted = true;
                DomainDiscoveryResult discovery = NativeMethods.DiscoverDomain(snapshot.TargetDomain, true);
                snapshot.DiscoverySucceeded = discovery.Success;
                snapshot.DiscoveryStatus = discovery.StatusCode;
                snapshot.DiscoveredDnsDomain = discovery.DnsDomainName;
                snapshot.DiscoveredDc = discovery.DomainControllerName;
                snapshot.ForestName = discovery.ForestName;
                if (discovery.Success && !String.IsNullOrWhiteSpace(discovery.DnsDomainName))
                    snapshot.TargetDomain = discovery.DnsDomainName;
            }

            snapshot.Health = HealthDiagnosticsService.Capture(
                snapshot.TargetDomain,
                snapshot.DiscoveredDc,
                snapshot.SecureChannelApplicable && !snapshot.SecureChannelHealthy,
                snapshot.PendingRename,
                snapshot.DiscoveryAttempted,
                snapshot.DiscoverySucceeded);

            snapshot.NetSetupLogPresent = File.Exists(NetSetupLogPath);
            if (snapshot.NetSetupLogPresent)
            {
                try
                {
                    snapshot.NetSetupLogModified = File.GetLastWriteTime(NetSetupLogPath);
                }
                catch
                {
                }
            }

            return snapshot;
        }

        internal static string ToText(DiagnosticsSnapshot s)
        {
            StringBuilder report = new StringBuilder();
            report.AppendLine("Domain Membership Check & Repair diagnostics");
            report.AppendLine("Version:           " + BuildInfo.Version);
            report.AppendLine("Generated:         " + s.GeneratedAt.ToString("yyyy-MM-dd HH:mm:ss"));
            report.AppendLine();
            report.AppendLine("Computer:          " + s.ComputerName);
            report.AppendLine("Architecture:      " + s.RuntimeSummary);
            report.AppendLine("Physical DNS:      " + FirstNonEmpty(s.PhysicalDnsDomain, "(none)"));
            report.AppendLine("Pending rename:    " + (s.PendingRename ? FirstNonEmpty(s.PendingComputerName, "Yes") : "No"));

            if (s.MembershipApiStatus != NativeMethods.NERR_Success)
            {
                report.AppendLine("Membership:        Unknown - " + NativeMethods.FormatError(s.MembershipApiStatus));
            }
            else if (s.JoinStatus == NetJoinStatus.NetSetupDomainName && !String.IsNullOrWhiteSpace(s.JoinedDomain))
            {
                report.AppendLine("Membership:        Domain - " + s.JoinedDomain);
                report.AppendLine("Secure channel:    " + (s.SecureChannelHealthy ? "OK" : "BROKEN - " + NativeMethods.FormatError(s.SecureChannelStatus)));
                report.AppendLine("Trusted DC:        " + FirstNonEmpty(s.TrustedDc, "(not returned)"));
            }
            else
            {
                report.AppendLine("Membership:        Not joined (" + s.JoinStatus + ")");
                report.AppendLine("Secure channel:    Not applicable");
            }

            report.AppendLine("Target domain:     " + FirstNonEmpty(s.TargetDomain, "(not detected)"));
            report.AppendLine("Preferred DC:      " + FirstNonEmpty(s.PreferredDirectoryServer, "Auto (LDAP operations)"));

            if (s.DiscoveryAttempted)
            {
                report.AppendLine("DC discovery:      " + (s.DiscoverySucceeded ? "OK" : NativeMethods.FormatError(s.DiscoveryStatus)));
                if (s.DiscoverySucceeded)
                {
                    report.AppendLine("DNS domain:        " + FirstNonEmpty(s.DiscoveredDnsDomain, "(not returned)"));
                    report.AppendLine("Domain controller: " + FirstNonEmpty(s.DiscoveredDc, "(not returned)"));
                    report.AppendLine("Forest:            " + FirstNonEmpty(s.ForestName, "(not returned)"));
                }
            }

            if (s.Health != null)
            {
                report.AppendLine();
                report.AppendLine("Root-cause diagnostics");
                report.AppendLine("----------------------");
                report.AppendLine("Windows version:     " + FirstNonEmpty(s.Health.OsDisplayVersion, "(unknown)") +
                    (String.IsNullOrWhiteSpace(s.Health.OsBuild) ? String.Empty : " / build " + s.Health.OsBuild));
                report.AppendLine("MII policy:          " + HealthDiagnosticsService.FormatMiiMode(s.Health.MachineIdentityIsolationPolicy));
                report.AppendLine("MII LSA:             " + HealthDiagnosticsService.FormatMiiMode(s.Health.MachineIdentityIsolationLsa));
                report.AppendLine("MII effective:       " + s.Health.MachineIdentityIsolationMode);
                report.AppendLine("Credential Guard:    " + FormatNullableBool(s.Health.CredentialGuardRunning, "Running", "Not running"));
                report.AppendLine("VBS status:          " + (s.Health.VbsStatus.HasValue ? s.Health.VbsStatus.Value.ToString() : "(unknown)"));
                report.AppendLine("Netlogon service:    " + FormatNullableBool(s.Health.NetlogonRunning, "Running", "Not running"));
                report.AppendLine("Windows Time:        " + FormatNullableBool(s.Health.WindowsTimeRunning, "Running", "Not running"));
                report.AppendLine("DNS Client:          " + FormatNullableBool(s.Health.DnsClientRunning, "Running", "Not running"));
                report.AppendLine("DNS servers:         " + FirstNonEmpty(s.Health.DnsServers, "(none detected)"));

                if (s.Health.DomainFunctionalLevelAttempted)
                {
                    report.AppendLine("Domain functional:   " +
                        (s.Health.DomainFunctionalLevel.HasValue
                            ? s.Health.DomainFunctionalLevelName + " (" + s.Health.DomainFunctionalLevel.Value + ")"
                            : "(not detected)"));
                }

                report.AppendLine("DC time skew:        " + FirstNonEmpty(s.Health.DcTimeStatus, "(not checked)"));
                report.AppendLine("DC TCP checks:       " + FirstNonEmpty(s.Health.DcPortStatus, "(not checked)"));

                if (s.Health.RootCauseHints.Count > 0)
                {
                    report.AppendLine();
                    report.AppendLine("Possible root causes / checks:");
                    foreach (string hint in s.Health.RootCauseHints)
                        report.AppendLine("- " + hint);
                }
            }

            report.AppendLine("NetSetup.log:       " + (s.NetSetupLogPresent
                ? "Present" + (s.NetSetupLogModified.HasValue ? "; modified " + s.NetSetupLogModified.Value.ToString("yyyy-MM-dd HH:mm:ss") : String.Empty)
                : "Not present"));
            report.AppendLine();
            report.AppendLine("Result code:       " + s.ResultCode);
            report.AppendLine("No passwords or domain credentials are included in this report.");
            return report.ToString();
        }

        internal static string ToJson(DiagnosticsSnapshot s)
        {
            StringBuilder json = new StringBuilder();
            json.Append("{");
            AppendJson(json, "version", BuildInfo.Version, true);
            AppendJson(json, "generatedAt", s.GeneratedAt.ToString("o"), true);
            AppendJson(json, "computer", s.ComputerName, true);
            AppendJson(json, "architecture", BuildInfo.TargetArchitecture, true);
            AppendJson(json, "runtime", s.RuntimeSummary, true);
            AppendJson(json, "physicalDnsDomain", s.PhysicalDnsDomain, true);
            AppendJson(json, "pendingRename", s.PendingRename, true);
            AppendJson(json, "pendingComputerName", s.PendingComputerName, true);
            AppendJson(json, "membershipApiStatus", s.MembershipApiStatus, true);
            AppendJson(json, "joinStatus", s.JoinStatus.ToString(), true);
            AppendJson(json, "joinedDomain", s.JoinedDomain, true);
            AppendJson(json, "secureChannelApplicable", s.SecureChannelApplicable, true);
            AppendJson(json, "secureChannelHealthy", s.SecureChannelHealthy, true);
            AppendJson(json, "secureChannelStatus", s.SecureChannelStatus, true);
            AppendJson(json, "trustedDc", s.TrustedDc, true);
            AppendJson(json, "targetDomain", s.TargetDomain, true);
            AppendJson(json, "preferredDirectoryServer", s.PreferredDirectoryServer, true);
            AppendJson(json, "discoveryAttempted", s.DiscoveryAttempted, true);
            AppendJson(json, "discoverySucceeded", s.DiscoverySucceeded, true);
            AppendJson(json, "discoveryStatus", s.DiscoveryStatus, true);
            AppendJson(json, "discoveredDnsDomain", s.DiscoveredDnsDomain, true);
            AppendJson(json, "discoveredDc", s.DiscoveredDc, true);
            AppendJson(json, "forest", s.ForestName, true);
            if (s.Health != null)
            {
                AppendJson(json, "machineIdentityIsolationLsa", s.Health.MachineIdentityIsolationLsa.HasValue ? s.Health.MachineIdentityIsolationLsa.Value.ToString() : null, true);
                AppendJson(json, "machineIdentityIsolationPolicy", s.Health.MachineIdentityIsolationPolicy.HasValue ? s.Health.MachineIdentityIsolationPolicy.Value.ToString() : null, true);
                AppendJson(json, "machineIdentityIsolationMode", s.Health.MachineIdentityIsolationMode, true);
                AppendJson(json, "credentialGuardRunning", s.Health.CredentialGuardRunning.HasValue ? (s.Health.CredentialGuardRunning.Value ? "true" : "false") : null, true);
                AppendJson(json, "vbsStatus", s.Health.VbsStatus.HasValue ? s.Health.VbsStatus.Value.ToString() : null, true);
                AppendJson(json, "netlogonRunning", s.Health.NetlogonRunning.HasValue ? (s.Health.NetlogonRunning.Value ? "true" : "false") : null, true);
                AppendJson(json, "windowsTimeRunning", s.Health.WindowsTimeRunning.HasValue ? (s.Health.WindowsTimeRunning.Value ? "true" : "false") : null, true);
                AppendJson(json, "dnsClientRunning", s.Health.DnsClientRunning.HasValue ? (s.Health.DnsClientRunning.Value ? "true" : "false") : null, true);
                AppendJson(json, "dnsServers", s.Health.DnsServers, true);
                AppendJson(json, "domainFunctionalLevel", s.Health.DomainFunctionalLevel.HasValue ? s.Health.DomainFunctionalLevel.Value.ToString() : null, true);
                AppendJson(json, "domainFunctionalLevelName", s.Health.DomainFunctionalLevelName, true);
                AppendJson(json, "dcTimeSkewSeconds", s.Health.DcTimeSkewSeconds.HasValue ? s.Health.DcTimeSkewSeconds.Value.ToString("0.0", System.Globalization.CultureInfo.InvariantCulture) : null, true);
                AppendJson(json, "dcTcpChecks", s.Health.DcPortStatus, true);
                AppendJson(json, "rootCauseHints", String.Join(" | ", s.Health.RootCauseHints.ToArray()), true);
            }

            AppendJson(json, "netSetupLogPresent", s.NetSetupLogPresent, true);
            AppendJson(json, "netSetupLogModified", s.NetSetupLogModified.HasValue ? s.NetSetupLogModified.Value.ToString("o") : null, true);
            AppendJson(json, "resultCode", s.ResultCode, false);
            json.Append("}");
            return json.ToString();
        }

        internal static string ExportPackage(DiagnosticsSnapshot snapshot, string outputPath, bool includeApplicationLog)
        {
            if (snapshot == null)
                throw new ArgumentNullException("snapshot");

            string path = outputPath;
            if (String.IsNullOrWhiteSpace(path))
                path = GetDefaultArchivePath();

            path = Path.GetFullPath(path);
            string outputDirectory = Path.GetDirectoryName(path);
            if (!String.IsNullOrWhiteSpace(outputDirectory) && !Directory.Exists(outputDirectory))
                Directory.CreateDirectory(outputDirectory);

            string tempRoot = Path.Combine(Path.GetTempPath(), "DomainMembershipCheckRepair", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempRoot);

            try
            {
                File.WriteAllText(Path.Combine(tempRoot, "diagnostics.txt"), ToText(snapshot), new UTF8Encoding(false));
                File.WriteAllText(Path.Combine(tempRoot, "diagnostics.json"), ToJson(snapshot), new UTF8Encoding(false));

                if (snapshot.NetSetupLogPresent && File.Exists(NetSetupLogPath))
                    CopyWithoutThrow(NetSetupLogPath, Path.Combine(tempRoot, "NetSetup.log"));

                if (includeApplicationLog && File.Exists(ApplicationLogPath))
                    CopyWithoutThrow(ApplicationLogPath, Path.Combine(tempRoot, "DomainMembershipRepair.log"));

                File.WriteAllText(
                    Path.Combine(tempRoot, "README.txt"),
                    "This diagnostic package was generated by DomainMembershipCheckRepair.\r\n" +
                    "It does not intentionally include entered usernames or passwords.\r\n" +
                    "Review logs before sharing them because Windows or third-party components may record environment-specific information.\r\n",
                    new UTF8Encoding(false));

                if (File.Exists(path))
                    File.Delete(path);

                ZipFile.CreateFromDirectory(tempRoot, path, CompressionLevel.Optimal, false);
                return path;
            }
            finally
            {
                try
                {
                    if (Directory.Exists(tempRoot))
                        Directory.Delete(tempRoot, true);
                }
                catch
                {
                }
            }
        }

        internal static string GetDefaultArchivePath()
        {
            string fileName = "DomainMembershipDiagnostics-" + Environment.MachineName + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".zip";
            return Path.Combine(Environment.CurrentDirectory, fileName);
        }

        internal static bool HasPendingRename(out string pendingName)
        {
            pendingName = null;
            try
            {
                string active;
                string pending;
                using (RegistryKey activeKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"))
                using (RegistryKey pendingKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"))
                {
                    active = activeKey == null ? null : Convert.ToString(activeKey.GetValue("ComputerName"));
                    pending = pendingKey == null ? null : Convert.ToString(pendingKey.GetValue("ComputerName"));
                }

                if (!String.IsNullOrWhiteSpace(active) && !String.IsNullOrWhiteSpace(pending) &&
                    !String.Equals(active, pending, StringComparison.OrdinalIgnoreCase))
                {
                    pendingName = pending;
                    return true;
                }
            }
            catch
            {
            }
            return false;
        }

        private static string ResolveTargetDomain(string explicitTargetDomain, JoinInformation join)
        {
            string candidate = (explicitTargetDomain ?? String.Empty).Trim();
            if (!String.IsNullOrWhiteSpace(candidate))
                return candidate;

            if (join != null && join.StatusCode == NativeMethods.NERR_Success &&
                join.Status == NetJoinStatus.NetSetupDomainName && !String.IsNullOrWhiteSpace(join.Name))
                return join.Name;

            candidate = NativeMethods.GetPhysicalDnsDomain();
            if (!String.IsNullOrWhiteSpace(candidate))
                return candidate;

            candidate = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            return candidate ?? String.Empty;
        }

        private static void AppendJson(StringBuilder json, string name, string value, bool comma)
        {
            json.Append('"').Append(JsonEscape(name)).Append("\":");
            if (value == null)
                json.Append("null");
            else
                json.Append('"').Append(JsonEscape(value)).Append('"');
            if (comma) json.Append(',');
        }

        private static void AppendJson(StringBuilder json, string name, bool value, bool comma)
        {
            json.Append('"').Append(JsonEscape(name)).Append("\":").Append(value ? "true" : "false");
            if (comma) json.Append(',');
        }

        private static void AppendJson(StringBuilder json, string name, int value, bool comma)
        {
            json.Append('"').Append(JsonEscape(name)).Append("\":").Append(value);
            if (comma) json.Append(',');
        }

        internal static string JsonEscape(string value)
        {
            if (value == null)
                return String.Empty;

            StringBuilder sb = new StringBuilder(value.Length + 16);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 32)
                            sb.Append("\\u").Append(((int)c).ToString("x4"));
                        else
                            sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }

        private static void CopyWithoutThrow(string source, string destination)
        {
            try
            {
                File.Copy(source, destination, true);
            }
            catch (Exception ex)
            {
                File.WriteAllText(destination + ".copy-error.txt", ex.Message, new UTF8Encoding(false));
            }
        }

        private static string FormatNullableBool(bool? value, string trueText, string falseText)
        {
            if (!value.HasValue)
                return "(unknown)";
            return value.Value ? trueText : falseText;
        }

        private static string FirstNonEmpty(string first, string second)
        {
            return !String.IsNullOrWhiteSpace(first) ? first : (second ?? String.Empty);
        }
    }
}
