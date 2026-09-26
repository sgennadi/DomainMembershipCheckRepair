using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class HealthDiagnosticsSnapshot
    {
        internal string OsDisplayVersion = String.Empty;
        internal string OsBuild = String.Empty;
        internal int? MachineIdentityIsolationLsa;
        internal int? MachineIdentityIsolationPolicy;
        internal int? MachineIdentityIsolationConfigured;
        internal string MachineIdentityIsolationMode = "Not configured";
        internal bool? CredentialGuardRunning;
        internal int? VbsStatus;
        internal bool? NetlogonRunning;
        internal bool? WindowsTimeRunning;
        internal bool? DnsClientRunning;
        internal string DnsServers = String.Empty;
        internal bool DomainFunctionalLevelAttempted;
        internal int? DomainFunctionalLevel;
        internal string DomainFunctionalLevelName = String.Empty;
        internal bool? MachineIdentityIsolationSupportedByDfl;
        internal double? DcTimeSkewSeconds;
        internal string DcTimeStatus = String.Empty;
        internal string DcPortStatus = String.Empty;
        internal readonly List<string> RootCauseHints = new List<string>();
    }

    internal static class HealthDiagnosticsService
    {
        private const string MiiLsaPath = @"SYSTEM\CurrentControlSet\Control\Lsa";
        private const string MiiPolicyPath = @"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard";
        private const string MiiValueName = "MachineIdentityIsolation";

        internal static HealthDiagnosticsSnapshot Capture(
            string targetDomain,
            string discoveredDc,
            bool secureChannelBroken,
            bool pendingRename,
            bool discoveryAttempted,
            bool discoverySucceeded)
        {
            HealthDiagnosticsSnapshot h = new HealthDiagnosticsSnapshot();

            ReadOsVersion(h);
            h.MachineIdentityIsolationLsa = ReadDword(MiiLsaPath, MiiValueName);
            h.MachineIdentityIsolationPolicy = ReadDword(MiiPolicyPath, MiiValueName);
            h.MachineIdentityIsolationConfigured =
                h.MachineIdentityIsolationPolicy.HasValue
                    ? h.MachineIdentityIsolationPolicy
                    : h.MachineIdentityIsolationLsa;
            h.MachineIdentityIsolationMode = FormatMiiMode(h.MachineIdentityIsolationConfigured);

            ReadCredentialGuard(h);
            h.NetlogonRunning = IsServiceRunning("Netlogon");
            h.WindowsTimeRunning = IsServiceRunning("W32Time");
            h.DnsClientRunning = IsServiceRunning("Dnscache");
            h.DnsServers = GetDnsServers();

            string dc = DomainValidation.NormalizeDirectoryServer(discoveredDc);
            if (!String.IsNullOrWhiteSpace(dc))
            {
                ReadDomainFunctionalLevel(h, dc);
                ReadDcTimeSkew(h, dc);
                h.DcPortStatus = ProbeDcPorts(dc);
            }

            if (h.MachineIdentityIsolationConfigured == 2)
            {
                if (h.DomainFunctionalLevel.HasValue && h.DomainFunctionalLevel.Value < 10)
                {
                    h.MachineIdentityIsolationSupportedByDfl = false;
                    h.RootCauseHints.Add(
                        "HIGH: Machine Identity Isolation enforcement is enabled, but the detected domain functional level is below Windows Server 2025. " +
                        "Microsoft documents this configuration as unsupported and it can break the machine secure channel.");
                }
                else if (h.DomainFunctionalLevel.HasValue && h.DomainFunctionalLevel.Value >= 10)
                {
                    h.MachineIdentityIsolationSupportedByDfl = true;
                }

                if (secureChannelBroken)
                {
                    h.RootCauseHints.Add(
                        "HIGH: Machine Identity Isolation enforcement is enabled while the secure channel is broken. " +
                        "This matches the Microsoft-known September 2026 failure pattern on affected Windows 11 systems.");
                }
            }
            else if (h.MachineIdentityIsolationConfigured == 1 && secureChannelBroken)
            {
                h.RootCauseHints.Add(
                    "MEDIUM: Machine Identity Isolation audit mode is enabled. Official guidance focuses on enforcement mode, " +
                    "but keep MII in scope while troubleshooting a broken secure channel.");
            }

            if (h.CredentialGuardRunning == true && h.MachineIdentityIsolationConfigured.HasValue &&
                h.MachineIdentityIsolationConfigured.Value > 0)
            {
                h.RootCauseHints.Add(
                    "INFO: Credential Guard is running and Machine Identity Isolation is configured; machine authentication can be routed through Credential Guard.");
            }

            if (h.NetlogonRunning == false)
                h.RootCauseHints.Add("HIGH: Netlogon service is not running.");

            if (h.WindowsTimeRunning == false)
                h.RootCauseHints.Add("MEDIUM: Windows Time service is not running; Kerberos authentication can fail when client/DC time is not synchronized.");

            if (h.DnsClientRunning == false)
                h.RootCauseHints.Add("MEDIUM: DNS Client service is not running.");

            if (String.IsNullOrWhiteSpace(h.DnsServers))
                h.RootCauseHints.Add("HIGH: No DNS server was detected on an active network interface.");

            if (h.DcTimeSkewSeconds.HasValue && Math.Abs(h.DcTimeSkewSeconds.Value) >= 300.0)
            {
                h.RootCauseHints.Add(
                    "HIGH: Client/DC clock skew is at least 5 minutes. Kerberos authentication commonly fails beyond the default tolerance.");
            }

            if (!String.IsNullOrWhiteSpace(h.DcPortStatus) && h.DcPortStatus.IndexOf("FAIL", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                h.RootCauseHints.Add(
                    "HIGH: One or more required TCP checks to the discovered DC failed. Check firewall/VPN/routing and the dynamic RPC range as well.");
            }

            if (discoveryAttempted && !discoverySucceeded)
                h.RootCauseHints.Add("HIGH: Domain controller discovery failed. DNS/DC locator configuration or network reachability should be checked first.");

            if (pendingRename)
                h.RootCauseHints.Add("MEDIUM: A computer rename is pending; reboot before Join/Rejoin.");

            if (secureChannelBroken && discoverySucceeded &&
                (String.IsNullOrWhiteSpace(h.DcPortStatus) || h.DcPortStatus.IndexOf("FAIL", StringComparison.OrdinalIgnoreCase) < 0))
            {
                h.RootCauseHints.Add(
                    "CHECK: DC discovery/connectivity look usable, so keep machine-password mismatch, disabled/stale AD computer account, account-reuse hardening, replication, and permissions in scope.");
            }

            if (!String.IsNullOrWhiteSpace(targetDomain) && String.IsNullOrWhiteSpace(dc))
                h.RootCauseHints.Add("CHECK: A target domain is known but no DC was selected for deeper health checks.");

            h.RootCauseHints.Add(
                "CHECK: If join/rejoin still fails, verify that the selected DC is writable (not RODC-only for the operation), " +
                "the operator has rights to create/reuse the computer account in the target OU, and machine-account quota/delegation is not blocking creation.");
            h.RootCauseHints.Add(
                "CHECK: Verify AD replication between DCs. A delete/recreate, password reset, rename, or account reuse can appear successful on one DC while another DC still has stale state.");
            h.RootCauseHints.Add(
                "CHECK: Review account-reuse hardening (KB5020276-era behavior), computer-object ownership, and explicit permissions when an existing computer account cannot be reused.");
            h.RootCauseHints.Add(
                "CHECK: On VPN or multi-NIC systems, verify split DNS, interface metrics, DNS suffixes, and that AD SRV records resolve to reachable internal DCs.");
            h.RootCauseHints.Add(
                "CHECK: Review Netlogon/Kerberos/NTLM hardening policies and security products if basic connectivity is healthy but authentication still fails.");

            return h;
        }

        internal static bool HasMachineIdentityIsolationEnabled(out int configuredValue)
        {
            int? policy = ReadDword(MiiPolicyPath, MiiValueName);
            int? lsa = ReadDword(MiiLsaPath, MiiValueName);
            int? value = policy.HasValue ? policy : lsa;
            configuredValue = value.HasValue ? value.Value : 0;
            return configuredValue > 0;
        }

        internal static bool DisableMachineIdentityIsolationLocally(out string details)
        {
            return DisableMachineIdentityIsolationLocally(null, out details);
        }

        internal static bool DisableMachineIdentityIsolationLocally(
            TransactionJournal journal,
            out string details)
        {
            List<string> changes = new List<string>();

            int? policyBefore = TransactionJournalService.ReadLocalMachineDword(MiiPolicyPath, MiiValueName);
            int? lsaBefore = TransactionJournalService.ReadLocalMachineDword(MiiLsaPath, MiiValueName);

            try
            {
                SetDwordIfPresent(MiiPolicyPath, MiiValueName, 0, changes);
                SetDwordIfPresent(MiiLsaPath, MiiValueName, 0, changes);

                int? policyAfter = TransactionJournalService.ReadLocalMachineDword(MiiPolicyPath, MiiValueName);
                int? lsaAfter = TransactionJournalService.ReadLocalMachineDword(MiiLsaPath, MiiValueName);

                if (policyBefore != policyAfter)
                {
                    TransactionJournalService.RecordRegistryDwordChange(
                        journal,
                        @"HKLM\" + MiiPolicyPath,
                        MiiValueName,
                        policyBefore,
                        policyAfter,
                        true);
                }

                if (lsaBefore != lsaAfter)
                {
                    TransactionJournalService.RecordRegistryDwordChange(
                        journal,
                        @"HKLM\" + MiiLsaPath,
                        MiiValueName,
                        lsaBefore,
                        lsaAfter,
                        true);
                }

                if (changes.Count == 0)
                {
                    details = "Machine Identity Isolation registry values were not present.";
                    return true;
                }

                details =
                    "Set MachineIdentityIsolation=0 in: " + String.Join("; ", changes.ToArray()) +
                    ". A restart is required. If this setting is managed by Group Policy or Intune, change the central policy too or it can be reapplied.";
                return true;
            }
            catch (Exception ex)
            {
                details = "Unable to disable Machine Identity Isolation: " + ex.Message;
                return false;
            }
        }

        private static void ReadOsVersion(HealthDiagnosticsSnapshot h)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    if (key == null)
                        return;

                    h.OsDisplayVersion = Convert.ToString(key.GetValue("DisplayVersion")) ?? String.Empty;
                    string build = Convert.ToString(key.GetValue("CurrentBuildNumber")) ?? String.Empty;
                    string ubr = Convert.ToString(key.GetValue("UBR")) ?? String.Empty;
                    h.OsBuild = String.IsNullOrWhiteSpace(ubr) ? build : build + "." + ubr;
                }
            }
            catch
            {
            }
        }

        private static void ReadCredentialGuard(HealthDiagnosticsSnapshot h)
        {
            try
            {
                ManagementScope scope = new ManagementScope(@"\\.\root\Microsoft\Windows\DeviceGuard");
                scope.Connect();

                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    scope,
                    new ObjectQuery("SELECT SecurityServicesRunning, VirtualizationBasedSecurityStatus FROM Win32_DeviceGuard")))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject item in results)
                    {
                        object running = item["SecurityServicesRunning"];
                        UInt32[] values = running as UInt32[];
                        if (values != null)
                        {
                            bool cg = false;
                            foreach (UInt32 value in values)
                            {
                                if (value == 1)
                                {
                                    cg = true;
                                    break;
                                }
                            }
                            h.CredentialGuardRunning = cg;
                        }

                        object vbs = item["VirtualizationBasedSecurityStatus"];
                        if (vbs != null)
                            h.VbsStatus = Convert.ToInt32(vbs);
                        break;
                    }
                }
            }
            catch
            {
            }
        }

        private static bool? IsServiceRunning(string serviceName)
        {
            try
            {
                using (ServiceController service = new ServiceController(serviceName))
                    return service.Status == ServiceControllerStatus.Running;
            }
            catch
            {
                return null;
            }
        }

        private static string GetDnsServers()
        {
            try
            {
                List<string> values = new List<string>();
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up)
                        continue;
                    if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    IPInterfaceProperties props = ni.GetIPProperties();
                    foreach (IPAddress address in props.DnsAddresses)
                    {
                        string text = address.ToString();
                        if (!values.Contains(text))
                            values.Add(text);
                    }
                }

                return String.Join(", ", values.ToArray());
            }
            catch
            {
                return String.Empty;
            }
        }

        private static void ReadDomainFunctionalLevel(HealthDiagnosticsSnapshot h, string dc)
        {
            h.DomainFunctionalLevelAttempted = true;
            try
            {
                using (DirectoryEntry rootDse = new DirectoryEntry("LDAP://" + dc + "/RootDSE"))
                {
                    object value = rootDse.Properties["domainFunctionality"].Value;
                    if (value == null)
                        return;

                    int level = Convert.ToInt32(value);
                    h.DomainFunctionalLevel = level;
                    h.DomainFunctionalLevelName = FormatDfl(level);
                }
            }
            catch
            {
            }
        }

        private static void ReadDcTimeSkew(HealthDiagnosticsSnapshot h, string dc)
        {
            IntPtr buffer = IntPtr.Zero;
            try
            {
                string server = dc.StartsWith(@"\\", StringComparison.Ordinal) ? dc : @"\\" + dc;
                int status = NetRemoteTOD(server, out buffer);
                if (status != 0 || buffer == IntPtr.Zero)
                {
                    h.DcTimeStatus = "Unavailable - " + NativeMethods.FormatError(status);
                    return;
                }

                TIME_OF_DAY_INFO tod = (TIME_OF_DAY_INFO)Marshal.PtrToStructure(buffer, typeof(TIME_OF_DAY_INFO));
                DateTimeOffset dcUtc = DateTimeOffset.FromUnixTimeSeconds(tod.tod_elapsedt);
                double skew = (DateTimeOffset.UtcNow - dcUtc).TotalSeconds;
                h.DcTimeSkewSeconds = skew;
                h.DcTimeStatus = skew.ToString("+0.0;-0.0;0.0") + " seconds";
            }
            catch (Exception ex)
            {
                h.DcTimeStatus = "Unavailable - " + ex.Message;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    NativeMethods.NetApiBufferFree(buffer);
            }
        }

        private static string ProbeDcPorts(string dc)
        {
            int[] ports = new int[] { 53, 88, 135, 389, 445 };
            List<string> results = new List<string>();

            foreach (int port in ports)
            {
                bool ok = CanConnectTcp(dc, port, 700);
                results.Add(port + "/TCP=" + (ok ? "OK" : "FAIL"));
            }

            return String.Join("; ", results.ToArray());
        }

        private static bool CanConnectTcp(string host, int port, int timeoutMs)
        {
            TcpClient client = null;
            try
            {
                client = new TcpClient();
                IAsyncResult ar = client.BeginConnect(host, port, null, null);
                bool ok = ar.AsyncWaitHandle.WaitOne(timeoutMs);
                if (!ok)
                    return false;
                client.EndConnect(ar);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (client != null)
                    client.Close();
            }
        }

        private static int? ReadDword(string path, string name)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(path))
                {
                    if (key == null)
                        return null;
                    object value = key.GetValue(name, null);
                    if (value == null)
                        return null;
                    return Convert.ToInt32(value);
                }
            }
            catch
            {
                return null;
            }
        }

        private static void SetDwordIfPresent(string path, string name, int value, List<string> changes)
        {
            using (RegistryKey read = Registry.LocalMachine.OpenSubKey(path))
            {
                if (read == null || read.GetValue(name, null) == null)
                    return;
            }

            using (RegistryKey write = Registry.LocalMachine.OpenSubKey(path, true))
            {
                if (write == null)
                    throw new InvalidOperationException("Registry path is not writable: HKLM\\" + path);
                write.SetValue(name, value, RegistryValueKind.DWord);
                changes.Add(@"HKLM\" + path);
            }
        }

        internal static string FormatMiiMode(int? value)
        {
            if (!value.HasValue)
                return "Not configured";
            switch (value.Value)
            {
                case 0: return "Disabled (0)";
                case 1: return "Audit (1)";
                case 2: return "Enforcement (2)";
                default: return "Unknown (" + value.Value + ")";
            }
        }

        private static string FormatDfl(int value)
        {
            switch (value)
            {
                case 0: return "Windows 2000";
                case 1:
                case 2: return "Windows Server 2003";
                case 3: return "Windows Server 2008";
                case 4: return "Windows Server 2008 R2";
                case 5: return "Windows Server 2012";
                case 6: return "Windows Server 2012 R2";
                case 7: return "Windows Server 2016";
                case 10: return "Windows Server 2025";
                default: return "Functional level " + value;
            }
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetRemoteTOD(string UncServerName, out IntPtr BufferPtr);

        [StructLayout(LayoutKind.Sequential)]
        private struct TIME_OF_DAY_INFO
        {
            public uint tod_elapsedt;
            public uint tod_msecs;
            public uint tod_hours;
            public uint tod_mins;
            public uint tod_secs;
            public uint tod_hunds;
            public int tod_timezone;
            public uint tod_tinterval;
            public uint tod_day;
            public uint tod_month;
            public uint tod_year;
            public uint tod_weekday;
        }
    }
}
