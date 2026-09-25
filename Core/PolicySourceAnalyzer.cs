using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class PolicyEvidence
    {
        internal string Setting = String.Empty;
        internal string Source = String.Empty;
        internal string Path = String.Empty;
        internal string Value = String.Empty;
    }

    internal sealed class PolicySourceDiagnosticsResult
    {
        internal readonly List<PolicyEvidence> Evidence = new List<PolicyEvidence>();
        internal readonly List<string> GpResultMatches = new List<string>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class PolicySourceAnalyzer
    {
        internal static PolicySourceDiagnosticsResult Analyze()
        {
            PolicySourceDiagnosticsResult r = new PolicySourceDiagnosticsResult();

            AddRegistry(
                r, "Machine Identity Isolation", "Group Policy",
                RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                "MachineIdentityIsolation");

            AddRegistry(
                r, "Machine Identity Isolation", "Runtime / local",
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Lsa",
                "MachineIdentityIsolation");

            AddRegistry(
                r, "Machine Identity Isolation", "MDM PolicyManager",
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\PolicyManager\current\device\DeviceGuard",
                "MachineIdentityIsolation");

            AddRegistry(
                r, "Credential Guard LsaCfgFlags", "Group Policy",
                RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                "LsaCfgFlags");

            AddRegistry(
                r, "Credential Guard LsaCfgFlags", "Runtime / local",
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Lsa",
                "LsaCfgFlags");

            AddRegistry(
                r, "Virtualization Based Security", "Group Policy",
                RegistryHive.LocalMachine,
                @"SOFTWARE\Policies\Microsoft\Windows\DeviceGuard",
                "EnableVirtualizationBasedSecurity");

            AddRegistry(
                r, "Virtualization Based Security", "Runtime / local",
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\DeviceGuard",
                "EnableVirtualizationBasedSecurity");

            AddRegistry(
                r, "LDAP client signing", "Effective security registry",
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Services\LDAP",
                "LDAPClientIntegrity");

            AddRegistry(
                r, "LDAP client signing", "MDM PolicyManager",
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\PolicyManager\current\device\LocalPoliciesSecurityOptions",
                "NetworkSecurity_LDAPClientSigningRequirements");

            AddRegistry(
                r, "Kerberos allowed encryption types", "Group Policy",
                RegistryHive.LocalMachine,
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
                "SupportedEncryptionTypes");

            AddRegistry(
                r, "Kerberos allowed encryption types", "Runtime / local",
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters",
                "SupportedEncryptionTypes");

            string[] netlogonValues = new string[]
            {
                "RequireSignOrSeal",
                "RequireStrongKey",
                "SealSecureChannel",
                "SignSecureChannel",
                "DisablePasswordChange",
                "MaximumPasswordAge"
            };

            foreach (string name in netlogonValues)
            {
                AddRegistry(
                    r, "Netlogon " + name, "Group Policy",
                    RegistryHive.LocalMachine,
                    @"SOFTWARE\Policies\Microsoft\Netlogon\Parameters",
                    name);

                AddRegistry(
                    r, "Netlogon " + name, "Runtime / local",
                    RegistryHive.LocalMachine,
                    @"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                    name);
            }

            AddRegistry(
                r, "Computer account reuse allow list", "Local DC policy/runtime",
                RegistryHive.LocalMachine,
                @"SYSTEM\CurrentControlSet\Control\SAM",
                "ComputerAccountReuseAllowList");

            CollectGpResult(r);
            BuildFindings(r);
            return r;
        }

        internal static string ToText(PolicySourceDiagnosticsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Policy Source Analyzer");
            sb.AppendLine("======================");

            if (r.Evidence.Count == 0)
                sb.AppendLine("No tracked policy values were explicitly present in the inspected registry locations.");

            foreach (PolicyEvidence item in r.Evidence)
            {
                sb.AppendLine(
                    item.Setting + " | " + item.Source + " | " +
                    item.Path + " | value=" + item.Value);
            }

            if (r.GpResultMatches.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("gpresult matching lines:");
                foreach (string line in r.GpResultMatches)
                    sb.AppendLine("- " + line);
            }

            if (r.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Findings:");
                foreach (string finding in r.Findings)
                    sb.AppendLine("- " + finding);
            }

            return sb.ToString();
        }

        private static void AddRegistry(
            PolicySourceDiagnosticsResult r,
            string setting,
            string source,
            RegistryHive hive,
            string path,
            string name)
        {
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default))
                using (RegistryKey key = baseKey.OpenSubKey(path))
                {
                    if (key == null)
                        return;

                    object value = key.GetValue(name, null);
                    if (value == null)
                        return;

                    PolicyEvidence evidence = new PolicyEvidence();
                    evidence.Setting = setting;
                    evidence.Source = source;
                    evidence.Path = "HKLM\\" + path + "\\" + name;
                    evidence.Value = FormatRegistryValue(value);
                    r.Evidence.Add(evidence);
                }
            }
            catch
            {
            }
        }

        private static void CollectGpResult(PolicySourceDiagnosticsResult r)
        {
            CommandResult result = ProcessRunner.Run(
                "gpresult.exe",
                "/scope computer /z",
                25000);

            if (!String.IsNullOrWhiteSpace(result.Error))
            {
                r.Findings.Add("gpresult could not be started: " + result.Error);
                return;
            }

            if (result.TimedOut)
            {
                r.Findings.Add("gpresult /scope computer /z timed out.");
                return;
            }

            if (result.ExitCode != 0)
            {
                r.Findings.Add(
                    "gpresult computer scope was unavailable in the current context. Registry/MDM evidence is still reported.");
                return;
            }

            string[] lines = result.StandardOutput.Split(
                new string[] { "\r\n", "\n" },
                StringSplitOptions.RemoveEmptyEntries);

            string[] terms = new string[]
            {
                "Machine Identity",
                "Credential Guard",
                "LDAP",
                "Kerberos",
                "Netlogon",
                "computer account",
                "Device Guard"
            };

            foreach (string raw in lines)
            {
                string line = raw.Trim();
                foreach (string term in terms)
                {
                    if (line.IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        if (!r.GpResultMatches.Contains(line))
                            r.GpResultMatches.Add(line);
                        break;
                    }
                }

                if (r.GpResultMatches.Count >= 80)
                    break;
            }
        }

        private static void BuildFindings(PolicySourceDiagnosticsResult r)
        {
            bool miiPolicy = Has(r, "Machine Identity Isolation", "Group Policy");
            bool miiMdm = Has(r, "Machine Identity Isolation", "MDM PolicyManager");
            bool miiRuntime = Has(r, "Machine Identity Isolation", "Runtime / local");

            if ((miiPolicy || miiMdm) && miiRuntime)
            {
                r.Findings.Add(
                    "INFO: Machine Identity Isolation has both policy-source and runtime/local evidence. " +
                    "A local registry repair can be overwritten by the authoritative policy source.");
            }

            if (HasConflictingValues(r, "Machine Identity Isolation"))
            {
                r.Findings.Add(
                    "HIGH: Machine Identity Isolation values differ between inspected policy/runtime sources.");
            }

            if (HasConflictingValues(r, "Kerberos allowed encryption types"))
            {
                r.Findings.Add(
                    "CHECK: Kerberos encryption-type values differ between policy and runtime locations.");
            }

            foreach (PolicyEvidence item in r.Evidence)
            {
                if (item.Setting == "Netlogon DisablePasswordChange" &&
                    item.Value == "1")
                {
                    r.Findings.Add(
                        "HIGH: Netlogon DisablePasswordChange=1 is explicitly configured. Machine-account password rotation is disabled.");
                }
            }
        }

        private static bool Has(
            PolicySourceDiagnosticsResult r,
            string setting,
            string source)
        {
            foreach (PolicyEvidence item in r.Evidence)
            {
                if (item.Setting == setting && item.Source == source)
                    return true;
            }
            return false;
        }

        private static bool HasConflictingValues(
            PolicySourceDiagnosticsResult r,
            string setting)
        {
            string first = null;
            foreach (PolicyEvidence item in r.Evidence)
            {
                if (item.Setting != setting)
                    continue;

                if (first == null)
                    first = item.Value;
                else if (!String.Equals(first, item.Value, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static string FormatRegistryValue(object value)
        {
            string[] strings = value as string[];
            if (strings != null)
                return String.Join("; ", strings);

            byte[] bytes = value as byte[];
            if (bytes != null)
                return "binary[" + bytes.Length + "]";

            return Convert.ToString(value) ?? String.Empty;
        }
    }
}
