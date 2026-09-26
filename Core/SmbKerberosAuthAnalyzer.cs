using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class SmbKerberosAuthResult
    {
        internal string Dc = String.Empty;
        internal string KerberosCifsStatus = String.Empty;
        internal string KerberosCifsDetails = String.Empty;
        internal string SmbStatus = String.Empty;
        internal string SmbDetails = String.Empty;
        internal int? RequireSecuritySignature;
        internal int? EnableSecuritySignature;
        internal int? BlockNtlm;
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class SmbKerberosAuthAnalyzer
    {
        internal static SmbKerberosAuthResult Analyze(string domain, string dc)
        {
            return Analyze(domain, dc, String.Empty, null);
        }

        internal static SmbKerberosAuthResult Analyze(
            string domain,
            string dc,
            string user,
            string password)
        {
            SmbKerberosAuthResult r = new SmbKerberosAuthResult();
            r.Dc = DomainValidation.NormalizeDirectoryServer(dc);

            if (String.IsNullOrWhiteSpace(r.Dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(domain, false);
                if (discovered.Success)
                    r.Dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            r.RequireSecuritySignature = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "RequireSecuritySignature");
            r.EnableSecuritySignature = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "EnableSecuritySignature");
            r.BlockNtlm = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters",
                "BlockNTLM");

            if (String.IsNullOrWhiteSpace(r.Dc))
            {
                r.Findings.Add("No DC is available for SMB/Kerberos authentication testing.");
                return r;
            }

            CommandResult kerberos = NetworkCredentialProcessRunner.Run(
                "klist.exe",
                "get cifs/" + r.Dc,
                10000,
                user,
                password);

            r.KerberosCifsStatus = Status(kerberos);
            r.KerberosCifsDetails = Collapse(kerberos == null ? String.Empty : kerberos.CombinedOutput, 500);

            CommandResult smb = NetworkCredentialProcessRunner.Run(
                "net.exe",
                ProtocolDiagnosticsService.BuildRemoteNetViewArguments(r.Dc),
                10000,
                user,
                password);

            r.SmbStatus = Status(smb);
            r.SmbDetails = Collapse(smb == null ? String.Empty : smb.CombinedOutput, 500);

            if (HasKerberosSmbMismatch(r.KerberosCifsStatus, r.SmbStatus))
            {
                r.Findings.Add(
                    "CHECK: SMB access succeeded while an explicit CIFS Kerberos ticket request failed. " +
                    "Investigate SPNs, DNS name usage and NTLM fallback policy.");
            }

            if (r.BlockNtlm.HasValue && r.BlockNtlm.Value != 0)
            {
                r.Findings.Add(
                    "INFO: SMB client NTLM blocking is configured. Kerberos/SPN/DNS correctness is therefore especially important.");
            }

            if (r.RequireSecuritySignature.HasValue && r.RequireSecuritySignature.Value != 0)
                r.Findings.Add("INFO: SMB client signing is required.");

            return r;
        }

        internal static string ToText(SmbKerberosAuthResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("SMB / Kerberos Authentication Analyzer");
            sb.AppendLine("======================================");
            sb.AppendLine("DC:                          " + First(r.Dc, "(none)"));
            sb.AppendLine("CIFS Kerberos ticket:        " + First(r.KerberosCifsStatus, "(not tested)"));
            sb.AppendLine("SMB server enumeration:      " + First(r.SmbStatus, "(not tested)"));
            sb.AppendLine("RequireSecuritySignature:    " + Format(r.RequireSecuritySignature));
            sb.AppendLine("EnableSecuritySignature:     " + Format(r.EnableSecuritySignature));
            sb.AppendLine("BlockNTLM:                   " + Format(r.BlockNtlm));

            if (!String.IsNullOrWhiteSpace(r.KerberosCifsDetails))
            {
                sb.AppendLine();
                sb.AppendLine("Kerberos details:");
                sb.AppendLine(r.KerberosCifsDetails);
            }

            if (!String.IsNullOrWhiteSpace(r.SmbDetails))
            {
                sb.AppendLine();
                sb.AppendLine("SMB details:");
                sb.AppendLine(r.SmbDetails);
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

        internal static bool HasKerberosSmbMismatch(string kerberosStatus, string smbStatus)
        {
            return !String.IsNullOrWhiteSpace(kerberosStatus) &&
                   kerberosStatus.StartsWith("FAILED", StringComparison.OrdinalIgnoreCase) &&
                   String.Equals(smbStatus, "OK", StringComparison.OrdinalIgnoreCase);
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

        private static string Status(CommandResult result)
        {
            if (result == null)
                return "NOT TESTED";
            if (!String.IsNullOrWhiteSpace(result.Error))
                return "NOT TESTED";
            if (result.TimedOut)
                return "FAILED / TIMEOUT";
            return result.ExitCode == 0 ? "OK" : "FAILED";
        }

        private static string Collapse(string value, int max)
        {
            string text = (value ?? String.Empty).Replace("\r", " ").Replace("\n", " ").Trim();
            while (text.Contains("  "))
                text = text.Replace("  ", " ");
            if (text.Length > max)
                text = text.Substring(0, max) + "...";
            return text;
        }

        private static string Format(int? value)
        {
            return value.HasValue ? value.Value.ToString() : "(not explicitly configured)";
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
