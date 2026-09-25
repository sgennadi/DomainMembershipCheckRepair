using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class HardeningDiagnosticsResult
    {
        internal int? LdapClientIntegrity;
        internal int? LdapServerIntegrity;
        internal int? LdapEnforceChannelBinding;
        internal int? LmCompatibilityLevel;
        internal int? RestrictSendingNtlmTraffic;
        internal int? RequireSignOrSeal;
        internal int? SealSecureChannel;
        internal int? SignSecureChannel;
        internal int? KerberosPolicyEncryptionTypes;
        internal int? KerberosRuntimeEncryptionTypes;
        internal int? ComputerAccountEncryptionTypes;
        internal string ComputerAccountEncryptionText = String.Empty;
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class HardeningDiagnosticsService
    {
        internal static HardeningDiagnosticsResult Analyze(AdComputerAccountInfo account)
        {
            HardeningDiagnosticsResult r = new HardeningDiagnosticsResult();

            r.LdapClientIntegrity = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\LDAP",
                "LDAPClientIntegrity");

            r.LdapServerIntegrity = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
                "LDAPServerIntegrity");

            r.LdapEnforceChannelBinding = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\NTDS\Parameters",
                "LdapEnforceChannelBinding");

            r.LmCompatibilityLevel = ReadDword(
                @"SYSTEM\CurrentControlSet\Control\Lsa",
                "LmCompatibilityLevel");

            r.RestrictSendingNtlmTraffic = ReadDword(
                @"SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0",
                "RestrictSendingNTLMTraffic");

            r.RequireSignOrSeal = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "RequireSignOrSeal");

            r.SealSecureChannel = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "SealSecureChannel");

            r.SignSecureChannel = ReadDword(
                @"SYSTEM\CurrentControlSet\Services\Netlogon\Parameters",
                "SignSecureChannel");

            r.KerberosPolicyEncryptionTypes = ReadDword(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters",
                "SupportedEncryptionTypes");

            r.KerberosRuntimeEncryptionTypes = ReadDword(
                @"SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters",
                "SupportedEncryptionTypes");

            if (account != null && account.SupportedEncryptionTypes.HasValue)
            {
                r.ComputerAccountEncryptionTypes = account.SupportedEncryptionTypes;
                r.ComputerAccountEncryptionText = DecodeEncryptionTypes(account.SupportedEncryptionTypes.Value);
            }

            BuildFindings(r);
            return r;
        }

        internal static string ToText(HardeningDiagnosticsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("LDAP / Kerberos / Netlogon hardening");
            sb.AppendLine("====================================");
            sb.AppendLine("LDAP client signing:      " + FormatLdapClient(r.LdapClientIntegrity));
            sb.AppendLine("Local DC LDAP signing:    " + FormatLdapServer(r.LdapServerIntegrity));
            sb.AppendLine("Local DC channel binding: " + FormatChannelBinding(r.LdapEnforceChannelBinding));
            sb.AppendLine("LM compatibility level:   " + FormatNullable(r.LmCompatibilityLevel));
            sb.AppendLine("Restrict outgoing NTLM:   " + FormatNullable(r.RestrictSendingNtlmTraffic));
            sb.AppendLine("Netlogon RequireSignSeal: " + FormatNullable(r.RequireSignOrSeal));
            sb.AppendLine("Netlogon SealChannel:     " + FormatNullable(r.SealSecureChannel));
            sb.AppendLine("Netlogon SignChannel:     " + FormatNullable(r.SignSecureChannel));
            sb.AppendLine("Kerberos policy etypes:   " +
                FormatEncryptionValue(r.KerberosPolicyEncryptionTypes));
            sb.AppendLine("Kerberos runtime etypes:  " +
                FormatEncryptionValue(r.KerberosRuntimeEncryptionTypes));
            sb.AppendLine("Computer AD etypes:       " +
                (r.ComputerAccountEncryptionTypes.HasValue
                    ? "0x" + r.ComputerAccountEncryptionTypes.Value.ToString("X") +
                      " (" + r.ComputerAccountEncryptionText + ")"
                    : "(not available)"));

            if (r.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Findings:");
                foreach (string finding in r.Findings)
                    sb.AppendLine("- " + finding);
            }

            return sb.ToString();
        }

        internal static string DecodeEncryptionTypes(int value)
        {
            List<string> values = new List<string>();

            if ((value & 0x00000001) != 0) values.Add("DES-CBC-CRC");
            if ((value & 0x00000002) != 0) values.Add("DES-CBC-MD5");
            if ((value & 0x00000004) != 0) values.Add("RC4-HMAC");
            if ((value & 0x00000008) != 0) values.Add("AES128-SHA1");
            if ((value & 0x00000010) != 0) values.Add("AES256-SHA1");
            if ((value & 0x00000020) != 0) values.Add("FAST");
            if ((value & 0x00000040) != 0) values.Add("Compound identity");
            if ((value & 0x00000080) != 0) values.Add("Claims");
            if ((value & 0x00000100) != 0) values.Add("Resource SID compression disabled");
            if ((value & 0x00000200) != 0) values.Add("AES256-SK");

            return values.Count == 0 ? "None/unspecified flags" : String.Join(", ", values.ToArray());
        }

        private static void BuildFindings(HardeningDiagnosticsResult r)
        {
            if (r.LdapClientIntegrity == 0)
            {
                r.Findings.Add(
                    "MEDIUM: LDAP client signing is explicitly disabled. Review the effective security policy before troubleshooting LDAP compatibility.");
            }
            else if (r.LdapClientIntegrity == 2)
            {
                r.Findings.Add(
                    "INFO: LDAP client signing is set to Require signing. Legacy or unsigned LDAP applications can fail while normal signed AD operations continue.");
            }

            if (r.LdapServerIntegrity.HasValue && r.LdapServerIntegrity.Value == 2)
            {
                r.Findings.Add(
                    "INFO: This computer is acting as a DC/AD LDS endpoint with LDAP signing required locally.");
            }

            if (r.LdapEnforceChannelBinding.HasValue &&
                r.LdapEnforceChannelBinding.Value == 2)
            {
                r.Findings.Add(
                    "INFO: Local LDAP server channel binding is set to Always. Older TLS LDAP clients can be incompatible.");
            }

            int? accountTypes = r.ComputerAccountEncryptionTypes;
            if (accountTypes.HasValue)
            {
                int value = accountTypes.Value;
                bool des = (value & 0x3) != 0;
                bool rc4 = (value & 0x4) != 0;
                bool aes = (value & 0x18) != 0;

                if (des)
                {
                    r.Findings.Add(
                        "HIGH: The computer account advertises legacy DES Kerberos encryption support.");
                }

                if (rc4 && !aes)
                {
                    r.Findings.Add(
                        "HIGH: The computer account appears RC4-only without AES128/AES256 flags. This can fail in hardened Kerberos environments.");
                }
                else if (rc4 && aes)
                {
                    r.Findings.Add(
                        "INFO: The computer account advertises both AES and RC4. AES is available; review RC4 retirement policy separately.");
                }
                else if (aes)
                {
                    r.Findings.Add(
                        "INFO: The computer account advertises AES Kerberos encryption support.");
                }
            }

            if (r.RequireSignOrSeal == 0 ||
                r.SignSecureChannel == 0 ||
                r.SealSecureChannel == 0)
            {
                r.Findings.Add(
                    "CHECK: One or more Netlogon secure-channel signing/sealing registry values are explicitly disabled. Confirm this is intentional policy.");
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

        private static string FormatLdapClient(int? value)
        {
            if (!value.HasValue) return "(not explicitly configured)";
            switch (value.Value)
            {
                case 0: return "None (0)";
                case 1: return "Negotiate signing (1)";
                case 2: return "Require signing (2)";
                default: return "Unknown (" + value.Value + ")";
            }
        }

        private static string FormatLdapServer(int? value)
        {
            if (!value.HasValue) return "(not local DC / not explicitly configured)";
            switch (value.Value)
            {
                case 0: return "Signing disabled (0)";
                case 1: return "Negotiate/default-compatible (1)";
                case 2: return "Require signing (2)";
                default: return "Unknown (" + value.Value + ")";
            }
        }

        private static string FormatChannelBinding(int? value)
        {
            if (!value.HasValue) return "(not local DC / not explicitly configured)";
            switch (value.Value)
            {
                case 0: return "Never (0)";
                case 1: return "When supported (1)";
                case 2: return "Always (2)";
                default: return "Unknown (" + value.Value + ")";
            }
        }

        private static string FormatEncryptionValue(int? value)
        {
            if (!value.HasValue)
                return "(not explicitly configured)";

            return "0x" + value.Value.ToString("X") + " (" + DecodeEncryptionTypes(value.Value) + ")";
        }

        private static string FormatNullable(int? value)
        {
            return value.HasValue ? value.Value.ToString() : "(not explicitly configured)";
        }
    }
}
