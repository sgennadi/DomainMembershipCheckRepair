using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class DnsDiagnosticsResult
    {
        internal string Domain = String.Empty;
        internal string DnsServers = String.Empty;
        internal string DomainAddresses = String.Empty;
        internal string LdapSrv = String.Empty;
        internal string KerberosSrv = String.Empty;
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class DnsDiagnosticsService
    {
        internal static DnsDiagnosticsResult Analyze(string domain)
        {
            DnsDiagnosticsResult result = new DnsDiagnosticsResult();
            result.Domain = (domain ?? String.Empty).Trim();
            result.DnsServers = GetDnsServers();

            if (String.IsNullOrWhiteSpace(result.Domain))
            {
                result.Findings.Add("No target domain is available for DNS testing.");
                return result;
            }

            try
            {
                IPAddress[] addresses = Dns.GetHostAddresses(result.Domain);
                List<string> values = new List<string>();
                foreach (IPAddress a in addresses)
                    values.Add(a.ToString());
                result.DomainAddresses = String.Join(", ", values.ToArray());
            }
            catch (Exception ex)
            {
                result.Findings.Add("Domain name resolution failed: " + ex.Message);
            }

            result.LdapSrv = RunNslookup("_ldap._tcp.dc._msdcs." + result.Domain);
            result.KerberosSrv = RunNslookup("_kerberos._tcp." + result.Domain);

            if (String.IsNullOrWhiteSpace(result.LdapSrv) ||
                result.LdapSrv.IndexOf("svr hostname", StringComparison.OrdinalIgnoreCase) < 0)
                result.Findings.Add("LDAP DC SRV records were not returned. Check that the client is using AD DNS and that _msdcs records are available.");

            if (String.IsNullOrWhiteSpace(result.KerberosSrv) ||
                result.KerberosSrv.IndexOf("svr hostname", StringComparison.OrdinalIgnoreCase) < 0)
                result.Findings.Add("Kerberos SRV records were not returned.");

            if (String.IsNullOrWhiteSpace(result.DnsServers))
                result.Findings.Add("No DNS servers were detected on active adapters.");

            return result;
        }

        internal static string ToText(DnsDiagnosticsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("DNS / DC Locator diagnostics");
            sb.AppendLine("============================");
            sb.AppendLine("Domain:      " + First(r.Domain, "(none)"));
            sb.AppendLine("DNS servers: " + First(r.DnsServers, "(none detected)"));
            sb.AppendLine("Domain A/AAAA: " + First(r.DomainAddresses, "(not resolved)"));
            sb.AppendLine();
            sb.AppendLine("_ldap._tcp.dc._msdcs SRV:");
            sb.AppendLine(First(r.LdapSrv, "(no result)"));
            sb.AppendLine();
            sb.AppendLine("_kerberos._tcp SRV:");
            sb.AppendLine(First(r.KerberosSrv, "(no result)"));

            if (r.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Findings:");
                foreach (string finding in r.Findings)
                    sb.AppendLine("- " + finding);
            }

            return sb.ToString();
        }

        private static string GetDnsServers()
        {
            List<string> values = new List<string>();
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    foreach (IPAddress dns in ni.GetIPProperties().DnsAddresses)
                    {
                        string text = dns.ToString();
                        if (!values.Contains(text))
                            values.Add(text);
                    }
                }
            }
            catch { }
            return String.Join(", ", values.ToArray());
        }

        private static string RunNslookup(string name)
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "nslookup.exe";
                psi.Arguments = "-type=SRV " + name;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;
                using (Process p = Process.Start(psi))
                {
                    if (p == null) return String.Empty;
                    string text = p.StandardOutput.ReadToEnd() + Environment.NewLine + p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(7000))
                    {
                        try { p.Kill(); } catch { }
                    }
                    return text.Trim();
                }
            }
            catch { return String.Empty; }
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
