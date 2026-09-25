using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
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
        internal string LocalFqdn = String.Empty;
        internal string LocalAddresses = String.Empty;
        internal string LocalForwardAddresses = String.Empty;
        internal string ReverseLookups = String.Empty;
        internal readonly List<string> ActiveAdapters = new List<string>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class DnsDiagnosticsService
    {
        internal static DnsDiagnosticsResult Analyze(string domain)
        {
            DnsDiagnosticsResult result = new DnsDiagnosticsResult();
            result.Domain = (domain ?? String.Empty).Trim();

            HashSet<string> localAddresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            CollectAdapterDetails(result, localAddresses);
            result.LocalAddresses = JoinSet(localAddresses);

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
            catch
            {
                // A domain apex does not have to resolve; this is informational only.
            }

            result.LdapSrv = RunNslookup("_ldap._tcp.dc._msdcs." + result.Domain);
            result.KerberosSrv = RunNslookup("_kerberos._tcp." + result.Domain);

            if (!ContainsSrvResult(result.LdapSrv))
                result.Findings.Add("LDAP DC SRV records were not returned. Check that the client is using AD DNS and that _msdcs records are available.");

            if (!ContainsSrvResult(result.KerberosSrv))
                result.Findings.Add("Kerberos SRV records were not returned.");

            if (String.IsNullOrWhiteSpace(result.DnsServers))
                result.Findings.Add("No DNS servers were detected on active adapters.");

            AnalyzeLocalHostRecords(result, localAddresses);
            return result;
        }

        internal static string ToText(DnsDiagnosticsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("DNS / DC Locator diagnostics");
            sb.AppendLine("============================");
            sb.AppendLine("Domain:         " + First(r.Domain, "(none)"));
            sb.AppendLine("DNS servers:    " + First(r.DnsServers, "(none detected)"));
            sb.AppendLine("Domain A/AAAA:  " + First(r.DomainAddresses, "(not resolved / not required)"));
            sb.AppendLine("Local FQDN:     " + First(r.LocalFqdn, "(not derived)"));
            sb.AppendLine("Local IPs:      " + First(r.LocalAddresses, "(none detected)"));
            sb.AppendLine("FQDN A/AAAA:    " + First(r.LocalForwardAddresses, "(not resolved)"));
            sb.AppendLine("Reverse lookup: " + First(r.ReverseLookups, "(not available)"));

            if (r.ActiveAdapters.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Active adapters:");
                foreach (string adapter in r.ActiveAdapters)
                    sb.AppendLine("- " + adapter);
            }

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

        private static void CollectAdapterDetails(
            DnsDiagnosticsResult result,
            HashSet<string> localAddresses)
        {
            HashSet<string> dnsServers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    IPInterfaceProperties props = ni.GetIPProperties();
                    List<string> ips = new List<string>();
                    List<string> gateways = new List<string>();
                    List<string> dns = new List<string>();

                    foreach (UnicastIPAddressInformation unicast in props.UnicastAddresses)
                    {
                        IPAddress address = unicast.Address;
                        if (address == null)
                            continue;
                        if (address.AddressFamily != AddressFamily.InterNetwork &&
                            address.AddressFamily != AddressFamily.InterNetworkV6)
                            continue;
                        if (IPAddress.IsLoopback(address))
                            continue;

                        string text = address.ToString();
                        ips.Add(text);
                        localAddresses.Add(text);
                    }

                    foreach (GatewayIPAddressInformation gateway in props.GatewayAddresses)
                    {
                        if (gateway.Address != null)
                            gateways.Add(gateway.Address.ToString());
                    }

                    foreach (IPAddress server in props.DnsAddresses)
                    {
                        string text = server.ToString();
                        dns.Add(text);
                        dnsServers.Add(text);
                    }

                    result.ActiveAdapters.Add(
                        ni.Name +
                        " | " + ni.NetworkInterfaceType +
                        " | suffix=" + First(props.DnsSuffix, "(none)") +
                        " | IP=" + (ips.Count == 0 ? "(none)" : String.Join(",", ips.ToArray())) +
                        " | GW=" + (gateways.Count == 0 ? "(none)" : String.Join(",", gateways.ToArray())) +
                        " | DNS=" + (dns.Count == 0 ? "(none)" : String.Join(",", dns.ToArray())));
                }
            }
            catch (Exception ex)
            {
                result.Findings.Add("Unable to enumerate active network adapters: " + ex.Message);
            }

            result.DnsServers = JoinSet(dnsServers);

            if (result.ActiveAdapters.Count > 1)
            {
                result.Findings.Add(
                    "CHECK: Multiple active network adapters are present. On VPN/multi-NIC systems verify interface routing, DNS suffixes and split-DNS behavior.");
            }
        }

        private static void AnalyzeLocalHostRecords(
            DnsDiagnosticsResult result,
            HashSet<string> localAddresses)
        {
            string suffix = String.Empty;
            try
            {
                suffix = IPGlobalProperties.GetIPGlobalProperties().DomainName ?? String.Empty;
            }
            catch
            {
            }

            if (String.IsNullOrWhiteSpace(suffix))
                suffix = result.Domain;

            if (String.IsNullOrWhiteSpace(suffix))
                return;

            result.LocalFqdn = Environment.MachineName + "." + suffix.Trim('.');

            try
            {
                IPAddress[] forward = Dns.GetHostAddresses(result.LocalFqdn);
                List<string> forwardValues = new List<string>();
                bool sawLocal = false;
                bool sawForeign = false;

                foreach (IPAddress address in forward)
                {
                    string text = address.ToString();
                    forwardValues.Add(text);

                    if (localAddresses.Contains(text))
                        sawLocal = true;
                    else if (address.AddressFamily == AddressFamily.InterNetwork ||
                             address.AddressFamily == AddressFamily.InterNetworkV6)
                        sawForeign = true;
                }

                result.LocalForwardAddresses = String.Join(", ", forwardValues.ToArray());

                if (!sawLocal && forwardValues.Count > 0)
                {
                    result.Findings.Add(
                        "HIGH: The computer FQDN resolves, but none of the returned addresses match an active local interface. Check stale or incorrect DNS host records.");
                }
                else if (sawForeign)
                {
                    result.Findings.Add(
                        "CHECK: The computer FQDN returns additional addresses that are not currently assigned to an active local interface. Check for stale/duplicate A or AAAA records.");
                }
            }
            catch (Exception ex)
            {
                result.Findings.Add(
                    "CHECK: The computer FQDN could not be resolved: " + result.LocalFqdn + " - " + ex.Message);
            }

            List<string> reverse = new List<string>();
            foreach (string text in localAddresses)
            {
                IPAddress ip;
                if (!IPAddress.TryParse(text, out ip) || ip.AddressFamily != AddressFamily.InterNetwork)
                    continue;

                try
                {
                    IPHostEntry entry = Dns.GetHostEntry(ip);
                    reverse.Add(text + "=" + (entry.HostName ?? "(no name)"));

                    if (!String.IsNullOrWhiteSpace(entry.HostName) &&
                        !entry.HostName.Equals(result.LocalFqdn, StringComparison.OrdinalIgnoreCase) &&
                        !entry.HostName.StartsWith(Environment.MachineName + ".", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Findings.Add(
                            "CHECK: Reverse DNS for " + text + " points to " + entry.HostName +
                            " instead of the current computer name.");
                    }
                }
                catch
                {
                    reverse.Add(text + "=(no PTR)");
                }
            }

            result.ReverseLookups = String.Join("; ", reverse.ToArray());
        }

        private static string RunNslookup(string name)
        {
            CommandResult result = ProcessRunner.Run("nslookup.exe", "-type=SRV " + name, 7000);
            if (!String.IsNullOrWhiteSpace(result.Error))
                return result.Error;
            return result.CombinedOutput.Trim();
        }

        private static bool ContainsSrvResult(string output)
        {
            if (String.IsNullOrWhiteSpace(output))
                return false;

            string text = output.ToLowerInvariant();
            return text.Contains("svr hostname") ||
                   text.Contains("service =") ||
                   text.Contains("service location");
        }

        private static string JoinSet(HashSet<string> values)
        {
            string[] array = new string[values.Count];
            values.CopyTo(array);
            return String.Join(", ", array);
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
