using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainMembershipCheckRepair
{
    internal sealed class SiteSubnetDiagnosticsResult
    {
        internal string CurrentSite = String.Empty;
        internal string SelectedDc = String.Empty;
        internal string SelectedDcSite = String.Empty;
        internal string ConfigurationNamingContext = String.Empty;
        internal readonly List<string> LocalIPv4 = new List<string>();
        internal readonly List<string> MatchingSubnets = new List<string>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class SiteSubnetDiagnosticsService
    {
        internal static SiteSubnetDiagnosticsResult Analyze(
            string domain,
            string preferredDc,
            string user,
            string password)
        {
            SiteSubnetDiagnosticsResult result = new SiteSubnetDiagnosticsResult();

            CommandResult site = ProcessRunner.Run("nltest.exe", "/dsgetsite", 7000);
            if (site.Started && !site.TimedOut && site.ExitCode == 0)
                result.CurrentSite = FirstUsefulLine(site.StandardOutput);
            else
                result.Findings.Add("CHECK: nltest /dsgetsite did not return a site. The client may not map to a valid AD subnet/site.");

            CollectLocalIPv4(result.LocalIPv4);

            string dc = DomainValidation.NormalizeDirectoryServer(preferredDc);
            if (String.IsNullOrWhiteSpace(dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(domain, false);
                if (discovered.Success)
                    dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            result.SelectedDc = dc;
            if (String.IsNullOrWhiteSpace(dc))
            {
                result.Findings.Add("No DC is available for AD Sites/Subnets inspection.");
                return result;
            }

            try
            {
                DirectoryEntry rootDse = CreateEntry("LDAP://" + dc + "/RootDSE", user, password);
                using (rootDse)
                {
                    result.ConfigurationNamingContext =
                        Convert.ToString(rootDse.Properties["configurationNamingContext"].Value) ?? String.Empty;
                    string serverName = Convert.ToString(rootDse.Properties["serverName"].Value) ?? String.Empty;
                    result.SelectedDcSite = ParseSiteFromServerDn(serverName);
                }
            }
            catch (Exception ex)
            {
                result.Findings.Add("Unable to read RootDSE/site data from " + dc + ": " + ex.Message);
                return result;
            }

            if (String.IsNullOrWhiteSpace(result.ConfigurationNamingContext))
                return result;

            try
            {
                string subnetsPath =
                    "LDAP://" + dc + "/CN=Subnets,CN=Sites," + result.ConfigurationNamingContext;

                DirectoryEntry subnets = CreateEntry(subnetsPath, user, password);
                using (subnets)
                using (DirectorySearcher searcher = new DirectorySearcher(subnets))
                {
                    searcher.Filter = "(objectClass=subnet)";
                    searcher.SearchScope = SearchScope.OneLevel;
                    searcher.PageSize = 500;
                    searcher.PropertiesToLoad.Add("cn");
                    searcher.PropertiesToLoad.Add("siteObject");

                    foreach (SearchResult item in searcher.FindAll())
                    {
                        string cidr = GetString(item, "cn");
                        string siteDn = GetString(item, "siteObject");
                        string mappedSite = ParseFirstCn(siteDn);

                        foreach (string ipText in result.LocalIPv4)
                        {
                            IPAddress ip;
                            if (!IPAddress.TryParse(ipText, out ip))
                                continue;

                            if (MatchesIpv4Subnet(ip, cidr))
                            {
                                string mapping = ipText + " -> " + cidr + " -> " +
                                    (String.IsNullOrWhiteSpace(mappedSite) ? "(site not returned)" : mappedSite);
                                if (!result.MatchingSubnets.Contains(mapping))
                                    result.MatchingSubnets.Add(mapping);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Findings.Add("Unable to query CN=Subnets from Active Directory: " + ex.Message);
            }

            if (result.LocalIPv4.Count > 0 && result.MatchingSubnets.Count == 0)
            {
                result.Findings.Add(
                    "HIGH: None of the active IPv4 addresses matched an AD Sites and Services subnet. " +
                    "This can cause the client to select a non-local DC.");
            }

            if (!String.IsNullOrWhiteSpace(result.CurrentSite) &&
                !String.IsNullOrWhiteSpace(result.SelectedDcSite) &&
                !String.Equals(result.CurrentSite, result.SelectedDcSite, StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(
                    "CHECK: Client site is '" + result.CurrentSite +
                    "' but the selected DC is in site '" + result.SelectedDcSite +
                    "'. Verify site coverage, subnet mapping and DC Locator behavior.");
            }

            return result;
        }

        internal static string ToText(SiteSubnetDiagnosticsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("AD Site / Subnet diagnostics");
            sb.AppendLine("============================");
            sb.AppendLine("Client site:     " + First(r.CurrentSite, "(not detected)"));
            sb.AppendLine("Selected DC:     " + First(r.SelectedDc, "(none)"));
            sb.AppendLine("Selected DC site:" + (String.IsNullOrWhiteSpace(r.SelectedDcSite) ? " (not detected)" : " " + r.SelectedDcSite));

            if (r.LocalIPv4.Count > 0)
            {
                sb.AppendLine("Local IPv4:");
                foreach (string ip in r.LocalIPv4)
                    sb.AppendLine("- " + ip);
            }

            if (r.MatchingSubnets.Count > 0)
            {
                sb.AppendLine("Matched AD subnets:");
                foreach (string item in r.MatchingSubnets)
                    sb.AppendLine("- " + item);
            }

            if (r.Findings.Count > 0)
            {
                sb.AppendLine("Findings:");
                foreach (string finding in r.Findings)
                    sb.AppendLine("- " + finding);
            }

            return sb.ToString();
        }

        private static DirectoryEntry CreateEntry(string path, string user, string password)
        {
            if (!String.IsNullOrWhiteSpace(user) && password != null)
                return new DirectoryEntry(path, user, password, AuthenticationTypes.Secure);
            return new DirectoryEntry(path);
        }

        private static void CollectLocalIPv4(List<string> values)
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    foreach (UnicastIPAddressInformation unicast in ni.GetIPProperties().UnicastAddresses)
                    {
                        IPAddress address = unicast.Address;
                        if (address != null &&
                            address.AddressFamily == AddressFamily.InterNetwork &&
                            !IPAddress.IsLoopback(address))
                        {
                            string text = address.ToString();
                            if (!values.Contains(text))
                                values.Add(text);
                        }
                    }
                }
            }
            catch
            {
            }
        }

        private static bool MatchesIpv4Subnet(IPAddress ip, string cidr)
        {
            if (ip == null || String.IsNullOrWhiteSpace(cidr))
                return false;

            string[] parts = cidr.Split('/');
            if (parts.Length != 2)
                return false;

            IPAddress network;
            int prefix;
            if (!IPAddress.TryParse(parts[0], out network) ||
                !Int32.TryParse(parts[1], out prefix) ||
                prefix < 0 || prefix > 32 ||
                network.AddressFamily != AddressFamily.InterNetwork ||
                ip.AddressFamily != AddressFamily.InterNetwork)
                return false;

            byte[] ipBytes = ip.GetAddressBytes();
            byte[] networkBytes = network.GetAddressBytes();

            int fullBytes = prefix / 8;
            int remaining = prefix % 8;

            for (int i = 0; i < fullBytes; i++)
                if (ipBytes[i] != networkBytes[i])
                    return false;

            if (remaining == 0)
                return true;

            int mask = 0xFF << (8 - remaining);
            return (ipBytes[fullBytes] & mask) == (networkBytes[fullBytes] & mask);
        }

        private static string ParseSiteFromServerDn(string serverDn)
        {
            if (String.IsNullOrWhiteSpace(serverDn))
                return String.Empty;

            Match match = Regex.Match(
                serverDn,
                @"CN=NTDS Settings,CN=[^,]+,CN=Servers,CN=([^,]+),CN=Sites",
                RegexOptions.IgnoreCase);

            return match.Success ? match.Groups[1].Value : String.Empty;
        }

        private static string ParseFirstCn(string dn)
        {
            if (String.IsNullOrWhiteSpace(dn))
                return String.Empty;

            Match match = Regex.Match(dn, @"^CN=([^,]+)", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value : String.Empty;
        }

        private static string FirstUsefulLine(string text)
        {
            string[] lines = (text ?? String.Empty)
                .Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string raw in lines)
            {
                string line = raw.Trim();
                if (line.Length == 0)
                    continue;
                if (line.IndexOf("command completed", StringComparison.OrdinalIgnoreCase) >= 0)
                    continue;
                return line;
            }

            return String.Empty;
        }

        private static string GetString(SearchResult result, string name)
        {
            if (result != null &&
                result.Properties.Contains(name) &&
                result.Properties[name].Count > 0)
                return Convert.ToString(result.Properties[name][0]) ?? String.Empty;

            return String.Empty;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
