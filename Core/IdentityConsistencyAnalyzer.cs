using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Text;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal sealed class IdentityConsistencyEntry
    {
        internal string DistinguishedName = String.Empty;
        internal string SamAccountName = String.Empty;
        internal string DnsHostName = String.Empty;
        internal string ObjectGuid = String.Empty;
        internal string ObjectSid = String.Empty;
        internal readonly List<string> MatchReasons = new List<string>();
    }

    internal sealed class IdentityConsistencyResult
    {
        internal string Dc = String.Empty;
        internal string ComputerName = String.Empty;
        internal string ExpectedFqdn = String.Empty;
        internal readonly List<IdentityConsistencyEntry> Entries = new List<IdentityConsistencyEntry>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class IdentityConsistencyAnalyzer
    {
        internal static IdentityConsistencyResult Analyze(
            string domain,
            string dc,
            string computerName,
            string expectedFqdn,
            string user,
            string password,
            CancellationToken cancellationToken)
        {
            IdentityConsistencyResult result = new IdentityConsistencyResult();
            result.Dc = DomainValidation.NormalizeDirectoryServer(dc);
            result.ComputerName = (computerName ?? String.Empty).Trim();
            result.ExpectedFqdn = (expectedFqdn ?? String.Empty).Trim();

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(domain, false);
                if (discovered.Success)
                    result.Dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            if (String.IsNullOrWhiteSpace(result.Dc) || String.IsNullOrWhiteSpace(result.ComputerName))
            {
                result.Findings.Add("CHECK: Identity consistency requires a DC and computer name.");
                return result;
            }

            try
            {
                using (DirectoryEntry rootDse = CreateEntry("LDAP://" + result.Dc + "/RootDSE", user, password))
                {
                    string nc = Convert.ToString(rootDse.Properties["defaultNamingContext"].Value);
                    if (String.IsNullOrWhiteSpace(nc))
                    {
                        result.Findings.Add("CHECK: defaultNamingContext was not returned by " + result.Dc + ".");
                        return result;
                    }

                    string[] expectedSpns = SpnCollisionAnalyzer.BuildExpectedSpns(
                        result.ComputerName,
                        result.ExpectedFqdn);

                    string filter = BuildFilter(result.ComputerName, result.ExpectedFqdn, expectedSpns);

                    using (DirectoryEntry root = CreateEntry("LDAP://" + result.Dc + "/" + nc, user, password))
                    using (DirectorySearcher searcher = new DirectorySearcher(root))
                    {
                        searcher.SearchScope = SearchScope.Subtree;
                        searcher.PageSize = 200;
                        searcher.ClientTimeout = TimeSpan.FromSeconds(8);
                        searcher.ServerTimeLimit = TimeSpan.FromSeconds(8);
                        searcher.Filter = filter;
                        string[] props = new string[] {
                            "distinguishedName", "sAMAccountName", "dNSHostName",
                            "objectGUID", "objectSid", "servicePrincipalName"
                        };
                        foreach (string prop in props)
                            searcher.PropertiesToLoad.Add(prop);

                        foreach (SearchResult found in searcher.FindAll())
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            IdentityConsistencyEntry entry = new IdentityConsistencyEntry();
                            entry.DistinguishedName = Get(found, "distinguishedName");
                            entry.SamAccountName = Get(found, "sAMAccountName");
                            entry.DnsHostName = Get(found, "dNSHostName");
                            entry.ObjectGuid = FormatGuid(found, "objectGUID");
                            entry.ObjectSid = FormatSid(found, "objectSid");

                            if (String.Equals(entry.SamAccountName, result.ComputerName + "$", StringComparison.OrdinalIgnoreCase))
                                entry.MatchReasons.Add("sAMAccountName");
                            if (!String.IsNullOrWhiteSpace(result.ExpectedFqdn) &&
                                String.Equals(entry.DnsHostName, result.ExpectedFqdn, StringComparison.OrdinalIgnoreCase))
                                entry.MatchReasons.Add("dNSHostName");

                            foreach (string spn in expectedSpns)
                            {
                                if (Contains(found, "servicePrincipalName", spn))
                                    entry.MatchReasons.Add("SPN:" + spn);
                            }

                            result.Entries.Add(entry);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                result.Findings.Add("CHECK: Identity consistency query failed: " + ex.Message);
                return result;
            }

            AnalyzeFindings(result);
            return result;
        }

        internal static string ToText(IdentityConsistencyResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Computer Identity Consistency Analyzer");
            sb.AppendLine("======================================");
            sb.AppendLine("DC:            " + First(result.Dc, "(none)"));
            sb.AppendLine("Computer:      " + First(result.ComputerName, "(none)"));
            sb.AppendLine("Expected FQDN: " + First(result.ExpectedFqdn, "(unknown)"));

            foreach (IdentityConsistencyEntry entry in result.Entries)
            {
                sb.AppendLine();
                sb.AppendLine("DN:      " + First(entry.DistinguishedName, "(unknown)"));
                sb.AppendLine("SAM:     " + First(entry.SamAccountName, "(unknown)"));
                sb.AppendLine("DNS:     " + First(entry.DnsHostName, "(unknown)"));
                sb.AppendLine("GUID:    " + First(entry.ObjectGuid, "(unknown)"));
                sb.AppendLine("SID:     " + First(entry.ObjectSid, "(unknown)"));
                sb.AppendLine("Matches: " + (entry.MatchReasons.Count == 0 ? "(none)" : String.Join(", ", entry.MatchReasons.ToArray())));
            }

            if (result.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Findings:");
                foreach (string finding in result.Findings)
                    sb.AppendLine("- " + finding);
            }

            return sb.ToString();
        }

        internal static string BuildFilter(string computerName, string fqdn, string[] spns)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("(&(objectCategory=computer)(|");
            sb.Append("(sAMAccountName=").Append(DomainValidation.EscapeLdapFilterValue(computerName + "$")).Append(")");
            if (!String.IsNullOrWhiteSpace(fqdn))
                sb.Append("(dNSHostName=").Append(DomainValidation.EscapeLdapFilterValue(fqdn)).Append(")");

            if (spns != null)
            {
                foreach (string spn in spns)
                    sb.Append("(servicePrincipalName=").Append(DomainValidation.EscapeLdapFilterValue(spn)).Append(")");
            }

            sb.Append("))");
            return sb.ToString();
        }

        private static void AnalyzeFindings(IdentityConsistencyResult result)
        {
            if (result.Entries.Count == 0)
            {
                result.Findings.Add("CHECK: No computer object matched the expected SAM/DNS/SPN identity keys.");
                return;
            }

            if (result.Entries.Count > 1)
            {
                result.Findings.Add(
                    "HIGH: Multiple AD computer objects match the same computer SAM/DNS/SPN identity keys.");
            }

            foreach (IdentityConsistencyEntry entry in result.Entries)
            {
                if (String.Equals(entry.SamAccountName, result.ComputerName + "$", StringComparison.OrdinalIgnoreCase) &&
                    !String.IsNullOrWhiteSpace(result.ExpectedFqdn) &&
                    !String.IsNullOrWhiteSpace(entry.DnsHostName) &&
                    !String.Equals(entry.DnsHostName, result.ExpectedFqdn, StringComparison.OrdinalIgnoreCase))
                {
                    result.Findings.Add(
                        "CHECK: The computer account SAM matches but dNSHostName differs: " +
                        entry.DnsHostName + " vs expected " + result.ExpectedFqdn + ".");
                }
            }
        }

        private static bool Contains(SearchResult result, string property, string expected)
        {
            if (!result.Properties.Contains(property))
                return false;
            foreach (object value in result.Properties[property])
            {
                if (String.Equals(Convert.ToString(value), expected, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static string Get(SearchResult result, string property)
        {
            return result.Properties.Contains(property) && result.Properties[property].Count > 0
                ? Convert.ToString(result.Properties[property][0]) ?? String.Empty
                : String.Empty;
        }

        private static string FormatGuid(SearchResult result, string property)
        {
            if (!result.Properties.Contains(property) || result.Properties[property].Count == 0)
                return String.Empty;
            byte[] value = result.Properties[property][0] as byte[];
            return value != null && value.Length == 16 ? new Guid(value).ToString() : String.Empty;
        }

        private static string FormatSid(SearchResult result, string property)
        {
            if (!result.Properties.Contains(property) || result.Properties[property].Count == 0)
                return String.Empty;
            byte[] value = result.Properties[property][0] as byte[];
            if (value == null)
                return String.Empty;
            try
            {
                return new System.Security.Principal.SecurityIdentifier(value, 0).Value;
            }
            catch
            {
                return String.Empty;
            }
        }

        private static DirectoryEntry CreateEntry(string path, string user, string password)
        {
            if (!String.IsNullOrWhiteSpace(user) && password != null)
                return new DirectoryEntry(path, user, password, AuthenticationTypes.Secure);
            return new DirectoryEntry(path);
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
