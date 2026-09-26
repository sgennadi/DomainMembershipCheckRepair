using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class SpnCollisionEntry
    {
        internal string Spn = String.Empty;
        internal readonly List<string> DistinguishedNames = new List<string>();
    }

    internal sealed class SpnCollisionResult
    {
        internal string Domain = String.Empty;
        internal string Dc = String.Empty;
        internal string ComputerName = String.Empty;
        internal string Fqdn = String.Empty;
        internal readonly List<SpnCollisionEntry> Entries = new List<SpnCollisionEntry>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class SpnCollisionAnalyzer
    {
        internal static SpnCollisionResult Analyze(
            string domain,
            string dc,
            string computerName,
            string user,
            string password)
        {
            SpnCollisionResult r = new SpnCollisionResult();
            r.Domain = (domain ?? String.Empty).Trim();
            r.Dc = DomainValidation.NormalizeDirectoryServer(dc);
            r.ComputerName = String.IsNullOrWhiteSpace(computerName) ? Environment.MachineName : computerName.Trim();

            if (String.IsNullOrWhiteSpace(r.Dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(r.Domain, false);
                if (discovered.Success)
                    r.Dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            if (String.IsNullOrWhiteSpace(r.Dc))
            {
                r.Findings.Add("No domain controller is available for SPN collision analysis.");
                return r;
            }

            try
            {
                using (DirectoryEntry rootDse = CreateEntry("LDAP://" + r.Dc + "/RootDSE", user, password))
                {
                    string defaultNc = Convert.ToString(rootDse.Properties["defaultNamingContext"].Value) ?? String.Empty;
                    string dnsDomain = Convert.ToString(rootDse.Properties["rootDomainNamingContext"].Value) ?? String.Empty;

                    if (String.IsNullOrWhiteSpace(defaultNc))
                    {
                        r.Findings.Add("RootDSE did not return defaultNamingContext.");
                        return r;
                    }

                    string suffix = DomainValidation.DnToDns(defaultNc);
                    r.Fqdn = String.IsNullOrWhiteSpace(suffix)
                        ? r.ComputerName
                        : r.ComputerName + "." + suffix;

                    string[] spns = BuildExpectedSpns(r.ComputerName, r.Fqdn);

                    using (DirectoryEntry searchRoot = CreateEntry("LDAP://" + r.Dc + "/" + defaultNc, user, password))
                    {
                        foreach (string spn in spns)
                            AnalyzeSpn(r, searchRoot, spn);
                    }
                }
            }
            catch (Exception ex)
            {
                r.Findings.Add("SPN collision analysis failed: " + ex.Message);
            }

            return r;
        }

        internal static string ToText(SpnCollisionResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("SPN Collision Analyzer");
            sb.AppendLine("======================");
            sb.AppendLine("Domain:   " + First(r.Domain, "(none)"));
            sb.AppendLine("DC:       " + First(r.Dc, "(none)"));
            sb.AppendLine("Computer: " + First(r.ComputerName, "(none)"));
            sb.AppendLine("FQDN:     " + First(r.Fqdn, "(none)"));

            foreach (SpnCollisionEntry entry in r.Entries)
            {
                sb.AppendLine();
                sb.AppendLine(entry.Spn + " -> " + entry.DistinguishedNames.Count + " object(s)");
                foreach (string dn in entry.DistinguishedNames)
                    sb.AppendLine("  " + dn);
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

        internal static string[] BuildExpectedSpns(string computerName, string fqdn)
        {
            List<string> values = new List<string>();
            AddSpn(values, "HOST", computerName);
            AddSpn(values, "HOST", fqdn);
            AddSpn(values, "RestrictedKrbHost", computerName);
            AddSpn(values, "RestrictedKrbHost", fqdn);
            AddSpn(values, "TERMSRV", computerName);
            AddSpn(values, "TERMSRV", fqdn);
            AddSpn(values, "CIFS", computerName);
            AddSpn(values, "CIFS", fqdn);
            return values.ToArray();
        }

        internal static string BuildStateFingerprint(SpnCollisionResult result)
        {
            if (result == null || result.Entries.Count == 0)
                return String.Empty;

            List<string> states = new List<string>();
            foreach (SpnCollisionEntry entry in result.Entries)
            {
                List<string> dns = new List<string>(entry.DistinguishedNames);
                dns.Sort(StringComparer.OrdinalIgnoreCase);
                states.Add((entry.Spn ?? String.Empty).ToLowerInvariant() + "=" +
                           String.Join("|", dns.ToArray()).ToLowerInvariant());
            }

            states.Sort(StringComparer.OrdinalIgnoreCase);
            return String.Join(";", states.ToArray());
        }

        internal static int CountCollisions(SpnCollisionResult result)
        {
            if (result == null)
                return 0;

            int count = 0;
            foreach (SpnCollisionEntry entry in result.Entries)
            {
                if (entry.DistinguishedNames.Count > 1)
                    count++;
            }
            return count;
        }

        private static void AddSpn(List<string> values, string serviceClass, string host)
        {
            if (String.IsNullOrWhiteSpace(host))
                return;

            string candidate = serviceClass + "/" + host.Trim();
            foreach (string existing in values)
            {
                if (String.Equals(existing, candidate, StringComparison.OrdinalIgnoreCase))
                    return;
            }

            values.Add(candidate);
        }

        private static void AnalyzeSpn(
            SpnCollisionResult result,
            DirectoryEntry root,
            string spn)
        {
            SpnCollisionEntry entry = new SpnCollisionEntry();
            entry.Spn = spn;

            using (DirectorySearcher searcher = new DirectorySearcher(root))
            {
                searcher.Filter = "(servicePrincipalName=" + DomainValidation.EscapeLdapFilterValue(spn) + ")";
                searcher.SearchScope = SearchScope.Subtree;
                searcher.PageSize = 200;
                searcher.PropertiesToLoad.Add("distinguishedName");

                using (SearchResultCollection matches = searcher.FindAll())
                {
                    foreach (SearchResult match in matches)
                    {
                        if (match.Properties.Contains("distinguishedName") &&
                            match.Properties["distinguishedName"].Count > 0)
                        {
                            entry.DistinguishedNames.Add(Convert.ToString(match.Properties["distinguishedName"][0]));
                        }
                    }
                }
            }

            result.Entries.Add(entry);

            if (entry.DistinguishedNames.Count > 1)
            {
                result.Findings.Add(
                    "HIGH: SPN collision detected for " + spn + " on " +
                    entry.DistinguishedNames.Count + " AD objects.");
            }
            else if (entry.DistinguishedNames.Count == 0 &&
                     spn.StartsWith("HOST/", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add("CHECK: expected HOST SPN was not found: " + spn);
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
