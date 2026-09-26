using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Globalization;
using System.Text;
using System.Threading;
using System.Xml;

namespace DomainMembershipCheckRepair
{
    internal sealed class ReplicationTimelineEntry
    {
        internal string Dc = String.Empty;
        internal string Attribute = String.Empty;
        internal int Version;
        internal string OriginatingDc = String.Empty;
        internal string OriginatingDsaInvocationId = String.Empty;
        internal string OriginatingUsn = String.Empty;
        internal string LocalUsn = String.Empty;
        internal string LastOriginatingChange = String.Empty;
    }

    internal sealed class ReplicationTimelineResult
    {
        internal string ObjectDn = String.Empty;
        internal readonly List<ReplicationTimelineEntry> Entries = new List<ReplicationTimelineEntry>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class ReplicationTimelineAnalyzer
    {
        private static readonly string[] ImportantAttributes = new string[]
        {
            "pwdLastSet",
            "servicePrincipalName",
            "dNSHostName",
            "userAccountControl"
        };

        internal static ReplicationTimelineResult Analyze(
            DcMatrixResult matrix,
            string objectDn,
            string user,
            string password,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            ReplicationTimelineResult result = new ReplicationTimelineResult();
            result.ObjectDn = objectDn ?? String.Empty;

            if (matrix == null || matrix.Entries.Count == 0 || String.IsNullOrWhiteSpace(result.ObjectDn))
            {
                result.Findings.Add("CHECK: Replication timeline requires a computer object DN and at least one reachable DC.");
                return result;
            }

            foreach (DcMatrixEntry dc in matrix.Entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (!dc.RootDseOk || String.IsNullOrWhiteSpace(dc.Host))
                    continue;

                if (progress != null)
                    progress("Replication Timeline: " + dc.Host);

                try
                {
                    using (DirectoryEntry entry = CreateEntry(
                        "LDAP://" + dc.Host + "/" + result.ObjectDn,
                        user,
                        password))
                    using (DirectorySearcher searcher = new DirectorySearcher(entry))
                    {
                        searcher.SearchScope = SearchScope.Base;
                        searcher.Filter = "(objectClass=*)";
                        searcher.ClientTimeout = TimeSpan.FromSeconds(8);
                        searcher.ServerTimeLimit = TimeSpan.FromSeconds(8);
                        searcher.PropertiesToLoad.Add("msDS-ReplAttributeMetaData");

                        SearchResult found = searcher.FindOne();
                        if (found == null)
                        {
                            result.Findings.Add("CHECK: Computer object was not returned by " + dc.Host + " for replication timeline.");
                            continue;
                        }

                        if (!found.Properties.Contains("msDS-ReplAttributeMetaData"))
                        {
                            result.Findings.Add("CHECK: " + dc.Host + " did not return msDS-ReplAttributeMetaData.");
                            continue;
                        }

                        foreach (object raw in found.Properties["msDS-ReplAttributeMetaData"])
                        {
                            ReplicationTimelineEntry parsed = ParseMetadataValue(dc.Host, Convert.ToString(raw));
                            if (parsed != null && IsImportant(parsed.Attribute))
                                result.Entries.Add(parsed);
                        }
                    }
                }
                catch (Exception ex)
                {
                    result.Findings.Add("CHECK: Replication timeline query failed on " + dc.Host + ": " + ex.Message);
                }
            }

            CompareVersions(result);
            return result;
        }

        internal static ReplicationTimelineEntry ParseMetadataValue(string dc, string xml)
        {
            if (String.IsNullOrWhiteSpace(xml))
                return null;

            try
            {
                XmlDocument doc = new XmlDocument();
                doc.LoadXml(xml);

                ReplicationTimelineEntry item = new ReplicationTimelineEntry();
                item.Dc = dc ?? String.Empty;
                item.Attribute = ReadNode(doc, "pszAttributeName");
                item.Version = ParseInt(ReadNode(doc, "dwVersion"));
                item.LastOriginatingChange = ReadNode(doc, "ftimeLastOriginatingChange");
                item.OriginatingDsaInvocationId = ReadNode(doc, "uuidLastOriginatingDsaInvocationID");
                item.OriginatingUsn = ReadNode(doc, "usnOriginatingChange");
                item.LocalUsn = ReadNode(doc, "usnLocalChange");
                item.OriginatingDc = ReadNode(doc, "pszLastOriginatingDsaDN");
                return item;
            }
            catch
            {
                return null;
            }
        }

        internal static string ToText(ReplicationTimelineResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Replication Timeline");
            sb.AppendLine("====================");
            sb.AppendLine("Object DN: " + First(result.ObjectDn, "(none)"));

            foreach (ReplicationTimelineEntry entry in result.Entries)
            {
                sb.AppendLine();
                sb.AppendLine(entry.Dc + " | " + entry.Attribute + " | version " + entry.Version);
                sb.AppendLine("  Last change:     " + First(entry.LastOriginatingChange, "(unknown)"));
                sb.AppendLine("  Originating DC:  " + First(entry.OriginatingDc, "(unknown)"));
                sb.AppendLine("  Originating USN: " + First(entry.OriginatingUsn, "(unknown)"));
                sb.AppendLine("  Local USN:       " + First(entry.LocalUsn, "(unknown)"));
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

        private static void CompareVersions(ReplicationTimelineResult result)
        {
            foreach (string attribute in ImportantAttributes)
            {
                int? first = null;
                string firstDc = String.Empty;

                foreach (ReplicationTimelineEntry entry in result.Entries)
                {
                    if (!String.Equals(entry.Attribute, attribute, StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (!first.HasValue)
                    {
                        first = entry.Version;
                        firstDc = entry.Dc;
                        continue;
                    }

                    if (first.Value != entry.Version)
                    {
                        result.Findings.Add(
                            "HIGH: " + attribute + " replication version differs between " +
                            firstDc + " (v" + first.Value + ") and " + entry.Dc + " (v" + entry.Version + ").");
                    }
                }
            }
        }

        private static bool IsImportant(string attribute)
        {
            foreach (string value in ImportantAttributes)
            {
                if (String.Equals(value, attribute, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static string ReadNode(XmlDocument doc, string name)
        {
            XmlNode node = doc.SelectSingleNode("//*[local-name()='" + name + "']");
            return node == null ? String.Empty : (node.InnerText ?? String.Empty).Trim();
        }

        private static int ParseInt(string value)
        {
            int result;
            return Int32.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out result)
                ? result
                : 0;
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
