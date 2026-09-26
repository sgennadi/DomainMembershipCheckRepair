using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal sealed class ReplicationMetadataResult
    {
        internal bool RepadminAvailable;
        internal bool LdapFallbackAttempted;
        internal bool LdapFallbackSucceeded;
        internal string Domain = String.Empty;
        internal string Dc = String.Empty;
        internal string ObjectDn = String.Empty;
        internal string LdapDcState = String.Empty;
        internal string LdapObjectMetadata = String.Empty;
        internal string ReplSummary = String.Empty;
        internal string ObjectMetadata = String.Empty;
        internal string ObjectAttributes = String.Empty;
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class ReplicationMetadataService
    {
        internal static ReplicationMetadataResult Analyze(
            string domain,
            string dc,
            string objectDn)
        {
            return Analyze(domain, dc, objectDn, String.Empty, null);
        }

        internal static ReplicationMetadataResult Analyze(
            string domain,
            string dc,
            string objectDn,
            string user,
            string password)
        {
            return Analyze(
                domain,
                dc,
                objectDn,
                user,
                password,
                CancellationToken.None);
        }

        internal static ReplicationMetadataResult Analyze(
            string domain,
            string dc,
            string objectDn,
            string user,
            string password,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ReplicationMetadataResult r = new ReplicationMetadataResult();
            r.Domain = domain ?? String.Empty;
            r.Dc = DomainValidation.NormalizeDirectoryServer(dc);
            r.ObjectDn = objectDn ?? String.Empty;

            ReadLdapFallback(r, user, password, cancellationToken);

            string repadmin = Path.Combine(Environment.SystemDirectory, "repadmin.exe");
            r.RepadminAvailable = File.Exists(repadmin);
            if (!r.RepadminAvailable)
            {
                if (r.LdapFallbackSucceeded)
                    r.Findings.Add("INFO: repadmin.exe is not installed; LDAP replication metadata fallback was used.");
                else
                    r.Findings.Add("CHECK: repadmin.exe is not installed and LDAP replication metadata fallback was not available.");
                return r;
            }

            cancellationToken.ThrowIfCancellationRequested();
            CommandResult summary = NetworkCredentialProcessRunner.Run(
                repadmin,
                BuildReplSummaryArguments(r.Dc),
                30000,
                user,
                password,
                cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
            r.ReplSummary = FormatCommand(summary);

            CommandResult meta = null;
            CommandResult attr = null;
            if (!String.IsNullOrWhiteSpace(r.Dc) && !String.IsNullOrWhiteSpace(r.ObjectDn))
            {
                meta = NetworkCredentialProcessRunner.Run(
                    repadmin,
                    "/showobjmeta " + Quote(r.Dc) + " " + Quote(r.ObjectDn),
                    30000,
                    user,
                    password,
                    cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                r.ObjectMetadata = FormatCommand(meta);

                attr = NetworkCredentialProcessRunner.Run(
                    repadmin,
                    "/showattr " + Quote(r.Dc) + " " + Quote(r.ObjectDn) +
                    " /atts:objectGUID,pwdLastSet,whenChanged,uSNChanged,servicePrincipalName",
                    30000,
                    user,
                    password,
                    cancellationToken);
                cancellationToken.ThrowIfCancellationRequested();
                r.ObjectAttributes = FormatCommand(attr);
            }
            else
            {
                r.Findings.Add("CHECK: repadmin object metadata was not requested because the DC or object DN is unavailable.");
            }

            string summaryDiagnostic = CommandDiagnosticText(summary);
            if (HasReplicationFailures(summaryDiagnostic))
            {
                r.Findings.Add("HIGH: repadmin /replsummary reports replication failures or unavailable partners.");
            }
            else if (IsAccessDenied(summaryDiagnostic))
            {
                r.Findings.Add("INFO: repadmin /replsummary could not be evaluated because replication query access was denied for the current security context.");
            }
            else if (CommandFailed(summary))
            {
                r.Findings.Add("CHECK: repadmin /replsummary did not complete successfully; LDAP fallback remains available when its section succeeded.");
            }

            if (meta != null && CommandFailed(meta))
            {
                string metaDiagnostic = CommandDiagnosticText(meta);
                if (IsAccessDenied(metaDiagnostic))
                    r.Findings.Add("INFO: repadmin object metadata could not be read because the current security context does not have permission.");
                else
                    r.Findings.Add("CHECK: repadmin object replication metadata could not be read cleanly from the selected DC.");
            }

            if (attr != null && CommandFailed(attr))
            {
                string attrDiagnostic = CommandDiagnosticText(attr);
                if (IsAccessDenied(attrDiagnostic))
                    r.Findings.Add("INFO: repadmin replicated object attributes could not be read because the current security context does not have permission.");
                else
                    r.Findings.Add("CHECK: repadmin replicated object attributes could not be read cleanly from the selected DC.");
            }

            return r;
        }

        internal static bool HasAnyCapability(ReplicationMetadataResult result)
        {
            return result != null && (result.RepadminAvailable || result.LdapFallbackSucceeded);
        }

        internal static string ToText(ReplicationMetadataResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("AD Replication Metadata Analyzer");
            sb.AppendLine("================================");
            sb.AppendLine("repadmin available: " + (r.RepadminAvailable ? "Yes" : "No"));
            sb.AppendLine("LDAP fallback:      " + (r.LdapFallbackSucceeded ? "Available" : (r.LdapFallbackAttempted ? "Failed" : "Not attempted")));
            sb.AppendLine("Domain:             " + First(r.Domain, "(none)"));
            sb.AppendLine("DC:                 " + First(r.Dc, "(none)"));
            sb.AppendLine("Object DN:          " + First(r.ObjectDn, "(none)"));

            if (!String.IsNullOrWhiteSpace(r.LdapDcState))
            {
                sb.AppendLine();
                sb.AppendLine("LDAP DC replication state");
                sb.AppendLine("-------------------------");
                sb.AppendLine(r.LdapDcState);
            }

            if (!String.IsNullOrWhiteSpace(r.LdapObjectMetadata))
            {
                sb.AppendLine();
                sb.AppendLine("LDAP object replication metadata");
                sb.AppendLine("--------------------------------");
                sb.AppendLine(r.LdapObjectMetadata);
            }

            if (!String.IsNullOrWhiteSpace(r.ReplSummary))
            {
                sb.AppendLine();
                sb.AppendLine("repadmin /replsummary");
                sb.AppendLine("---------------------");
                sb.AppendLine(r.ReplSummary);
            }

            if (!String.IsNullOrWhiteSpace(r.ObjectMetadata))
            {
                sb.AppendLine();
                sb.AppendLine("repadmin /showobjmeta");
                sb.AppendLine("---------------------");
                sb.AppendLine(r.ObjectMetadata);
            }

            if (!String.IsNullOrWhiteSpace(r.ObjectAttributes))
            {
                sb.AppendLine();
                sb.AppendLine("repadmin /showattr");
                sb.AppendLine("-------------------");
                sb.AppendLine(r.ObjectAttributes);
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

        private static void ReadLdapFallback(
            ReplicationMetadataResult r,
            string user,
            string password,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (r == null || String.IsNullOrWhiteSpace(r.Dc))
                return;

            r.LdapFallbackAttempted = true;

            try
            {
                StringBuilder dcState = new StringBuilder();
                using (DirectoryEntry rootDse = CreateEntry("LDAP://" + r.Dc + "/RootDSE", user, password))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    dcState.AppendLine("dnsHostName:          " + ReadProperty(rootDse, "dnsHostName"));
                    dcState.AppendLine("defaultNamingContext: " + ReadProperty(rootDse, "defaultNamingContext"));
                    dcState.AppendLine("isSynchronized:       " + ReadProperty(rootDse, "isSynchronized"));
                    dcState.AppendLine("highestCommittedUSN:  " + ReadProperty(rootDse, "highestCommittedUSN"));
                    dcState.AppendLine("dsServiceName:        " + ReadProperty(rootDse, "dsServiceName"));
                }

                r.LdapDcState = dcState.ToString().Trim();
                r.LdapFallbackSucceeded = true;

                if (String.IsNullOrWhiteSpace(r.ObjectDn))
                {
                    r.Findings.Add("CHECK: LDAP DC replication state is available, but computer-object replication metadata could not be read because the object DN is unavailable.");
                    return;
                }

                cancellationToken.ThrowIfCancellationRequested();
                using (DirectoryEntry objectEntry = CreateEntry(
                    "LDAP://" + r.Dc + "/" + r.ObjectDn,
                    user,
                    password))
                using (DirectorySearcher searcher = new DirectorySearcher(objectEntry))
                {
                    searcher.ClientTimeout = TimeSpan.FromSeconds(8);
                    searcher.ServerTimeLimit = TimeSpan.FromSeconds(8);
                    searcher.SearchScope = SearchScope.Base;
                    searcher.Filter = "(objectClass=*)";
                    string[] properties = new string[]
                    {
                        "objectGUID",
                        "pwdLastSet",
                        "whenChanged",
                        "uSNChanged",
                        "servicePrincipalName",
                        "msDS-ReplAttributeMetaData",
                        "msDS-ReplValueMetaData"
                    };

                    foreach (string property in properties)
                        searcher.PropertiesToLoad.Add(property);

                    SearchResult result = searcher.FindOne();
                    if (result == null)
                    {
                        r.Findings.Add("CHECK: LDAP fallback could not locate the selected computer object on the selected DC.");
                        return;
                    }

                    StringBuilder metadata = new StringBuilder();
                    metadata.AppendLine("objectGUID:                 " + FormatGuid(result, "objectGUID"));
                    metadata.AppendLine("pwdLastSet:                 " + FirstProperty(result, "pwdLastSet"));
                    metadata.AppendLine("whenChanged:                " + FirstProperty(result, "whenChanged"));
                    metadata.AppendLine("uSNChanged:                 " + FirstProperty(result, "uSNChanged"));
                    metadata.AppendLine("servicePrincipalName count: " + PropertyCount(result, "servicePrincipalName"));
                    AppendMulti(metadata, result, "msDS-ReplAttributeMetaData", 40);
                    AppendMulti(metadata, result, "msDS-ReplValueMetaData", 20);
                    r.LdapObjectMetadata = metadata.ToString().Trim();
                }
            }
            catch (Exception ex)
            {
                if (IsAccessDenied(ex.Message))
                    r.Findings.Add("INFO: LDAP replication metadata fallback was denied for the current security context: " + ex.Message);
                else
                    r.Findings.Add("CHECK: LDAP replication metadata fallback failed: " + ex.Message);
            }
        }

        private static DirectoryEntry CreateEntry(string path, string user, string password)
        {
            if (!String.IsNullOrWhiteSpace(user) && password != null)
                return new DirectoryEntry(path, user, password, AuthenticationTypes.Secure);
            return new DirectoryEntry(path);
        }

        private static string ReadProperty(DirectoryEntry entry, string name)
        {
            try
            {
                object value = entry.Properties[name].Value;
                return value == null ? "(not returned)" : Convert.ToString(value);
            }
            catch
            {
                return "(not returned)";
            }
        }

        private static string FirstProperty(SearchResult result, string name)
        {
            try
            {
                if (result.Properties.Contains(name) && result.Properties[name].Count > 0)
                    return Convert.ToString(result.Properties[name][0]) ?? "(empty)";
            }
            catch
            {
            }
            return "(not returned)";
        }

        private static int PropertyCount(SearchResult result, string name)
        {
            try
            {
                return result.Properties.Contains(name) ? result.Properties[name].Count : 0;
            }
            catch
            {
                return 0;
            }
        }

        private static string FormatGuid(SearchResult result, string name)
        {
            try
            {
                if (result.Properties.Contains(name) && result.Properties[name].Count > 0)
                {
                    byte[] value = result.Properties[name][0] as byte[];
                    if (value != null && value.Length == 16)
                        return new Guid(value).ToString();
                }
            }
            catch
            {
            }
            return "(not returned)";
        }

        private static void AppendMulti(
            StringBuilder sb,
            SearchResult result,
            string name,
            int maxValues)
        {
            sb.AppendLine(name + ":");
            try
            {
                if (!result.Properties.Contains(name) || result.Properties[name].Count == 0)
                {
                    sb.AppendLine("  (not returned)");
                    return;
                }

                int count = 0;
                foreach (object value in result.Properties[name])
                {
                    if (count >= maxValues)
                    {
                        sb.AppendLine("  ... additional values omitted ...");
                        break;
                    }
                    sb.AppendLine("  " + (Convert.ToString(value) ?? String.Empty));
                    count++;
                }
            }
            catch (Exception ex)
            {
                sb.AppendLine("  (unable to read: " + ex.Message + ")");
            }
        }

        private static string FormatCommand(CommandResult r)
        {
            if (r == null)
                return String.Empty;

            StringBuilder sb = new StringBuilder();
            if (r.Cancelled)
                sb.AppendLine("[Cancelled]");
            if (r.TimedOut)
                sb.AppendLine("[Timed out]");
            if (!String.IsNullOrWhiteSpace(r.Error))
                sb.AppendLine("[Runner error] " + r.Error);
            if (r.Started && !r.TimedOut)
                sb.AppendLine("[Exit code] " + r.ExitCode);
            sb.Append(r.CombinedOutput ?? String.Empty);
            return sb.ToString().Trim();
        }

        internal static string BuildReplSummaryArguments(string dc)
        {
            string server = DomainValidation.NormalizeDirectoryServer(dc);
            return String.IsNullOrWhiteSpace(server)
                ? "/replsummary"
                : "/replsummary " + Quote(server);
        }

        internal static bool HasReplicationFailures(string text)
        {
            if (String.IsNullOrWhiteSpace(text))
                return false;

            string value = text.ToLowerInvariant();
            if (value.Contains("rpc server is unavailable") ||
                value.Contains("target principal name is incorrect") ||
                value.Contains("naming context is in the process of being removed"))
            {
                return true;
            }

            string[] lines = text.Replace("\r", String.Empty).Split('\n');
            foreach (string line in lines)
            {
                Match failureCount = Regex.Match(
                    line,
                    @"(?<!\d)([1-9]\d*)\s*/\s*\d+(?!\d)");

                if (failureCount.Success)
                    return true;
            }

            return false;
        }

        internal static bool IsAccessDenied(string text)
        {
            if (String.IsNullOrWhiteSpace(text))
                return false;

            string value = text.ToLowerInvariant();
            return value.Contains("access is denied") ||
                   value.Contains("access was denied") ||
                   value.Contains("replication access was denied") ||
                   value.Contains("unauthorized") ||
                   value.Contains("8453") ||
                   value.Contains("0x2105");
        }

        private static string CommandDiagnosticText(CommandResult result)
        {
            if (result == null)
                return String.Empty;

            StringBuilder sb = new StringBuilder();
            if (!String.IsNullOrWhiteSpace(result.Error))
                sb.AppendLine(result.Error);
            if (!String.IsNullOrWhiteSpace(result.CombinedOutput))
                sb.AppendLine(result.CombinedOutput);
            return sb.ToString();
        }

        private static bool CommandFailed(CommandResult result)
        {
            if (result == null)
                return true;
            if (!result.Started || result.TimedOut || !String.IsNullOrWhiteSpace(result.Error))
                return true;
            return result.ExitCode != 0;
        }

        private static string Quote(string value)
        {
            string text = value ?? String.Empty;
            return "\"" + text.Replace("\"", "\\\"") + "\"";
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
