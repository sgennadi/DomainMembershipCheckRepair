using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class ReplicationMetadataResult
    {
        internal bool RepadminAvailable;
        internal string Domain = String.Empty;
        internal string Dc = String.Empty;
        internal string ObjectDn = String.Empty;
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
            ReplicationMetadataResult r = new ReplicationMetadataResult();
            r.Domain = domain ?? String.Empty;
            r.Dc = DomainValidation.NormalizeDirectoryServer(dc);
            r.ObjectDn = objectDn ?? String.Empty;

            string repadmin = Path.Combine(Environment.SystemDirectory, "repadmin.exe");
            r.RepadminAvailable = File.Exists(repadmin);
            if (!r.RepadminAvailable)
            {
                r.Findings.Add("repadmin.exe is not installed on this computer. Install RSAT AD DS tools for replication metadata.");
                return r;
            }

            CommandResult summary = ProcessRunner.Run(repadmin, "/replsummary", 30000);
            r.ReplSummary = FormatCommand(summary);

            if (!String.IsNullOrWhiteSpace(r.Dc) && !String.IsNullOrWhiteSpace(r.ObjectDn))
            {
                CommandResult meta = ProcessRunner.Run(
                    repadmin,
                    "/showobjmeta " + Quote(r.Dc) + " " + Quote(r.ObjectDn),
                    30000);
                r.ObjectMetadata = FormatCommand(meta);

                CommandResult attr = ProcessRunner.Run(
                    repadmin,
                    "/showattr " + Quote(r.Dc) + " " + Quote(r.ObjectDn) + " /atts:objectGUID,pwdLastSet,whenChanged,servicePrincipalName",
                    30000);
                r.ObjectAttributes = FormatCommand(attr);
            }
            else
            {
                r.Findings.Add("Object metadata was not requested because the DC or object DN is unavailable.");
            }

            if (ContainsFailure(r.ReplSummary))
                r.Findings.Add("HIGH: repadmin /replsummary reports replication failures or unavailable partners.");

            if (ContainsFailure(r.ObjectMetadata))
                r.Findings.Add("CHECK: object replication metadata could not be read cleanly from the selected DC.");

            return r;
        }

        internal static string ToText(ReplicationMetadataResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("AD Replication Metadata Analyzer");
            sb.AppendLine("================================");
            sb.AppendLine("repadmin available: " + (r.RepadminAvailable ? "Yes" : "No"));
            sb.AppendLine("Domain:             " + First(r.Domain, "(none)"));
            sb.AppendLine("DC:                 " + First(r.Dc, "(none)"));
            sb.AppendLine("Object DN:          " + First(r.ObjectDn, "(none)"));

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

        private static string FormatCommand(CommandResult r)
        {
            if (r == null)
                return String.Empty;

            StringBuilder sb = new StringBuilder();
            if (r.TimedOut)
                sb.AppendLine("[Timed out]");
            if (!String.IsNullOrWhiteSpace(r.Error))
                sb.AppendLine("[Runner error] " + r.Error);
            if (r.Started && !r.TimedOut)
                sb.AppendLine("[Exit code] " + r.ExitCode);
            sb.Append(r.CombinedOutput ?? String.Empty);
            return sb.ToString().Trim();
        }

        private static bool ContainsFailure(string text)
        {
            if (String.IsNullOrWhiteSpace(text))
                return false;

            string value = text.ToLowerInvariant();
            return value.Contains("fails") ||
                   value.Contains("error") ||
                   value.Contains("1722") ||
                   value.Contains("8452") ||
                   value.Contains("access is denied");
        }

        private static string Quote(string value)
        {
            string text = value ?? String.Empty;
            return """ + text.Replace(""", "\"") + """;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
