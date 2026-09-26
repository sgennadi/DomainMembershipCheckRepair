using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

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

            CommandResult summary = ProcessRunner.Run(repadmin, BuildReplSummaryArguments(r.Dc), 30000);
            r.ReplSummary = FormatCommand(summary);

            CommandResult meta = null;
            CommandResult attr = null;
            if (!String.IsNullOrWhiteSpace(r.Dc) && !String.IsNullOrWhiteSpace(r.ObjectDn))
            {
                meta = ProcessRunner.Run(
                    repadmin,
                    "/showobjmeta " + Quote(r.Dc) + " " + Quote(r.ObjectDn),
                    30000);
                r.ObjectMetadata = FormatCommand(meta);

                attr = ProcessRunner.Run(
                    repadmin,
                    "/showattr " + Quote(r.Dc) + " " + Quote(r.ObjectDn) + " /atts:objectGUID,pwdLastSet,whenChanged,servicePrincipalName",
                    30000);
                r.ObjectAttributes = FormatCommand(attr);
            }
            else
            {
                r.Findings.Add("Object metadata was not requested because the DC or object DN is unavailable.");
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
                r.Findings.Add("CHECK: repadmin /replsummary did not complete successfully; replication health could not be verified.");
            }

            if (meta != null && CommandFailed(meta))
            {
                string metaDiagnostic = CommandDiagnosticText(meta);
                if (IsAccessDenied(metaDiagnostic))
                    r.Findings.Add("INFO: object replication metadata could not be read because the current security context does not have permission.");
                else
                    r.Findings.Add("CHECK: object replication metadata could not be read cleanly from the selected DC.");
            }

            if (attr != null && CommandFailed(attr))
            {
                string attrDiagnostic = CommandDiagnosticText(attr);
                if (IsAccessDenied(attrDiagnostic))
                    r.Findings.Add("INFO: replicated object attributes could not be read because the current security context does not have permission.");
                else
                    r.Findings.Add("CHECK: replicated object attributes could not be read cleanly from the selected DC.");
            }

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
