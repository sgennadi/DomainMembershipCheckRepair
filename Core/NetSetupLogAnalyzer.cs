using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainMembershipCheckRepair
{
    internal sealed class NetSetupAnalysis
    {
        internal bool Present;
        internal DateTime? Modified;
        internal readonly List<string> RecentRelevantLines = new List<string>();
        internal readonly List<string> Findings = new List<string>();
        internal string LastErrorCode = String.Empty;
        internal string LastDc = String.Empty;
        internal string LastDomain = String.Empty;
    }

    internal static class NetSetupLogAnalyzer
    {
        private static readonly Regex HexCode = new Regex(@"0x[0-9a-fA-F]{3,8}", RegexOptions.Compiled);
        private static readonly Regex DcPattern = new Regex(@"\\\\[A-Za-z0-9_.-]+", RegexOptions.Compiled);

        internal static NetSetupAnalysis Analyze(string path)
        {
            NetSetupAnalysis result = new NetSetupAnalysis();
            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return result;

            result.Present = true;
            try { result.Modified = File.GetLastWriteTime(path); } catch { }

            string[] lines;
            try { lines = File.ReadAllLines(path); }
            catch (Exception ex)
            {
                result.Findings.Add("Unable to read NetSetup.log: " + ex.Message);
                return result;
            }

            int start = Math.Max(0, lines.Length - 1200);
            for (int i = start; i < lines.Length; i++)
            {
                string line = lines[i] ?? String.Empty;
                string lower = line.ToLowerInvariant();
                bool relevant =
                    lower.Contains("netp") ||
                    lower.Contains("error") ||
                    lower.Contains("fail") ||
                    lower.Contains("join") ||
                    lower.Contains("domain") ||
                    lower.Contains("status") ||
                    lower.Contains("0x");

                if (!relevant)
                    continue;

                if (result.RecentRelevantLines.Count >= 120)
                    result.RecentRelevantLines.RemoveAt(0);
                result.RecentRelevantLines.Add(line);

                Match hex = HexCode.Match(line);
                if (hex.Success)
                    result.LastErrorCode = hex.Value;

                Match dc = DcPattern.Match(line);
                if (dc.Success)
                    result.LastDc = dc.Value.TrimStart('\\');
            }

            Classify(result);
            return result;
        }

        internal static string ToText(NetSetupAnalysis a)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("NetSetup.log analysis");
            sb.AppendLine("--------------------");
            sb.AppendLine("Present:    " + (a.Present ? "Yes" : "No"));
            if (a.Modified.HasValue)
                sb.AppendLine("Modified:   " + a.Modified.Value.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("Last code:  " + (String.IsNullOrWhiteSpace(a.LastErrorCode) ? "(not detected)" : a.LastErrorCode));
            sb.AppendLine("Last DC:    " + (String.IsNullOrWhiteSpace(a.LastDc) ? "(not detected)" : a.LastDc));

            if (a.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Findings:");
                foreach (string finding in a.Findings)
                    sb.AppendLine("- " + finding);
            }

            if (a.RecentRelevantLines.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Recent relevant lines:");
                foreach (string line in a.RecentRelevantLines)
                    sb.AppendLine(line);
            }
            return sb.ToString();
        }

        internal static string ExplainCode(string code)
        {
            string c = (code ?? String.Empty).Trim().ToLowerInvariant();
            switch (c)
            {
                case "0xaac":
                case "0x00000aac":
                    return "NERR_AccountReuseBlockedByPolicy: existing computer-account reuse was blocked by Windows account-reuse hardening.";
                case "0x8b0":
                case "0x000008b0":
                    return "NERR_UserExists: an account with the same name already exists.";
                case "0x5":
                case "0x00000005":
                    return "Access denied: check join rights, computer-object ownership, reuse hardening, OU delegation, and security controls.";
                case "0x52e":
                case "0x0000052e":
                    return "Logon failure (1326): supplied domain credentials were rejected.";
                case "0x54b":
                case "0x0000054b":
                    return "No such domain (1355): DC locator/DNS/domain reachability problem.";
                case "0x51f":
                case "0x0000051f":
                    return "No logon servers (1311): no usable DC/logon server is reachable.";
                case "0x6ba":
                case "0x000006ba":
                    return "RPC server unavailable: check firewall, routing, endpoint mapper 135 and dynamic RPC.";
                case "0x6bf":
                case "0x000006bf":
                    return "RPC call failed: check RPC/network path and endpoint security.";
                default:
                    return String.Empty;
            }
        }

        private static void Classify(NetSetupAnalysis result)
        {
            if (!String.IsNullOrWhiteSpace(result.LastErrorCode))
            {
                string explanation = ExplainCode(result.LastErrorCode);
                if (!String.IsNullOrWhiteSpace(explanation))
                    result.Findings.Add(explanation);
            }

            string all = String.Join("\n", result.RecentRelevantLines.ToArray()).ToLowerInvariant();
            if (all.Contains("account reuse") || all.Contains("reuse") && all.Contains("blocked"))
                result.Findings.Add("Existing computer-account reuse appears to be blocked; inspect owner/permissions and KB5020276-era hardening.");
            if (all.Contains("no logon servers") || all.Contains("no such domain"))
                result.Findings.Add("DC discovery/connectivity failed; validate AD DNS, SRV records, VPN/routing and firewall.");
            if (all.Contains("rpc server is unavailable") || all.Contains("0x6ba"))
                result.Findings.Add("RPC connectivity problem detected; TCP 135 alone is not enough, dynamic RPC must also be reachable.");
            if (all.Contains("access is denied") || all.Contains("access denied"))
                result.Findings.Add("Access denied was logged; do not assume duplicate account alone—verify object ownership, delegation and reuse policy.");
            if (all.Contains("password") && (all.Contains("bad") || all.Contains("mismatch") || all.Contains("failed")))
                result.Findings.Add("Password-related failure detected; consider user credential rejection or machine-account password mismatch.");
        }
    }
}
