using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal sealed class KerberosTicketDetails
    {
        internal string Label = String.Empty;
        internal string Status = String.Empty;
        internal string Client = String.Empty;
        internal string Server = String.Empty;
        internal string Domain = String.Empty;
        internal string EncryptionType = String.Empty;
        internal string SessionKeyType = String.Empty;
        internal string TicketFlags = String.Empty;
        internal string StartTime = String.Empty;
        internal string EndTime = String.Empty;
        internal string RenewTime = String.Empty;
        internal string TimeSkew = String.Empty;
        internal string Raw = String.Empty;
    }

    internal sealed class KerberosDeepResult
    {
        internal string Domain = String.Empty;
        internal string Dc = String.Empty;
        internal string KdcBindings = String.Empty;
        internal readonly List<KerberosTicketDetails> Tickets = new List<KerberosTicketDetails>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class KerberosDeepAnalyzer
    {
        internal static KerberosDeepResult Analyze(
            string domain,
            string dc,
            string user,
            string password,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            KerberosDeepResult result = new KerberosDeepResult();
            result.Domain = (domain ?? String.Empty).Trim();
            result.Dc = DomainValidation.NormalizeDirectoryServer(dc);

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(result.Domain, false);
                if (discovered.Success)
                    result.Dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                result.Findings.Add("CHECK: No domain controller is available for deep Kerberos analysis.");
                return result;
            }

            Report(progress, "Kerberos: querying KDC binding cache");
            CommandResult bindings = NetworkCredentialProcessRunner.Run(
                "klist.exe",
                "query_bind",
                10000,
                user,
                password,
                cancellationToken);
            result.KdcBindings = Collapse(bindings == null ? String.Empty : bindings.CombinedOutput, 1600);

            Report(progress, "Kerberos: reading TGT");
            CommandResult tgt = NetworkCredentialProcessRunner.Run(
                "klist.exe",
                "tgt",
                10000,
                user,
                password,
                cancellationToken);
            KerberosTicketDetails tgtTicket = ParseTicketOutput("TGT", tgt);
            result.Tickets.Add(tgtTicket);

            string[] services = new string[]
            {
                "HOST/" + result.Dc,
                "LDAP/" + result.Dc,
                "CIFS/" + result.Dc
            };

            foreach (string spn in services)
            {
                cancellationToken.ThrowIfCancellationRequested();
                Report(progress, "Kerberos: requesting " + spn);
                CommandResult command = NetworkCredentialProcessRunner.Run(
                    "klist.exe",
                    "get " + spn,
                    10000,
                    user,
                    password,
                    cancellationToken);
                result.Tickets.Add(ParseTicketOutput(spn, command));
            }

            AnalyzeFindings(result);
            return result;
        }

        internal static KerberosTicketDetails ParseTicketText(string label, string text)
        {
            KerberosTicketDetails ticket = new KerberosTicketDetails();
            ticket.Label = label ?? String.Empty;
            ticket.Status = "OK";
            ticket.Raw = text ?? String.Empty;

            string[] lines = (text ?? String.Empty).Replace("\r", String.Empty).Split('\n');
            foreach (string raw in lines)
            {
                string line = (raw ?? String.Empty).Trim();
                if (line.Length == 0)
                    continue;

                SetIfMatch(line, "Client:", ref ticket.Client);
                SetIfMatch(line, "Server:", ref ticket.Server);
                SetIfMatch(line, "ServiceName:", ref ticket.Server);
                SetIfMatch(line, "TargetName", ref ticket.Server);
                SetIfMatch(line, "DomainName:", ref ticket.Domain);
                SetIfMatch(line, "TargetDomainName:", ref ticket.Domain);
                SetIfMatch(line, "KerbTicket Encryption Type:", ref ticket.EncryptionType);
                SetIfMatch(line, "Ticket Encryption Type:", ref ticket.EncryptionType);
                SetIfMatch(line, "Session Key Type:", ref ticket.SessionKeyType);
                SetIfMatch(line, "SessionKeyType:", ref ticket.SessionKeyType);
                SetIfMatch(line, "Ticket Flags", ref ticket.TicketFlags);
                SetIfMatch(line, "Start Time:", ref ticket.StartTime);
                SetIfMatch(line, "StartTime:", ref ticket.StartTime);
                SetIfMatch(line, "End Time:", ref ticket.EndTime);
                SetIfMatch(line, "EndTime:", ref ticket.EndTime);
                SetIfMatch(line, "Renew Time:", ref ticket.RenewTime);
                SetIfMatch(line, "RenewUntil:", ref ticket.RenewTime);
                SetIfMatch(line, "TimeSkew:", ref ticket.TimeSkew);
            }

            return ticket;
        }

        internal static bool IsLegacyEncryption(string value)
        {
            string text = value ?? String.Empty;
            return text.IndexOf("RC4", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   text.IndexOf("DES", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        internal static string ToText(KerberosDeepResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Kerberos Deep Analyzer");
            sb.AppendLine("======================");
            sb.AppendLine("Domain: " + First(result.Domain, "(none)"));
            sb.AppendLine("DC:     " + First(result.Dc, "(none)"));

            if (!String.IsNullOrWhiteSpace(result.KdcBindings))
            {
                sb.AppendLine();
                sb.AppendLine("KDC bindings:");
                sb.AppendLine(result.KdcBindings);
            }

            foreach (KerberosTicketDetails ticket in result.Tickets)
            {
                sb.AppendLine();
                sb.AppendLine(ticket.Label + ": " + First(ticket.Status, "(not tested)"));
                if (!String.IsNullOrWhiteSpace(ticket.Client)) sb.AppendLine("  Client:       " + ticket.Client);
                if (!String.IsNullOrWhiteSpace(ticket.Server)) sb.AppendLine("  Server:       " + ticket.Server);
                if (!String.IsNullOrWhiteSpace(ticket.Domain)) sb.AppendLine("  Domain:       " + ticket.Domain);
                if (!String.IsNullOrWhiteSpace(ticket.EncryptionType)) sb.AppendLine("  Ticket enc:   " + ticket.EncryptionType);
                if (!String.IsNullOrWhiteSpace(ticket.SessionKeyType)) sb.AppendLine("  Session key:  " + ticket.SessionKeyType);
                if (!String.IsNullOrWhiteSpace(ticket.TicketFlags)) sb.AppendLine("  Flags:        " + ticket.TicketFlags);
                if (!String.IsNullOrWhiteSpace(ticket.StartTime)) sb.AppendLine("  Start:        " + ticket.StartTime);
                if (!String.IsNullOrWhiteSpace(ticket.EndTime)) sb.AppendLine("  End:          " + ticket.EndTime);
                if (!String.IsNullOrWhiteSpace(ticket.RenewTime)) sb.AppendLine("  Renew:        " + ticket.RenewTime);
                if (!String.IsNullOrWhiteSpace(ticket.TimeSkew)) sb.AppendLine("  Time skew:    " + ticket.TimeSkew);
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

        private static KerberosTicketDetails ParseTicketOutput(string label, CommandResult command)
        {
            if (command == null)
            {
                KerberosTicketDetails missing = new KerberosTicketDetails();
                missing.Label = label;
                missing.Status = "NOT TESTED";
                return missing;
            }

            if (!String.IsNullOrWhiteSpace(command.Error))
            {
                KerberosTicketDetails error = new KerberosTicketDetails();
                error.Label = label;
                error.Status = "NOT TESTED";
                error.Raw = command.Error;
                return error;
            }

            if (command.Cancelled)
                throw new OperationCanceledException();

            if (command.TimedOut)
            {
                KerberosTicketDetails timeout = new KerberosTicketDetails();
                timeout.Label = label;
                timeout.Status = "FAILED / TIMEOUT";
                timeout.Raw = command.CombinedOutput;
                return timeout;
            }

            KerberosTicketDetails parsed = ParseTicketText(label, command.CombinedOutput);
            if (command.ExitCode != 0)
                parsed.Status = "FAILED";
            return parsed;
        }

        private static void AnalyzeFindings(KerberosDeepResult result)
        {
            foreach (KerberosTicketDetails ticket in result.Tickets)
            {
                if (ticket.Status.StartsWith("FAILED", StringComparison.OrdinalIgnoreCase))
                {
                    string severity = String.Equals(ticket.Label, "TGT", StringComparison.OrdinalIgnoreCase)
                        ? "HIGH"
                        : "CHECK";
                    result.Findings.Add(
                        severity + ": Kerberos ticket acquisition failed for " + ticket.Label + ".");
                }

                if (IsLegacyEncryption(ticket.EncryptionType) ||
                    IsLegacyEncryption(ticket.SessionKeyType))
                {
                    result.Findings.Add(
                        "MEDIUM: " + ticket.Label +
                        " uses legacy Kerberos encryption (" +
                        First(ticket.EncryptionType, ticket.SessionKeyType) + ").");
                }

                if (!String.IsNullOrWhiteSpace(ticket.TimeSkew) &&
                    ticket.TimeSkew.IndexOf("0:00:00", StringComparison.OrdinalIgnoreCase) < 0)
                {
                    result.Findings.Add(
                        "INFO: TGT reports KDC time skew: " + ticket.TimeSkew + ".");
                }
            }

            KerberosTicketDetails cifs = Find(result, "CIFS/");
            KerberosTicketDetails ldap = Find(result, "LDAP/");
            if (cifs != null && ldap != null &&
                cifs.Status.StartsWith("FAILED", StringComparison.OrdinalIgnoreCase) &&
                String.Equals(ldap.Status, "OK", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add(
                    "CHECK: LDAP Kerberos succeeds while CIFS Kerberos fails. Check CIFS SPN visibility and SMB name usage.");
            }
        }

        private static KerberosTicketDetails Find(KerberosDeepResult result, string prefix)
        {
            foreach (KerberosTicketDetails ticket in result.Tickets)
            {
                if ((ticket.Label ?? String.Empty).StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    return ticket;
            }
            return null;
        }

        private static void SetIfMatch(string line, string name, ref string target)
        {
            if (!line.StartsWith(name, StringComparison.OrdinalIgnoreCase))
                return;

            int colon = line.IndexOf(':');
            if (colon >= 0 && colon < line.Length - 1)
                target = line.Substring(colon + 1).Trim();
            else if (line.Length > name.Length)
                target = line.Substring(name.Length).Trim().TrimStart(':').Trim();
        }

        private static void Report(Action<string> progress, string text)
        {
            if (progress != null)
                progress(text);
        }

        private static string Collapse(string value, int max)
        {
            string text = (value ?? String.Empty).Replace("\r", " ").Replace("\n", " ").Trim();
            while (text.Contains("  "))
                text = text.Replace("  ", " ");
            if (text.Length > max)
                text = text.Substring(0, max) + "...";
            return text;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
