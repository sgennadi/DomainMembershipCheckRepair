using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class DeleteSafetyResult
    {
        internal bool Allowed = true;
        internal DcMatrixResult DcMatrix;
        internal readonly List<string> BlockingReasons = new List<string>();
        internal readonly List<string> Warnings = new List<string>();
    }

    internal static class DeleteSafetyAnalyzer
    {
        internal static DeleteSafetyResult Analyze(
            string domain,
            string preferredDc,
            string computerName,
            string user,
            string password,
            AdComputerAccountInfo account)
        {
            DeleteSafetyResult r = new DeleteSafetyResult();

            if (account == null || !account.LookupSucceeded || !account.Exists)
            {
                Block(r, "The AD computer object was not located reliably.");
                return r;
            }

            if (String.IsNullOrWhiteSpace(account.ObjectGuid))
                Block(r, "The computer object's GUID was not returned. Identity cannot be verified safely.");

            if (String.IsNullOrWhiteSpace(account.Owner))
                Block(r, "The computer object's owner was not returned. Account-reuse/deletion safety cannot be assessed.");

            if (account.ChildObjectCount > 0)
            {
                Block(
                    r,
                    "The computer object has " + account.ChildObjectCount +
                    " child object(s). Delete is blocked to avoid removing recovery/management data.");
            }

            DateTime changed;
            if (TryParseAdDisplayTime(account.WhenChanged, out changed))
            {
                TimeSpan age = DateTime.Now - changed;
                if (age.TotalMinutes >= 0 && age.TotalMinutes < 15)
                {
                    Block(
                        r,
                        "The computer object changed only " +
                        Math.Max(0, (int)Math.Round(age.TotalMinutes)) +
                        " minute(s) ago. Wait for replication and re-run diagnostics before deletion.");
                }
                else if (age.TotalMinutes >= 0 && age.TotalMinutes < 60)
                {
                    r.Warnings.Add(
                        "The computer object changed within the last hour. Confirm replication is complete.");
                }
            }
            else
            {
                r.Warnings.Add("whenChanged could not be parsed; recent-object-change protection is limited.");
            }

            r.DcMatrix = DcMatrixService.Analyze(
                domain,
                preferredDc,
                computerName,
                user,
                password);

            if (r.DcMatrix == null || r.DcMatrix.Entries.Count == 0)
            {
                Block(r, "No DC Matrix entries were available. Cross-DC state cannot be verified.");
                return r;
            }

            bool writableHealthyDc = false;
            foreach (DcMatrixEntry dc in r.DcMatrix.Entries)
            {
                if (dc.IsReadOnly != true && dc.RootDseOk && dc.IsSynchronized != false)
                    writableHealthyDc = true;

                if (dc.ComputerAccountExists.HasValue && dc.ComputerAccountExists.Value)
                {
                    if (!String.IsNullOrWhiteSpace(dc.ComputerObjectGuid) &&
                        !String.IsNullOrWhiteSpace(account.ObjectGuid) &&
                        !String.Equals(
                            dc.ComputerObjectGuid,
                            account.ObjectGuid,
                            StringComparison.OrdinalIgnoreCase))
                    {
                        Block(
                            r,
                            "DC " + dc.Host +
                            " reports a different objectGUID for the computer account.");
                    }
                }
            }

            if (!writableHealthyDc)
                Block(r, "No writable, synchronized DC was verified for destructive recovery.");

            string selected = DomainValidation.NormalizeDirectoryServer(preferredDc);
            if (!String.IsNullOrWhiteSpace(selected))
            {
                foreach (DcMatrixEntry dc in r.DcMatrix.Entries)
                {
                    if (String.Equals(
                        DomainValidation.NormalizeDirectoryServer(dc.Host),
                        selected,
                        StringComparison.OrdinalIgnoreCase) &&
                        dc.IsReadOnly == true)
                    {
                        Block(r, "The selected/preferred DC is an RODC. Destructive recovery requires a writable DC.");
                    }
                }
            }

            foreach (string note in r.DcMatrix.Notes)
            {
                string text = note ?? String.Empty;
                if (text.IndexOf("replication", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("missing on others", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    text.IndexOf("differs between DCs", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Block(r, "DC Matrix reports replication/cross-DC inconsistency: " + text);
                }
            }

            if (r.DcMatrix.Entries.Count < 2)
            {
                r.Warnings.Add(
                    "Only one DC was available for verification. Cross-DC replication consistency could not be independently confirmed.");
            }

            r.Allowed = r.BlockingReasons.Count == 0;
            return r;
        }

        internal static string ToText(DeleteSafetyResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Destructive AD Delete Safety Gate");
            sb.AppendLine("=================================");
            sb.AppendLine("Delete allowed: " + (r != null && r.Allowed ? "YES" : "NO"));

            if (r == null)
                return sb.ToString();

            if (r.BlockingReasons.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("BLOCKING reasons:");
                foreach (string reason in r.BlockingReasons)
                    sb.AppendLine("- " + reason);
            }

            if (r.Warnings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Warnings:");
                foreach (string warning in r.Warnings)
                    sb.AppendLine("- " + warning);
            }

            if (r.DcMatrix != null)
            {
                sb.AppendLine();
                sb.AppendLine(DcMatrixService.ToText(r.DcMatrix));
            }

            return sb.ToString();
        }

        private static void Block(DeleteSafetyResult r, string reason)
        {
            r.Allowed = false;
            if (!r.BlockingReasons.Contains(reason))
                r.BlockingReasons.Add(reason);
        }

        private static bool TryParseAdDisplayTime(string value, out DateTime result)
        {
            return DateTime.TryParseExact(
                value ?? String.Empty,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out result);
        }
    }
}
