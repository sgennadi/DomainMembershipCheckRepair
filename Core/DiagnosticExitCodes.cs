using System;
using System.Collections.Generic;

namespace DomainMembershipCheckRepair
{
    internal static class DiagnosticExitCodes
    {
        internal const int Success = 0;
        internal const int FindingDetected = 20;
        internal const int NotTested = 21;
        internal const int AccessDenied = 22;
        internal const int Partial = 23;

        internal static string Describe(int code)
        {
            switch (code)
            {
                case Success: return "success";
                case FindingDetected: return "diagnostic finding detected";
                case NotTested: return "not tested or required diagnostic capability unavailable";
                case AccessDenied: return "diagnostic access denied";
                case Partial: return "partial diagnostic result";
                default: return "legacy/application exit code";
            }
        }

        internal static int FromReportText(string report, bool capabilityAvailable)
        {
            if (!capabilityAvailable)
                return NotTested;

            string text = report ?? String.Empty;
            string lower = text.ToLowerInvariant();

            if (lower.IndexOf("high:", StringComparison.Ordinal) >= 0 ||
                lower.IndexOf(": failed", StringComparison.Ordinal) >= 0 ||
                lower.StartsWith("failed", StringComparison.Ordinal))
                return FindingDetected;

            if (lower.IndexOf("access denied", StringComparison.Ordinal) >= 0 ||
                lower.IndexOf("access was denied", StringComparison.Ordinal) >= 0)
                return AccessDenied;

            if (lower.IndexOf("not tested", StringComparison.Ordinal) >= 0 ||
                lower.IndexOf("check:", StringComparison.Ordinal) >= 0 ||
                lower.IndexOf("warn", StringComparison.Ordinal) >= 0 ||
                lower.IndexOf("unavailable", StringComparison.Ordinal) >= 0)
                return Partial;

            return Success;
        }

        internal static int FromFindings(IEnumerable<string> findings, bool capabilityAvailable)
        {
            bool partial = false;
            bool denied = false;

            if (findings != null)
            {
                foreach (string raw in findings)
                {
                    string item = (raw ?? String.Empty).Trim();
                    if (item.Length == 0)
                        continue;

                    if (item.StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase) ||
                        item.StartsWith("MEDIUM:", StringComparison.OrdinalIgnoreCase) ||
                        item.StartsWith("FAILED:", StringComparison.OrdinalIgnoreCase))
                        return FindingDetected;

                    if (item.IndexOf("access denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("access was denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("permission denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("permission was denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("does not have permission", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("insufficient permission", StringComparison.OrdinalIgnoreCase) >= 0)
                        denied = true;

                    if (item.StartsWith("INFO:", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (item.StartsWith("CHECK:", StringComparison.OrdinalIgnoreCase) ||
                        item.IndexOf("not tested", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("unavailable", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("could not", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("unable to", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        partial = true;
                        continue;
                    }

                    // A non-INFO finding without an explicit severity is still evidence
                    // that the diagnostic did not complete with a clean result.
                    partial = true;
                }
            }

            if (denied)
                return AccessDenied;
            if (!capabilityAvailable)
                return NotTested;
            return partial ? Partial : Success;
        }
    }
}
