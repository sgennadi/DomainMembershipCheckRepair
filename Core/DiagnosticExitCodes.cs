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

        internal static int FromFindings(IEnumerable<string> findings, bool capabilityAvailable)
        {
            if (!capabilityAvailable)
                return NotTested;

            bool partial = false;
            bool denied = false;

            if (findings != null)
            {
                foreach (string raw in findings)
                {
                    string item = raw ?? String.Empty;
                    if (item.StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase) ||
                        item.StartsWith("FAILED:", StringComparison.OrdinalIgnoreCase))
                        return FindingDetected;

                    if (item.IndexOf("access denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("access was denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("permission", StringComparison.OrdinalIgnoreCase) >= 0)
                        denied = true;

                    if (item.StartsWith("CHECK:", StringComparison.OrdinalIgnoreCase) ||
                        item.IndexOf("not tested", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        item.IndexOf("unavailable", StringComparison.OrdinalIgnoreCase) >= 0)
                        partial = true;
                }
            }

            if (denied)
                return AccessDenied;
            return partial ? Partial : Success;
        }
    }
}
