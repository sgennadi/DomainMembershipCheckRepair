using System;
using System.Collections.Generic;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal static class RecoveryPlanService
    {
        internal static List<string> Build(
            DiagnosticsSnapshot snapshot,
            NetSetupAnalysis netSetup,
            DnsDiagnosticsResult dns,
            DcMatrixResult dcMatrix,
            AdComputerAccountInfo account)
        {
            List<string> steps = new List<string>();

            if (snapshot == null)
            {
                steps.Add("Run diagnostics first.");
                return steps;
            }

            if (snapshot.PendingRename)
                steps.Add("1. Restart Windows first because a computer rename is pending.");

            if (snapshot.Health != null &&
                snapshot.Health.MachineIdentityIsolationConfigured == 2 &&
                snapshot.Health.MachineIdentityIsolationSupportedByDfl == false)
                steps.Add("2. Disable unsupported Machine Identity Isolation enforcement through the authoritative policy source, restart, then re-test.");

            if (dns != null && dns.Findings.Count > 0)
                steps.Add("3. Correct AD DNS/DC Locator issues before changing the computer account.");

            if (snapshot.Health != null && snapshot.Health.DcTimeSkewSeconds.HasValue &&
                Math.Abs(snapshot.Health.DcTimeSkewSeconds.Value) >= 300.0)
                steps.Add("4. Correct client/DC time synchronization before Kerberos-based repair.");

            if (snapshot.Health != null && snapshot.Health.NetlogonRunning == false)
                steps.Add("5. Restore the Netlogon service to Running and re-test DC discovery.");

            if (dcMatrix != null && dcMatrix.Notes.Count > 0)
                steps.Add("6. Resolve cross-DC inconsistency/replication before deleting or recreating the computer object.");

            if (snapshot.SecureChannelApplicable && !snapshot.SecureChannelHealthy)
                steps.Add("7. Attempt native secure-channel repair after DNS/time/MII prerequisites are healthy.");

            if (netSetup != null && ContainsFinding(netSetup, "reuse"))
                steps.Add("8. Analyze existing computer-account owner and permissions; account reuse hardening may be blocking rejoin.");

            if (account != null && account.LookupSucceeded && account.Exists)
            {
                steps.Add("9. Reuse/repair the existing computer account when safe. Review owner=" +
                    First(account.Owner, "(unknown)") + ", pwdLastSet=" + First(account.PwdLastSet, "(unknown)") +
                    ", children=" + account.ChildObjectCount + ".");
            }

            if (snapshot.SecureChannelApplicable && !snapshot.SecureChannelHealthy)
                steps.Add("10. If secure-channel repair fails, perform Join/Rejoin with the current name using verified domain credentials.");

            steps.Add("11. Use Rename + Join when the current name cannot safely be reused.");
            steps.Add("12. Delete + Recreate the AD computer object only as a last resort after checking owner, child objects, replication and recovery data.");

            return steps;
        }

        internal static string ToText(List<string> steps)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Recommended Recovery Plan");
            sb.AppendLine("=========================");
            if (steps == null || steps.Count == 0)
            {
                sb.AppendLine("No recovery action is currently recommended.");
                return sb.ToString();
            }
            foreach (string step in steps)
                sb.AppendLine(step);
            return sb.ToString();
        }

        private static bool ContainsFinding(NetSetupAnalysis a, string term)
        {
            foreach (string value in a.Findings)
                if ((value ?? String.Empty).IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            return false;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
