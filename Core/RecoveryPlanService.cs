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
                AddStep(steps, "Run diagnostics first.");
                return steps;
            }

            if (snapshot.PendingRename)
                AddStep(steps, "Restart Windows first because a computer rename is pending.");

            if (snapshot.Health != null &&
                snapshot.Health.MachineIdentityIsolationConfigured == 2 &&
                snapshot.Health.MachineIdentityIsolationSupportedByDfl == false)
            {
                AddStep(
                    steps,
                    "Disable unsupported Machine Identity Isolation enforcement through the authoritative policy source, restart, then re-test.");
            }

            if (dns != null && dns.Findings.Count > 0)
                AddStep(steps, "Correct AD DNS/DC Locator and local host-record issues before changing the computer account.");

            if (snapshot.Health != null &&
                snapshot.Health.DcTimeSkewSeconds.HasValue &&
                Math.Abs(snapshot.Health.DcTimeSkewSeconds.Value) >= 300.0)
            {
                AddStep(steps, "Correct client/DC time synchronization before Kerberos-based repair.");
            }

            if (snapshot.Health != null && snapshot.Health.NetlogonRunning == false)
                AddStep(steps, "Restore the Netlogon service to Running and re-test DC discovery.");

            if (dcMatrix != null && HasDcMatrixRisk(dcMatrix))
            {
                AddStep(
                    steps,
                    "Resolve DC writability, synchronization or cross-DC replication inconsistency before deleting/recreating the computer object.");
            }

            if (snapshot.SecureChannelApplicable && !snapshot.SecureChannelHealthy)
            {
                AddStep(
                    steps,
                    "Run Safe Fixes (DNS cache flush, time resync, Netlogon restart and forced DC rediscovery), then re-check trust.");
                AddStep(
                    steps,
                    "Attempt native secure-channel repair after DNS/time/MII/DC prerequisites are healthy.");
            }

            if (netSetup != null && ContainsFinding(netSetup, "reuse"))
            {
                AddStep(
                    steps,
                    "Analyze the existing computer-account owner and permissions; account-reuse hardening may be blocking rejoin.");
            }

            if (account != null && account.LookupSucceeded && account.Exists)
            {
                AddStep(
                    steps,
                    "Prefer reusing/repairing the existing computer account when safe. Review owner=" +
                    First(account.Owner, "(unknown)") +
                    ", pwdLastSet=" + First(account.PwdLastSet, "(unknown)") +
                    ", SPNs=" + account.ServicePrincipalNameCount +
                    ", children=" + account.ChildObjectCount + ".");
            }

            if (snapshot.SecureChannelApplicable && !snapshot.SecureChannelHealthy)
            {
                AddStep(
                    steps,
                    "If secure-channel repair still fails, perform Join/Rejoin with the current computer name using verified domain credentials.");
            }

            AddStep(steps, "Use Rename + Join when the current computer name cannot safely be reused.");
            AddStep(
                steps,
                "Delete + Recreate the AD computer object only as a last resort after checking owner, child objects, replication and recovery data.");

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

        private static void AddStep(List<string> steps, string text)
        {
            steps.Add((steps.Count + 1) + ". " + text);
        }

        private static bool HasDcMatrixRisk(DcMatrixResult matrix)
        {
            if (matrix == null)
                return false;

            if (matrix.Notes.Count > 0)
                return true;

            foreach (DcMatrixEntry entry in matrix.Entries)
            {
                if (!entry.RootDseOk ||
                    entry.IsReadOnly == true ||
                    entry.IsSynchronized == false ||
                    entry.Ports.IndexOf("FAIL", StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        private static bool ContainsFinding(NetSetupAnalysis a, string term)
        {
            foreach (string value in a.Findings)
            {
                if ((value ?? String.Empty).IndexOf(term, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
