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
            SiteSubnetDiagnosticsResult siteSubnet,
            ProtocolDiagnosticsResult protocols,
            HardeningDiagnosticsResult hardening,
            JoinPermissionsResult joinPermissions,
            HybridEntraDiagnosticsResult hybridEntra,
            PolicySourceDiagnosticsResult policySources,
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

            if (policySources != null && HasHighFinding(policySources.Findings))
            {
                AddStep(
                    steps,
                    "Resolve the authoritative GPO/MDM policy conflict before applying local registry fixes that can be overwritten.");
            }

            if (dns != null && dns.Findings.Count > 0)
                AddStep(steps, "Correct AD DNS/DC Locator and local host-record issues before changing the computer account.");

            if (siteSubnet != null && siteSubnet.Findings.Count > 0)
            {
                AddStep(
                    steps,
                    "Correct AD Site/Subnet mapping or non-local DC selection if the Site/Subnet analyzer reports a mismatch.");
            }

            if (snapshot.Health != null &&
                snapshot.Health.DcTimeSkewSeconds.HasValue &&
                Math.Abs(snapshot.Health.DcTimeSkewSeconds.Value) >= 300.0)
            {
                AddStep(steps, "Correct client/DC time synchronization before Kerberos-based repair.");
            }

            if (snapshot.Health != null && snapshot.Health.NetlogonRunning == false)
                AddStep(steps, "Restore the Netlogon service to Running and re-test DC discovery.");

            if (protocols != null && HasFailedProtocol(protocols))
            {
                AddStep(
                    steps,
                    "Resolve failed protocol-level tests (DNS UDP, LDAP/LDAPS, Kerberos, RPC or SMB) before destructive AD recovery.");
            }

            if (hardening != null && HasHighFinding(hardening.Findings))
            {
                AddStep(
                    steps,
                    "Resolve LDAP/Kerberos/Netlogon hardening incompatibility before retrying Join/Rejoin.");
            }

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

            if (joinPermissions != null && joinPermissions.Findings.Count > 0)
            {
                AddStep(
                    steps,
                    "Review Join Permissions evidence: MachineAccountQuota, target-container ACLs, owner and reuse rights.");
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

            if (hybridEntra != null &&
                hybridEntra.Findings.Count > 0 &&
                snapshot.SecureChannelApplicable &&
                snapshot.SecureChannelHealthy)
            {
                AddStep(
                    steps,
                    "After on-prem AD trust is healthy, remediate Microsoft Entra hybrid join/device authentication if dsregcmd still reports a problem.");
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

        private static bool HasFailedProtocol(ProtocolDiagnosticsResult protocols)
        {
            foreach (ProtocolCheckResult check in protocols.Checks)
            {
                if (String.Equals(check.Status, "FAILED", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static bool HasHighFinding(List<string> findings)
        {
            if (findings == null)
                return false;

            foreach (string item in findings)
            {
                if ((item ?? String.Empty).StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase))
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
