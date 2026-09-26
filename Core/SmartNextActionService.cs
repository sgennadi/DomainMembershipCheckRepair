using System;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class SmartNextActionResult
    {
        internal string Severity = "INFO";
        internal string Title = "No immediate action";
        internal string Action = "Review the full diagnostic report.";
        internal string Rationale = String.Empty;
        internal bool BlockDestructiveRecovery;
    }

    internal static class SmartNextActionService
    {
        internal static SmartNextActionResult Analyze(AdvancedDiagnosticsResult result)
        {
            SmartNextActionResult next = new SmartNextActionResult();
            if (result == null || result.Snapshot == null)
            {
                next.Severity = "CHECK";
                next.Title = "Run diagnostics first";
                next.Action = "Run Advanced Diagnostics before applying recovery actions.";
                return next;
            }

            DiagnosticsSnapshot snapshot = result.Snapshot;

            if (snapshot.PendingRename)
                return Create("HIGH", "Restart before any domain recovery",
                    "Restart Windows, then re-run diagnostics.",
                    "A computer rename is pending; further join/rejoin changes can create inconsistent machine identity.",
                    true);

            if (result.Dns != null && HasHigh(result.Dns.Findings))
                return Create("HIGH", "Fix AD DNS / DC Locator first",
                    "Correct DNS/DC Locator and re-run diagnostics before repair or rejoin.",
                    FirstHigh(result.Dns.Findings), true);

            if (snapshot.Health != null &&
                snapshot.Health.DcTimeSkewSeconds.HasValue &&
                Math.Abs(snapshot.Health.DcTimeSkewSeconds.Value) >= 300.0)
            {
                return Create("HIGH", "Correct time synchronization first",
                    "Correct client/DC time, then re-test Kerberos and trust.",
                    "Kerberos clock skew is " + snapshot.Health.DcTimeSkewSeconds.Value.ToString("0.0") + " seconds.",
                    true);
            }

            if (result.RpcEndpoints != null && HasHigh(result.RpcEndpoints.Findings))
                return Create("HIGH", "Fix dynamic RPC connectivity",
                    "Allow the required dynamic RPC endpoint(s), then re-run protocol diagnostics.",
                    FirstHigh(result.RpcEndpoints.Findings), true);

            if (result.ReplicationTimeline != null && HasHigh(result.ReplicationTimeline.Findings))
                return Create("HIGH", "Wait for or repair AD replication",
                    "Resolve the replication version mismatch before trust repair or computer-object deletion.",
                    FirstHigh(result.ReplicationTimeline.Findings), true);

            if (result.IdentityConsistency != null && HasHigh(result.IdentityConsistency.Findings))
                return Create("HIGH", "Resolve duplicate computer identity",
                    "Identify the authoritative AD computer object and remove/correct conflicting identity keys only after replication is healthy.",
                    FirstHigh(result.IdentityConsistency.Findings), true);

            if (result.SpnCollisions != null && HasHigh(result.SpnCollisions.Findings))
                return Create("HIGH", "Resolve duplicate SPNs",
                    "Correct duplicate SPN registrations and allow replication to converge before retrying Kerberos.",
                    FirstHigh(result.SpnCollisions.Findings), true);

            if (result.LdapCompatibility != null && HasHigh(result.LdapCompatibility.Findings))
                return Create("HIGH", "Fix LDAP authentication compatibility",
                    "Resolve the failed signed LDAP/LDAPS bind before domain recovery.",
                    FirstHigh(result.LdapCompatibility.Findings), true);

            if (result.KerberosDeep != null && HasHigh(result.KerberosDeep.Findings))
                return Create("HIGH", "Fix Kerberos ticket acquisition",
                    "Correct KDC/SPN/DNS/time/encryption issues, then re-test the secure channel.",
                    FirstHigh(result.KerberosDeep.Findings), true);

            if (snapshot.SecureChannelApplicable && !snapshot.SecureChannelHealthy)
                return Create("MEDIUM", "Run Safe Fixes, then Repair Trust",
                    "Run Safe Fixes and re-check trust. If prerequisites remain healthy, attempt native Repair Trust before Join/Rejoin.",
                    "The workstation is domain joined but its secure channel is broken.",
                    false);

            if (result.RootCauses != null && result.RootCauses.Count > 0)
            {
                RootCauseFinding finding = result.RootCauses[0];
                return Create(
                    finding.Severity,
                    finding.Category,
                    finding.Recommendation,
                    finding.Evidence,
                    String.Equals(finding.Severity, "HIGH", StringComparison.OrdinalIgnoreCase));
            }

            next.Title = "No blocking domain-membership fault detected";
            next.Action = "No destructive recovery is recommended. Keep the current computer object and monitor/re-test if symptoms recur.";
            next.Rationale = "Available diagnostics did not identify a high-priority blocker.";
            return next;
        }

        internal static string ToText(SmartNextActionResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Recommended Next Safe Action");
            sb.AppendLine("============================");
            sb.AppendLine("Severity: " + (result == null ? "CHECK" : result.Severity));
            sb.AppendLine("Title:    " + (result == null ? "Unavailable" : result.Title));
            sb.AppendLine("Action:   " + (result == null ? "Run diagnostics." : result.Action));
            if (result != null && !String.IsNullOrWhiteSpace(result.Rationale))
                sb.AppendLine("Why:      " + result.Rationale);
            sb.AppendLine("Destructive recovery blocked by evidence: " +
                (result != null && result.BlockDestructiveRecovery ? "Yes" : "No"));
            return sb.ToString();
        }

        private static SmartNextActionResult Create(
            string severity,
            string title,
            string action,
            string rationale,
            bool block)
        {
            SmartNextActionResult result = new SmartNextActionResult();
            result.Severity = severity;
            result.Title = title;
            result.Action = action;
            result.Rationale = rationale;
            result.BlockDestructiveRecovery = block;
            return result;
        }

        private static bool HasHigh(System.Collections.Generic.List<string> findings)
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

        private static string FirstHigh(System.Collections.Generic.List<string> findings)
        {
            if (findings == null)
                return String.Empty;
            foreach (string item in findings)
            {
                if ((item ?? String.Empty).StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase))
                    return item;
            }
            return findings.Count > 0 ? findings[0] : String.Empty;
        }
    }
}
