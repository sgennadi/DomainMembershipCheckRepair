using System;
using System.Collections.Generic;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class RootCauseFinding
    {
        internal int Priority;
        internal string Severity = String.Empty;
        internal string Category = String.Empty;
        internal string Evidence = String.Empty;
        internal string Recommendation = String.Empty;
    }

    internal static class RootCauseEngine
    {
        internal static List<RootCauseFinding> Analyze(
            DiagnosticsSnapshot snapshot,
            NetSetupAnalysis netSetup,
            DnsDiagnosticsResult dns,
            DcMatrixResult matrix,
            SiteSubnetDiagnosticsResult siteSubnet,
            ProtocolDiagnosticsResult protocols,
            AdComputerAccountInfo account,
            MachinePasswordAnalysis machinePassword,
            HardeningDiagnosticsResult hardening,
            JoinPermissionsResult joinPermissions,
            HybridEntraDiagnosticsResult hybridEntra,
            PolicySourceDiagnosticsResult policySources,
            ReplicationMetadataResult replicationMetadata,
            SpnCollisionResult spnCollisions,
            SmbKerberosAuthResult smbKerberos)
        {
            List<RootCauseFinding> findings = new List<RootCauseFinding>();

            if (snapshot == null)
                return findings;

            if (snapshot.PendingRename)
            {
                Add(findings, 100, "HIGH", "Pending restart / rename",
                    "Windows has a pending computer rename.",
                    "Restart Windows before attempting Join/Rejoin.");
            }

            if (snapshot.Health != null)
            {
                HealthDiagnosticsSnapshot h = snapshot.Health;

                if (h.MachineIdentityIsolationConfigured == 2 &&
                    h.MachineIdentityIsolationSupportedByDfl == false)
                {
                    Add(findings, 99, "HIGH", "Machine Identity Isolation",
                        "MII Enforcement is enabled and the detected domain functional level is below Windows Server 2025.",
                        "Correct the authoritative MII policy, restart, then re-test trust before rejoining.");
                }

                if (h.DcTimeSkewSeconds.HasValue &&
                    Math.Abs(h.DcTimeSkewSeconds.Value) >= 300.0)
                {
                    Add(findings, 96, "HIGH", "Kerberos / time synchronization",
                        "Client/DC clock skew is " + h.DcTimeSkewSeconds.Value.ToString("0.0") + " seconds.",
                        "Correct time synchronization before trust repair or domain join.");
                }

                if (h.NetlogonRunning == false)
                {
                    Add(findings, 95, "HIGH", "Netlogon service",
                        "The Netlogon service is not running.",
                        "Start/restart Netlogon and force DC rediscovery.");
                }

                if (!String.IsNullOrWhiteSpace(h.DcPortStatus) &&
                    h.DcPortStatus.IndexOf("FAIL", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    Add(findings, 94, "HIGH", "DC network connectivity",
                        "One or more required TCP checks to the selected DC failed: " + h.DcPortStatus,
                        "Check firewall, VPN, routing, TCP 53/88/135/389/445 and the dynamic RPC range.");
                }
            }

            if (snapshot.DiscoveryAttempted && !snapshot.DiscoverySucceeded)
            {
                Add(findings, 98, "HIGH", "DC Locator / DNS",
                    "Domain controller discovery failed: " + NativeMethods.FormatError(snapshot.DiscoveryStatus),
                    "Correct AD DNS, SRV records, VPN/routing and DC reachability before changing the computer account.");
            }

            if (dns != null)
            {
                foreach (string item in dns.Findings)
                {
                    string text = item ?? String.Empty;
                    int priority = text.StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase) ? 97 : 82;
                    string severity = priority >= 90 ? "HIGH" : "MEDIUM";
                    Add(findings, priority, severity, "DNS / host records", text,
                        "Correct DNS/DC Locator or stale host-record issues and re-run diagnostics.");
                }
            }

            if (matrix != null)
            {
                foreach (DcMatrixEntry dc in matrix.Entries)
                {
                    if (dc.IsReadOnly == true)
                    {
                        Add(findings, 88, "MEDIUM", "Read-only domain controller",
                            dc.Host + " is an RODC.",
                            "Ensure Join/Rejoin and computer-account changes can reach a writable DC.");
                    }

                    if (dc.IsSynchronized == false)
                    {
                        Add(findings, 93, "HIGH", "AD replication / DC synchronization",
                            dc.Host + " reports isSynchronized=FALSE.",
                            "Resolve DC synchronization/replication before destructive account recovery.");
                    }
                }

                foreach (string note in matrix.Notes)
                {
                    if ((note ?? String.Empty).IndexOf("replication", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        (note ?? String.Empty).IndexOf("missing on others", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Add(findings, 92, "HIGH", "AD replication inconsistency", note,
                            "Wait for or repair replication and compare the computer object across DCs before Delete + Recreate.");
                    }
                }
            }

            if (netSetup != null)
            {
                foreach (string item in netSetup.Findings)
                {
                    string text = item ?? String.Empty;
                    if (text.IndexOf("reuse", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        text.IndexOf("owner", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Add(findings, 91, "HIGH", "Computer account reuse hardening", text,
                            "Review object owner, OU delegation and account-reuse policy before deleting the existing account.");
                    }
                    else if (text.IndexOf("RPC", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Add(findings, 90, "HIGH", "RPC connectivity", text,
                            "Validate endpoint mapper and dynamic RPC connectivity to a writable DC.");
                    }
                    else if (text.IndexOf("credential", StringComparison.OrdinalIgnoreCase) >= 0 ||
                             text.IndexOf("logon", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Add(findings, 86, "MEDIUM", "Domain credentials", text,
                            "Verify the supplied account, UPN/NetBIOS format and join/reuse permissions.");
                    }
                }
            }

            if (account != null && account.LookupSucceeded && account.Exists)
            {
                if (account.Enabled == false)
                {
                    Add(findings, 89, "HIGH", "Disabled computer account",
                        "The existing AD computer account is disabled.",
                        "Enable or intentionally replace the account after confirming ownership, replication and recovery data.");
                }

                if (account.ChildObjectCount > 0)
                {
                    Add(findings, 40, "INFO", "Deletion risk",
                        "The computer object has " + account.ChildObjectCount + " child object(s).",
                        "Treat Delete + Recreate as a last resort because child recovery data can be removed.");
                }
            }

            if (machinePassword != null && machinePassword.Findings.Count > 0)
            {
                foreach (string item in machinePassword.Findings)
                {
                    if ((item ?? String.Empty).StartsWith("CHECK:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(findings, 79, "MEDIUM", "Machine-account password / stale DC view", item,
                            "Compare pwdLastSet across writable DCs and retry secure-channel repair only after replication/DNS/time are healthy.");
                    }
                }
            }

            if (siteSubnet != null)
            {
                foreach (string item in siteSubnet.Findings)
                {
                    string text = item ?? String.Empty;
                    int priority = text.StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase) ? 93 : 78;
                    Add(
                        findings,
                        priority,
                        priority >= 90 ? "HIGH" : "MEDIUM",
                        "AD Site / Subnet",
                        text,
                        "Correct AD Sites and Services subnet mapping or DC Locator site selection, then re-run diagnostics.");
                }
            }

            if (protocols != null)
            {
                foreach (ProtocolCheckResult check in protocols.Checks)
                {
                    if (String.Equals(check.Status, "FAILED", StringComparison.OrdinalIgnoreCase))
                    {
                        int priority = check.Name.IndexOf("DNS", StringComparison.OrdinalIgnoreCase) >= 0 ? 97 : 91;
                        Add(
                            findings,
                            priority,
                            "HIGH",
                            "Protocol failure: " + check.Name,
                            check.Details,
                            "Resolve this application-level protocol failure before destructive AD recovery.");
                    }
                }
            }

            if (hardening != null)
            {
                foreach (string item in hardening.Findings)
                {
                    string text = item ?? String.Empty;
                    if (text.StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(
                            findings,
                            90,
                            "HIGH",
                            "Authentication hardening",
                            text,
                            "Review LDAP/Kerberos/Netlogon hardening compatibility before retrying the join.");
                    }
                    else if (text.StartsWith("CHECK:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(
                            findings,
                            76,
                            "MEDIUM",
                            "Authentication hardening",
                            text,
                            "Confirm the effective hardening policy is intentional and compatible.");
                    }
                }
            }

            if (joinPermissions != null)
            {
                foreach (string item in joinPermissions.Findings)
                {
                    string text = item ?? String.Empty;
                    if (text.IndexOf("reuse", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        text.IndexOf("MachineAccountQuota", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        text.IndexOf("ACL", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        Add(
                            findings,
                            87,
                            "MEDIUM",
                            "Domain join permissions",
                            text,
                            "Review OU delegation, account ownership and account-reuse rights before deleting the computer object.");
                    }
                }
            }

            if (policySources != null)
            {
                foreach (string item in policySources.Findings)
                {
                    string text = item ?? String.Empty;
                    if (text.StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(
                            findings,
                            95,
                            "HIGH",
                            "Policy source conflict",
                            text,
                            "Correct the authoritative GPO/MDM policy source; local registry changes alone can be overwritten.");
                    }
                }
            }

            if (hybridEntra != null)
            {
                foreach (string item in hybridEntra.Findings)
                {
                    if ((item ?? String.Empty).StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(
                            findings,
                            60,
                            "MEDIUM",
                            "Hybrid Microsoft Entra state",
                            item,
                            "Restore on-prem AD trust first, then remediate the Entra device state.");
                    }
                }
            }

            if (replicationMetadata != null)
            {
                foreach (string item in replicationMetadata.Findings)
                {
                    string text = item ?? String.Empty;
                    if (text.StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(findings, 97, "HIGH", "AD replication metadata", text,
                            "Resolve AD replication failures before trust repair, rejoin or destructive computer-account recovery.");
                    }
                    else if (text.StartsWith("CHECK:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(findings, 84, "MEDIUM", "AD replication metadata", text,
                            "Verify object replication metadata on a writable DC before destructive computer-account recovery.");
                    }
                }
            }

            if (spnCollisions != null)
            {
                foreach (string item in spnCollisions.Findings)
                {
                    string text = item ?? String.Empty;
                    if (text.StartsWith("HIGH:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(findings, 99, "HIGH", "SPN collision", text,
                            "Remove or correct duplicate SPN registrations, allow AD replication to converge, then re-test Kerberos and domain trust.");
                    }
                    else if (text.StartsWith("CHECK:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(findings, 88, "MEDIUM", "Computer SPN registration", text,
                            "Restore the expected computer SPNs on the correct AD computer object and re-test Kerberos.");
                    }
                }
            }

            if (smbKerberos != null)
            {
                foreach (string item in smbKerberos.Findings)
                {
                    string text = item ?? String.Empty;
                    if (text.StartsWith("CHECK:", StringComparison.OrdinalIgnoreCase))
                    {
                        Add(findings, 89, "MEDIUM", "Kerberos / SMB authentication", text,
                            "Correct CIFS SPN/DNS/Kerberos issues and confirm whether NTLM fallback is permitted before retrying recovery.");
                    }
                }
            }

            if (snapshot.SecureChannelApplicable && !snapshot.SecureChannelHealthy)
            {
                Add(findings, 70, "MEDIUM", "Machine secure channel",
                    "The workstation is domain joined but the secure channel is broken: " +
                    NativeMethods.FormatError(snapshot.SecureChannelStatus),
                    "Use Safe Fixes, then native trust repair; use Join/Rejoin only if repair does not recover the channel.");
            }

            Deduplicate(findings);
            findings.Sort(delegate(RootCauseFinding a, RootCauseFinding b)
            {
                return b.Priority.CompareTo(a.Priority);
            });

            return findings;
        }

        internal static string ToText(List<RootCauseFinding> findings)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Prioritized root-cause findings");
            sb.AppendLine("===============================");
            sb.AppendLine("These are evidence-based troubleshooting priorities, not probability estimates.");

            if (findings == null || findings.Count == 0)
            {
                sb.AppendLine("No specific root cause was identified from the available evidence.");
                return sb.ToString();
            }

            int number = 1;
            foreach (RootCauseFinding finding in findings)
            {
                sb.AppendLine();
                sb.AppendLine(number + ". [" + finding.Severity + "] " + finding.Category);
                sb.AppendLine("   Evidence: " + finding.Evidence);
                sb.AppendLine("   Next:     " + finding.Recommendation);
                number++;
            }

            return sb.ToString();
        }

        private static void Add(
            List<RootCauseFinding> findings,
            int priority,
            string severity,
            string category,
            string evidence,
            string recommendation)
        {
            RootCauseFinding item = new RootCauseFinding();
            item.Priority = priority;
            item.Severity = severity;
            item.Category = category;
            item.Evidence = evidence;
            item.Recommendation = recommendation;
            findings.Add(item);
        }

        private static void Deduplicate(List<RootCauseFinding> findings)
        {
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (int i = findings.Count - 1; i >= 0; i--)
            {
                string key = findings[i].Category + "|" + findings[i].Evidence;
                if (seen.Contains(key))
                    findings.RemoveAt(i);
                else
                    seen.Add(key);
            }
        }
    }
}
