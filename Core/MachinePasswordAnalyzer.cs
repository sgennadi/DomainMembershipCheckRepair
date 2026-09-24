using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class MachinePasswordAnalysis
    {
        internal string AdPwdLastSet = String.Empty;
        internal DateTime? LatestLocalPasswordChangeEvent;
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class MachinePasswordAnalyzer
    {
        internal static MachinePasswordAnalysis Analyze(
            AdComputerAccountInfo account,
            List<EventTimelineEntry> events,
            bool secureChannelBroken)
        {
            MachinePasswordAnalysis result = new MachinePasswordAnalysis();
            if (account != null)
                result.AdPwdLastSet = account.PwdLastSet ?? String.Empty;

            if (events != null)
            {
                foreach (EventTimelineEntry e in events)
                {
                    if (e.EventId == 5823 &&
                        (result.LatestLocalPasswordChangeEvent == null ||
                         e.Time > result.LatestLocalPasswordChangeEvent.Value))
                    {
                        result.LatestLocalPasswordChangeEvent = e.Time;
                    }
                }
            }

            DateTime adTime;
            bool hasAdTime = DateTime.TryParseExact(
                result.AdPwdLastSet,
                "yyyy-MM-dd HH:mm:ss",
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeLocal,
                out adTime);

            if (hasAdTime && result.LatestLocalPasswordChangeEvent.HasValue)
            {
                TimeSpan delta = result.LatestLocalPasswordChangeEvent.Value - adTime;
                if (delta.TotalMinutes > 10)
                {
                    result.Findings.Add(
                        "CHECK: A recent local Netlogon machine-password change event is newer than the AD pwdLastSet value being read. " +
                        "This can indicate stale DC/replication state or that the account view is not from the DC that processed the change.");
                }
                else
                {
                    result.Findings.Add(
                        "INFO: Local machine-password change history and the visible AD pwdLastSet are not obviously inconsistent.");
                }
            }
            else if (secureChannelBroken && hasAdTime)
            {
                result.Findings.Add(
                    "CHECK: Secure channel is broken. AD pwdLastSet is available, but no recent local 5823 event was retained for direct comparison.");
            }
            else if (secureChannelBroken)
            {
                result.Findings.Add(
                    "CHECK: Secure channel is broken, but machine-password consistency could not be proven from local event history and AD metadata.");
            }

            return result;
        }

        internal static string ToText(MachinePasswordAnalysis r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Machine Password Consistency");
            sb.AppendLine("============================");
            sb.AppendLine("AD pwdLastSet:        " + (String.IsNullOrWhiteSpace(r.AdPwdLastSet) ? "(not available)" : r.AdPwdLastSet));
            sb.AppendLine("Local event 5823:     " +
                (r.LatestLocalPasswordChangeEvent.HasValue
                    ? r.LatestLocalPasswordChangeEvent.Value.ToString("yyyy-MM-dd HH:mm:ss")
                    : "(not found in collected window)"));
            foreach (string finding in r.Findings)
                sb.AppendLine("- " + finding);
            return sb.ToString();
        }
    }
}
