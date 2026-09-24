using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class EventTimelineEntry
    {
        internal DateTime Time;
        internal string Log = String.Empty;
        internal string Source = String.Empty;
        internal int EventId;
        internal string Level = String.Empty;
        internal string Message = String.Empty;
    }

    internal static class EventTimelineService
    {
        private static readonly string[] Logs = new string[]
        {
            "System",
            "Microsoft-Windows-DeviceGuard/Operational",
            "Microsoft-Windows-Kerberos/Operational"
        };

        internal static List<EventTimelineEntry> Collect(int hours)
        {
            List<EventTimelineEntry> entries = new List<EventTimelineEntry>();
            DateTime cutoff = DateTime.Now.AddHours(-Math.Max(1, hours));

            foreach (string logName in Logs)
            {
                try
                {
                    using (EventLog log = new EventLog(logName))
                    {
                        int start = Math.Max(0, log.Entries.Count - 1000);
                        for (int i = log.Entries.Count - 1; i >= start; i--)
                        {
                            EventLogEntry e = log.Entries[i];
                            if (e.TimeGenerated < cutoff)
                                break;

                            string source = e.Source ?? String.Empty;
                            string message = SafeMessage(e);
                            if (!IsRelevant(source, e.InstanceId, message))
                                continue;

                            EventTimelineEntry item = new EventTimelineEntry();
                            item.Time = e.TimeGenerated;
                            item.Log = logName;
                            item.Source = source;
                            item.EventId = unchecked((int)e.InstanceId);
                            item.Level = e.EntryType.ToString();
                            item.Message = Collapse(message, 600);
                            entries.Add(item);

                            if (entries.Count >= 150)
                                break;
                        }
                    }
                }
                catch
                {
                }
            }

            entries.Sort(delegate(EventTimelineEntry a, EventTimelineEntry b)
            {
                return a.Time.CompareTo(b.Time);
            });
            return entries;
        }

        internal static string ToText(List<EventTimelineEntry> entries)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Windows event timeline");
            sb.AppendLine("----------------------");

            if (entries == null || entries.Count == 0)
            {
                sb.AppendLine("No relevant recent events were collected.");
                return sb.ToString();
            }

            foreach (EventTimelineEntry e in entries)
            {
                sb.AppendLine(
                    e.Time.ToString("yyyy-MM-dd HH:mm:ss") + " | " +
                    e.Log + " | " + e.Source + " | " + e.EventId + " | " + e.Level);
                sb.AppendLine("  " + e.Message);
            }
            return sb.ToString();
        }

        private static bool IsRelevant(string source, long id, string message)
        {
            string s = (source ?? String.Empty).ToLowerInvariant();
            string m = (message ?? String.Empty).ToLowerInvariant();

            if (s.Contains("netlogon") || s.Contains("kerberos") || s.Contains("lsasrv") ||
                s.Contains("time-service") || s.Contains("dns") || s.Contains("deviceguard"))
                return true;

            int eventId = unchecked((int)id);
            if (eventId == 3210 || eventId == 5719 || eventId == 5722 || eventId == 5805 ||
                eventId == 5823 || eventId == 40960 || eventId == 40961)
                return true;

            return m.Contains("trust relationship") || m.Contains("secure channel") ||
                   m.Contains("domain controller") || m.Contains("machine account");
        }

        private static string SafeMessage(EventLogEntry entry)
        {
            try { return entry.Message ?? String.Empty; }
            catch { return String.Empty; }
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
    }
}
