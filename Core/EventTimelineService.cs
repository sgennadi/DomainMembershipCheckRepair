using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
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
            "Microsoft-Windows-Kerberos/Operational",
            "Microsoft-Windows-DNS-Client/Operational"
        };

        internal static List<EventTimelineEntry> Collect(int hours)
        {
            List<EventTimelineEntry> entries = new List<EventTimelineEntry>();
            int effectiveHours = Math.Max(1, hours);
            long windowMs = (long)TimeSpan.FromHours(effectiveHours).TotalMilliseconds;
            string queryText = "*[System[TimeCreated[timediff(@SystemTime) <= " + windowMs + "]]]";

            foreach (string logName in Logs)
                CollectChannel(logName, queryText, entries);

            entries.Sort(delegate(EventTimelineEntry a, EventTimelineEntry b)
            {
                return a.Time.CompareTo(b.Time);
            });

            if (entries.Count > 250)
                entries.RemoveRange(0, entries.Count - 250);

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

        private static void CollectChannel(
            string logName,
            string queryText,
            List<EventTimelineEntry> entries)
        {
            try
            {
                EventLogQuery query = new EventLogQuery(
                    logName,
                    PathType.LogName,
                    queryText);
                query.ReverseDirection = true;
                query.TolerateQueryErrors = true;

                using (EventLogReader reader = new EventLogReader(query))
                {
                    int inspected = 0;
                    while (inspected < 1000)
                    {
                        using (EventRecord record = reader.ReadEvent())
                        {
                            if (record == null)
                                break;

                            inspected++;

                            string source = record.ProviderName ?? String.Empty;
                            string message = SafeMessage(record);
                            if (!IsRelevant(source, record.Id, message))
                                continue;

                            EventTimelineEntry item = new EventTimelineEntry();
                            item.Time = record.TimeCreated.HasValue
                                ? record.TimeCreated.Value.ToLocalTime()
                                : DateTime.Now;
                            item.Log = logName;
                            item.Source = source;
                            item.EventId = record.Id;
                            item.Level = FirstNonEmpty(
                                record.LevelDisplayName,
                                record.Level.HasValue ? record.Level.Value.ToString() : "(unknown)");
                            item.Message = Collapse(message, 900);
                            entries.Add(item);

                            if (entries.Count >= 350)
                                return;
                        }
                    }
                }
            }
            catch
            {
                // Missing/disabled operational channels must not break diagnostics.
            }
        }

        private static bool IsRelevant(string source, int eventId, string message)
        {
            string s = (source ?? String.Empty).ToLowerInvariant();
            string m = (message ?? String.Empty).ToLowerInvariant();

            if (s.Contains("netlogon") ||
                s.Contains("kerberos") ||
                s.Contains("lsasrv") ||
                s.Contains("time-service") ||
                s.Contains("w32time") ||
                s.Contains("dns") ||
                s.Contains("deviceguard"))
                return true;

            switch (eventId)
            {
                case 3210:
                case 5719:
                case 5722:
                case 5805:
                case 5823:
                case 40960:
                case 40961:
                    return true;
            }

            return m.Contains("trust relationship") ||
                   m.Contains("secure channel") ||
                   m.Contains("domain controller") ||
                   m.Contains("machine account") ||
                   m.Contains("credential guard") ||
                   m.Contains("machine identity");
        }

        private static string SafeMessage(EventRecord record)
        {
            try
            {
                return record.FormatDescription() ?? String.Empty;
            }
            catch
            {
                return "(event message text is unavailable on this computer)";
            }
        }

        private static string Collapse(string value, int max)
        {
            string text = (value ?? String.Empty)
                .Replace("\r", " ")
                .Replace("\n", " ")
                .Trim();

            while (text.Contains("  "))
                text = text.Replace("  ", " ");

            if (text.Length > max)
                text = text.Substring(0, max) + "...";

            return text;
        }

        private static string FirstNonEmpty(string first, string second)
        {
            return !String.IsNullOrWhiteSpace(first) ? first : (second ?? String.Empty);
        }
    }
}
