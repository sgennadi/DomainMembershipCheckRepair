using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace DomainMembershipCheckRepair
{
    [DataContract]
    public sealed class DiagnosticHistoryRecord
    {
        [DataMember] public string Id = String.Empty;
        [DataMember] public string CreatedUtc = String.Empty;
        [DataMember] public string Version = String.Empty;
        [DataMember] public string ComputerName = String.Empty;
        [DataMember] public string Domain = String.Empty;
        [DataMember] public string SecureChannel = String.Empty;
        [DataMember] public string AccountGuid = String.Empty;
        [DataMember] public string AccountPwdLastSet = String.Empty;
        [DataMember] public string NextActionSeverity = String.Empty;
        [DataMember] public string NextActionTitle = String.Empty;
        [DataMember] public List<DiagnosticHistoryDc> Dcs =
            new List<DiagnosticHistoryDc>();
        [DataMember] public List<DiagnosticHistoryKerberos> Kerberos =
            new List<DiagnosticHistoryKerberos>();
        [DataMember] public List<DiagnosticHistorySpn> Spns =
            new List<DiagnosticHistorySpn>();
        [DataMember] public List<DiagnosticHistoryReplication> Replication =
            new List<DiagnosticHistoryReplication>();
        [DataMember] public List<DiagnosticHistoryRootCause> RootCauses =
            new List<DiagnosticHistoryRootCause>();
    }

    [DataContract]
    public sealed class DiagnosticHistoryDc
    {
        [DataMember] public string Host = String.Empty;
        [DataMember] public string RootDse = String.Empty;
        [DataMember] public string Synchronized = String.Empty;
        [DataMember] public string AccountExists = String.Empty;
        [DataMember] public string ObjectGuid = String.Empty;
        [DataMember] public string PwdLastSet = String.Empty;
        [DataMember] public string WhenChanged = String.Empty;
        [DataMember] public string SpnFingerprint = String.Empty;
        [DataMember] public int SpnCollisionCount;
    }

    [DataContract]
    public sealed class DiagnosticHistoryKerberos
    {
        [DataMember] public string Label = String.Empty;
        [DataMember] public string Status = String.Empty;
        [DataMember] public string Server = String.Empty;
        [DataMember] public string Encryption = String.Empty;
        [DataMember] public string SessionKey = String.Empty;
        [DataMember] public string TimeSkew = String.Empty;
    }

    [DataContract]
    public sealed class DiagnosticHistorySpn
    {
        [DataMember] public string Spn = String.Empty;
        [DataMember] public string Owners = String.Empty;
        [DataMember] public int OwnerCount;
    }

    [DataContract]
    public sealed class DiagnosticHistoryReplication
    {
        [DataMember] public string Dc = String.Empty;
        [DataMember] public string Attribute = String.Empty;
        [DataMember] public int Version;
        [DataMember] public string OriginatingDc = String.Empty;
        [DataMember] public string OriginatingUsn = String.Empty;
        [DataMember] public string LastChange = String.Empty;
    }

    [DataContract]
    public sealed class DiagnosticHistoryRootCause
    {
        [DataMember] public string Severity = String.Empty;
        [DataMember] public string Category = String.Empty;
        [DataMember] public string Evidence = String.Empty;
        [DataMember] public string Recommendation = String.Empty;
    }

    internal sealed class DiagnosticHistoryComparison
    {
        internal DiagnosticHistoryRecord Older;
        internal DiagnosticHistoryRecord Newer;
        internal readonly List<string> Changes = new List<string>();
    }

    internal static class DiagnosticHistoryService
    {
        internal static bool TrySave(
            AdvancedDiagnosticsResult advanced,
            out string path,
            out string error)
        {
            path = String.Empty;
            error = String.Empty;

            if (advanced == null || advanced.Snapshot == null)
            {
                error = "Advanced diagnostic result is unavailable.";
                return false;
            }

            try
            {
                DiagnosticHistoryRecord record = CreateRecord(advanced);
                string folder = GetFolder();
                path = Path.Combine(
                    folder,
                    record.Id + "-" +
                    SafeFileName(record.ComputerName) + ".json");

                WriteRecord(path, record);
                Prune(folder, 60);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        internal static DiagnosticHistoryRecord CreateRecord(
            AdvancedDiagnosticsResult advanced)
        {
            DiagnosticHistoryRecord record = new DiagnosticHistoryRecord();
            record.Id =
                DateTime.UtcNow.ToString("yyyyMMdd-HHmmssfff") + "-" +
                Guid.NewGuid().ToString("N").Substring(0, 6);
            record.CreatedUtc = DateTime.UtcNow.ToString("o");
            record.Version = BuildInfo.Version;

            if (advanced == null)
                return record;

            if (advanced.Snapshot != null)
            {
                record.ComputerName =
                    advanced.Snapshot.ComputerName ?? String.Empty;
                record.Domain =
                    advanced.Snapshot.TargetDomain ?? String.Empty;
                record.SecureChannel =
                    !advanced.Snapshot.SecureChannelApplicable
                        ? "NOT APPLICABLE"
                        : (advanced.Snapshot.SecureChannelHealthy
                            ? "OK"
                            : "BROKEN:" +
                              advanced.Snapshot.SecureChannelStatus);
            }

            if (advanced.Account != null)
            {
                record.AccountGuid =
                    advanced.Account.ObjectGuid ?? String.Empty;
                record.AccountPwdLastSet =
                    advanced.Account.PwdLastSet ?? String.Empty;
            }

            if (advanced.NextAction != null)
            {
                record.NextActionSeverity =
                    advanced.NextAction.Severity ?? String.Empty;
                record.NextActionTitle =
                    advanced.NextAction.Title ?? String.Empty;
            }

            if (advanced.DcMatrix != null)
            {
                foreach (DcMatrixEntry entry in advanced.DcMatrix.Entries)
                {
                    DiagnosticHistoryDc item =
                        new DiagnosticHistoryDc();
                    item.Host = entry.Host ?? String.Empty;
                    item.RootDse = entry.RootDseOk ? "OK" : "FAILED";
                    item.Synchronized =
                        entry.IsSynchronized.HasValue
                            ? entry.IsSynchronized.Value.ToString()
                            : String.Empty;
                    item.AccountExists =
                        entry.ComputerAccountExists.HasValue
                            ? entry.ComputerAccountExists.Value.ToString()
                            : String.Empty;
                    item.ObjectGuid =
                        entry.ComputerObjectGuid ?? String.Empty;
                    item.PwdLastSet =
                        entry.ComputerPwdLastSet ?? String.Empty;
                    item.WhenChanged =
                        entry.ComputerWhenChanged ?? String.Empty;
                    item.SpnFingerprint =
                        entry.SpnStateFingerprint ?? String.Empty;
                    item.SpnCollisionCount =
                        entry.SpnCollisionCount;
                    record.Dcs.Add(item);
                }
            }

            if (advanced.KerberosDeep != null)
            {
                foreach (KerberosTicketDetails ticket
                    in advanced.KerberosDeep.Tickets)
                {
                    DiagnosticHistoryKerberos item =
                        new DiagnosticHistoryKerberos();
                    item.Label = ticket.Label ?? String.Empty;
                    item.Status = ticket.Status ?? String.Empty;
                    item.Server = ticket.Server ?? String.Empty;
                    item.Encryption =
                        ticket.EncryptionType ?? String.Empty;
                    item.SessionKey =
                        ticket.SessionKeyType ?? String.Empty;
                    item.TimeSkew =
                        ticket.TimeSkew ?? String.Empty;
                    record.Kerberos.Add(item);
                }
            }

            if (advanced.SpnCollisions != null)
            {
                foreach (SpnCollisionEntry entry
                    in advanced.SpnCollisions.Entries)
                {
                    DiagnosticHistorySpn item =
                        new DiagnosticHistorySpn();
                    item.Spn = entry.Spn ?? String.Empty;

                    List<string> owners =
                        new List<string>(entry.DistinguishedNames);
                    owners.Sort(StringComparer.OrdinalIgnoreCase);
                    item.Owners = String.Join("|", owners.ToArray());
                    item.OwnerCount = owners.Count;
                    record.Spns.Add(item);
                }
            }

            if (advanced.ReplicationTimeline != null)
            {
                foreach (ReplicationTimelineEntry entry
                    in advanced.ReplicationTimeline.Entries)
                {
                    DiagnosticHistoryReplication item =
                        new DiagnosticHistoryReplication();
                    item.Dc = entry.Dc ?? String.Empty;
                    item.Attribute =
                        entry.Attribute ?? String.Empty;
                    item.Version = entry.Version;
                    item.OriginatingDc =
                        entry.OriginatingDc ?? String.Empty;
                    item.OriginatingUsn =
                        entry.OriginatingUsn ?? String.Empty;
                    item.LastChange =
                        entry.LastOriginatingChange ?? String.Empty;
                    record.Replication.Add(item);
                }
            }

            if (advanced.RootCauses != null)
            {
                foreach (RootCauseFinding finding
                    in advanced.RootCauses)
                {
                    DiagnosticHistoryRootCause item =
                        new DiagnosticHistoryRootCause();
                    item.Severity =
                        finding.Severity ?? String.Empty;
                    item.Category =
                        finding.Category ?? String.Empty;
                    item.Evidence =
                        finding.Evidence ?? String.Empty;
                    item.Recommendation =
                        finding.Recommendation ?? String.Empty;
                    record.RootCauses.Add(item);
                }
            }

            return record;
        }

        internal static List<DiagnosticHistoryRecord> ListRecords(int max)
        {
            List<DiagnosticHistoryRecord> result =
                new List<DiagnosticHistoryRecord>();
            string folder = GetFolderPath();
            if (!Directory.Exists(folder))
                return result;

            FileInfo[] files =
                new DirectoryInfo(folder).GetFiles("*.json");
            Array.Sort(files, delegate(FileInfo a, FileInfo b)
            {
                return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc);
            });

            int limit = max <= 0 ? 20 : max;
            foreach (FileInfo file in files)
            {
                if (result.Count >= limit)
                    break;

                try
                {
                    DiagnosticHistoryRecord record =
                        ReadRecord(file.FullName);
                    if (record != null)
                        result.Add(record);
                }
                catch
                {
                }
            }

            return result;
        }

        internal static bool TryCompareLatest(
            out DiagnosticHistoryComparison comparison,
            out string error)
        {
            comparison = null;
            error = String.Empty;

            List<DiagnosticHistoryRecord> records =
                ListRecords(60);

            if (records.Count < 2)
            {
                error =
                    "At least two diagnostic history records are required.";
                return false;
            }

            string computer = records[0].ComputerName;
            DiagnosticHistoryRecord older = null;

            for (int i = 1; i < records.Count; i++)
            {
                if (String.IsNullOrWhiteSpace(computer) ||
                    String.Equals(
                        records[i].ComputerName,
                        computer,
                        StringComparison.OrdinalIgnoreCase))
                {
                    older = records[i];
                    break;
                }
            }

            if (older == null)
            {
                error =
                    "No earlier history record for the current computer was found.";
                return false;
            }

            comparison = Compare(older, records[0]);
            return true;
        }

        internal static DiagnosticHistoryComparison Compare(
            DiagnosticHistoryRecord older,
            DiagnosticHistoryRecord newer)
        {
            DiagnosticHistoryComparison result =
                new DiagnosticHistoryComparison();
            result.Older = older;
            result.Newer = newer;

            if (older == null || newer == null)
            {
                result.Changes.Add(
                    "One of the history records is unavailable.");
                return result;
            }

            AddChange(
                result,
                "Secure channel",
                older.SecureChannel,
                newer.SecureChannel);

            AddChange(
                result,
                "Computer object GUID",
                older.AccountGuid,
                newer.AccountGuid);

            AddChange(
                result,
                "Computer pwdLastSet",
                older.AccountPwdLastSet,
                newer.AccountPwdLastSet);

            AddChange(
                result,
                "Next safe action",
                JoinPair(
                    older.NextActionSeverity,
                    older.NextActionTitle),
                JoinPair(
                    newer.NextActionSeverity,
                    newer.NextActionTitle));

            CompareDcs(result, older.Dcs, newer.Dcs);
            CompareKerberos(
                result,
                older.Kerberos,
                newer.Kerberos);
            CompareSpns(result, older.Spns, newer.Spns);
            CompareReplication(
                result,
                older.Replication,
                newer.Replication);
            CompareRootCauses(
                result,
                older.RootCauses,
                newer.RootCauses);

            if (result.Changes.Count == 0)
                result.Changes.Add(
                    "No tracked diagnostic differences were detected.");

            return result;
        }

        internal static string ToText(
            DiagnosticHistoryComparison comparison)
        {
            if (comparison == null)
                return "No history comparison is available.";

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Diagnostic History Comparison");
            sb.AppendLine("=============================");
            sb.AppendLine(
                "Older: " + Describe(comparison.Older));
            sb.AppendLine(
                "Newer: " + Describe(comparison.Newer));
            sb.AppendLine();
            sb.AppendLine("Changes:");

            foreach (string change in comparison.Changes)
                sb.AppendLine("- " + change);

            return sb.ToString();
        }

        internal static string ListToText(
            List<DiagnosticHistoryRecord> records)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Diagnostic History");
            sb.AppendLine("==================");

            if (records == null || records.Count == 0)
            {
                sb.AppendLine("No diagnostic history records were found.");
                return sb.ToString();
            }

            foreach (DiagnosticHistoryRecord record in records)
            {
                sb.AppendLine();
                sb.AppendLine(Describe(record));
                sb.AppendLine(
                    "  Domain: " +
                    First(record.Domain, "(none)"));
                sb.AppendLine(
                    "  Secure channel: " +
                    First(record.SecureChannel, "(unknown)"));
                sb.AppendLine(
                    "  Account GUID: " +
                    First(record.AccountGuid, "(unknown)"));
                sb.AppendLine(
                    "  Next action: " +
                    First(
                        JoinPair(
                            record.NextActionSeverity,
                            record.NextActionTitle),
                        "(none)"));
            }

            return sb.ToString();
        }

        internal static string GetLatestHistoryPath()
        {
            string folder = GetFolderPath();
            if (!Directory.Exists(folder))
                return String.Empty;

            FileInfo[] files =
                new DirectoryInfo(folder).GetFiles("*.json");
            if (files.Length == 0)
                return String.Empty;

            Array.Sort(files, delegate(FileInfo a, FileInfo b)
            {
                return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc);
            });

            return files[0].FullName;
        }

        private static void CompareDcs(
            DiagnosticHistoryComparison result,
            List<DiagnosticHistoryDc> older,
            List<DiagnosticHistoryDc> newer)
        {
            Dictionary<string, DiagnosticHistoryDc> oldMap =
                MapDcs(older);
            Dictionary<string, DiagnosticHistoryDc> newMap =
                MapDcs(newer);

            foreach (string key in UnionKeys(oldMap, newMap))
            {
                DiagnosticHistoryDc a =
                    oldMap.ContainsKey(key) ? oldMap[key] : null;
                DiagnosticHistoryDc b =
                    newMap.ContainsKey(key) ? newMap[key] : null;

                if (a == null)
                {
                    result.Changes.Add(
                        "DC added: " + key + ".");
                    continue;
                }

                if (b == null)
                {
                    result.Changes.Add(
                        "DC no longer reported: " + key + ".");
                    continue;
                }

                AddChange(
                    result,
                    "DC " + key + " synchronization",
                    a.Synchronized,
                    b.Synchronized);
                AddChange(
                    result,
                    "DC " + key + " computer GUID",
                    a.ObjectGuid,
                    b.ObjectGuid);
                AddChange(
                    result,
                    "DC " + key + " pwdLastSet",
                    a.PwdLastSet,
                    b.PwdLastSet);
                AddChange(
                    result,
                    "DC " + key + " whenChanged",
                    a.WhenChanged,
                    b.WhenChanged);
                AddChange(
                    result,
                    "DC " + key + " SPN state",
                    a.SpnFingerprint,
                    b.SpnFingerprint);

                if (a.SpnCollisionCount != b.SpnCollisionCount)
                {
                    result.Changes.Add(
                        "DC " + key + " SPN collisions: " +
                        a.SpnCollisionCount + " -> " +
                        b.SpnCollisionCount + ".");
                }
            }
        }

        private static void CompareKerberos(
            DiagnosticHistoryComparison result,
            List<DiagnosticHistoryKerberos> older,
            List<DiagnosticHistoryKerberos> newer)
        {
            Dictionary<string, DiagnosticHistoryKerberos> oldMap =
                MapKerberos(older);
            Dictionary<string, DiagnosticHistoryKerberos> newMap =
                MapKerberos(newer);

            foreach (string key in UnionKeys(oldMap, newMap))
            {
                DiagnosticHistoryKerberos a =
                    oldMap.ContainsKey(key) ? oldMap[key] : null;
                DiagnosticHistoryKerberos b =
                    newMap.ContainsKey(key) ? newMap[key] : null;

                if (a == null)
                {
                    result.Changes.Add(
                        "Kerberos ticket added: " + key + ".");
                    continue;
                }

                if (b == null)
                {
                    result.Changes.Add(
                        "Kerberos ticket no longer reported: " +
                        key + ".");
                    continue;
                }

                AddChange(
                    result,
                    "Kerberos " + key + " status",
                    a.Status,
                    b.Status);
                AddChange(
                    result,
                    "Kerberos " + key + " encryption",
                    a.Encryption,
                    b.Encryption);
                AddChange(
                    result,
                    "Kerberos " + key + " session key",
                    a.SessionKey,
                    b.SessionKey);
                AddChange(
                    result,
                    "Kerberos " + key + " server",
                    a.Server,
                    b.Server);
                AddChange(
                    result,
                    "Kerberos " + key + " time skew",
                    a.TimeSkew,
                    b.TimeSkew);
            }
        }

        private static void CompareSpns(
            DiagnosticHistoryComparison result,
            List<DiagnosticHistorySpn> older,
            List<DiagnosticHistorySpn> newer)
        {
            Dictionary<string, DiagnosticHistorySpn> oldMap =
                MapSpns(older);
            Dictionary<string, DiagnosticHistorySpn> newMap =
                MapSpns(newer);

            foreach (string key in UnionKeys(oldMap, newMap))
            {
                DiagnosticHistorySpn a =
                    oldMap.ContainsKey(key) ? oldMap[key] : null;
                DiagnosticHistorySpn b =
                    newMap.ContainsKey(key) ? newMap[key] : null;

                if (a == null)
                {
                    result.Changes.Add(
                        "SPN appeared: " + key +
                        " -> " + b.Owners + ".");
                    continue;
                }

                if (b == null)
                {
                    result.Changes.Add(
                        "SPN disappeared: " + key +
                        " (previous owners: " + a.Owners + ").");
                    continue;
                }

                AddChange(
                    result,
                    "SPN " + key + " owners",
                    a.Owners,
                    b.Owners);
            }
        }

        private static void CompareReplication(
            DiagnosticHistoryComparison result,
            List<DiagnosticHistoryReplication> older,
            List<DiagnosticHistoryReplication> newer)
        {
            Dictionary<string, DiagnosticHistoryReplication> oldMap =
                MapReplication(older);
            Dictionary<string, DiagnosticHistoryReplication> newMap =
                MapReplication(newer);

            foreach (string key in UnionKeys(oldMap, newMap))
            {
                DiagnosticHistoryReplication a =
                    oldMap.ContainsKey(key) ? oldMap[key] : null;
                DiagnosticHistoryReplication b =
                    newMap.ContainsKey(key) ? newMap[key] : null;

                if (a == null)
                {
                    result.Changes.Add(
                        "Replication metadata appeared: " + key +
                        " v" + b.Version + ".");
                    continue;
                }

                if (b == null)
                {
                    result.Changes.Add(
                        "Replication metadata disappeared: " +
                        key + ".");
                    continue;
                }

                if (a.Version != b.Version)
                {
                    result.Changes.Add(
                        "Replication " + key + " version: " +
                        a.Version + " -> " + b.Version + ".");
                }

                AddChange(
                    result,
                    "Replication " + key + " originating DC",
                    a.OriginatingDc,
                    b.OriginatingDc);
                AddChange(
                    result,
                    "Replication " + key + " last change",
                    a.LastChange,
                    b.LastChange);
            }
        }

        private static void CompareRootCauses(
            DiagnosticHistoryComparison result,
            List<DiagnosticHistoryRootCause> older,
            List<DiagnosticHistoryRootCause> newer)
        {
            Dictionary<string, DiagnosticHistoryRootCause> oldMap =
                MapRootCauses(older);
            Dictionary<string, DiagnosticHistoryRootCause> newMap =
                MapRootCauses(newer);

            foreach (string key in UnionKeys(oldMap, newMap))
            {
                if (!oldMap.ContainsKey(key))
                {
                    result.Changes.Add(
                        "Root cause added: " + key + ".");
                }
                else if (!newMap.ContainsKey(key))
                {
                    result.Changes.Add(
                        "Root cause cleared: " + key + ".");
                }
                else
                {
                    AddChange(
                        result,
                        "Root cause " + key + " evidence",
                        oldMap[key].Evidence,
                        newMap[key].Evidence);
                }
            }
        }

        private static Dictionary<string, DiagnosticHistoryDc> MapDcs(
            List<DiagnosticHistoryDc> values)
        {
            Dictionary<string, DiagnosticHistoryDc> result =
                new Dictionary<string, DiagnosticHistoryDc>(
                    StringComparer.OrdinalIgnoreCase);
            if (values == null)
                return result;
            foreach (DiagnosticHistoryDc item in values)
            {
                if (!String.IsNullOrWhiteSpace(item.Host))
                    result[item.Host] = item;
            }
            return result;
        }

        private static Dictionary<string, DiagnosticHistoryKerberos> MapKerberos(
            List<DiagnosticHistoryKerberos> values)
        {
            Dictionary<string, DiagnosticHistoryKerberos> result =
                new Dictionary<string, DiagnosticHistoryKerberos>(
                    StringComparer.OrdinalIgnoreCase);
            if (values == null)
                return result;
            foreach (DiagnosticHistoryKerberos item in values)
            {
                if (!String.IsNullOrWhiteSpace(item.Label))
                    result[item.Label] = item;
            }
            return result;
        }

        private static Dictionary<string, DiagnosticHistorySpn> MapSpns(
            List<DiagnosticHistorySpn> values)
        {
            Dictionary<string, DiagnosticHistorySpn> result =
                new Dictionary<string, DiagnosticHistorySpn>(
                    StringComparer.OrdinalIgnoreCase);
            if (values == null)
                return result;
            foreach (DiagnosticHistorySpn item in values)
            {
                if (!String.IsNullOrWhiteSpace(item.Spn))
                    result[item.Spn] = item;
            }
            return result;
        }

        private static Dictionary<string, DiagnosticHistoryReplication> MapReplication(
            List<DiagnosticHistoryReplication> values)
        {
            Dictionary<string, DiagnosticHistoryReplication> result =
                new Dictionary<string, DiagnosticHistoryReplication>(
                    StringComparer.OrdinalIgnoreCase);
            if (values == null)
                return result;
            foreach (DiagnosticHistoryReplication item in values)
            {
                string key = JoinPair(item.Dc, item.Attribute);
                if (!String.IsNullOrWhiteSpace(key))
                    result[key] = item;
            }
            return result;
        }

        private static Dictionary<string, DiagnosticHistoryRootCause> MapRootCauses(
            List<DiagnosticHistoryRootCause> values)
        {
            Dictionary<string, DiagnosticHistoryRootCause> result =
                new Dictionary<string, DiagnosticHistoryRootCause>(
                    StringComparer.OrdinalIgnoreCase);
            if (values == null)
                return result;
            foreach (DiagnosticHistoryRootCause item in values)
            {
                string key = JoinPair(
                    item.Severity,
                    item.Category);
                if (!String.IsNullOrWhiteSpace(key))
                    result[key] = item;
            }
            return result;
        }

        private static List<string> UnionKeys<T>(
            Dictionary<string, T> first,
            Dictionary<string, T> second)
        {
            List<string> result = new List<string>();
            foreach (string key in first.Keys)
            {
                if (!result.Contains(key))
                    result.Add(key);
            }
            foreach (string key in second.Keys)
            {
                bool exists = false;
                foreach (string current in result)
                {
                    if (String.Equals(
                        current,
                        key,
                        StringComparison.OrdinalIgnoreCase))
                    {
                        exists = true;
                        break;
                    }
                }
                if (!exists)
                    result.Add(key);
            }

            result.Sort(StringComparer.OrdinalIgnoreCase);
            return result;
        }

        private static void AddChange(
            DiagnosticHistoryComparison result,
            string label,
            string older,
            string newer)
        {
            string a = older ?? String.Empty;
            string b = newer ?? String.Empty;

            if (String.Equals(
                a,
                b,
                StringComparison.OrdinalIgnoreCase))
                return;

            result.Changes.Add(
                label + ": " +
                First(a, "(none)") + " -> " +
                First(b, "(none)") + ".");
        }

        private static void WriteRecord(
            string path,
            DiagnosticHistoryRecord record)
        {
            DataContractJsonSerializer serializer =
                new DataContractJsonSerializer(
                    typeof(DiagnosticHistoryRecord));

            using (FileStream stream = new FileStream(
                path,
                FileMode.Create,
                FileAccess.Write,
                FileShare.Read))
            {
                serializer.WriteObject(stream, record);
            }
        }

        private static DiagnosticHistoryRecord ReadRecord(
            string path)
        {
            DataContractJsonSerializer serializer =
                new DataContractJsonSerializer(
                    typeof(DiagnosticHistoryRecord));

            using (FileStream stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite))
            {
                return
                    serializer.ReadObject(stream)
                    as DiagnosticHistoryRecord;
            }
        }

        private static string Describe(
            DiagnosticHistoryRecord record)
        {
            if (record == null)
                return "(missing record)";

            return
                First(record.CreatedUtc, "(unknown time)") +
                " | " +
                First(record.ComputerName, "(unknown computer)") +
                " | v" +
                First(record.Version, "?");
        }

        private static string JoinPair(string first, string second)
        {
            if (String.IsNullOrWhiteSpace(first))
                return second ?? String.Empty;
            if (String.IsNullOrWhiteSpace(second))
                return first ?? String.Empty;
            return first + " | " + second;
        }

        private static string GetFolder()
        {
            string path = GetFolderPath();
            Directory.CreateDirectory(path);
            return path;
        }

        internal static string GetFolderPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "DomainMembershipCheckRepair",
                "History");
        }

        private static void Prune(string folder, int keep)
        {
            try
            {
                FileInfo[] files =
                    new DirectoryInfo(folder).GetFiles("*.json");
                Array.Sort(files, delegate(FileInfo a, FileInfo b)
                {
                    return b.LastWriteTimeUtc.CompareTo(
                        a.LastWriteTimeUtc);
                });

                for (int i = keep; i < files.Length; i++)
                {
                    try { files[i].Delete(); }
                    catch { }
                }
            }
            catch
            {
            }
        }

        private static string SafeFileName(string value)
        {
            string text = String.IsNullOrWhiteSpace(value)
                ? "computer"
                : value;

            foreach (char c in Path.GetInvalidFileNameChars())
                text = text.Replace(c, '_');

            return text;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value)
                ? fallback
                : value;
        }
    }
}
