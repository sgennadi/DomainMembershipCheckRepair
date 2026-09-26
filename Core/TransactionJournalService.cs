using System;
using System.Collections.Generic;
using System.IO;
using System.ServiceProcess;
using System.Text;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class TransactionJournalEntry
    {
        internal string Kind = String.Empty;
        internal string Target = String.Empty;
        internal string Before = String.Empty;
        internal string After = String.Empty;
        internal bool Reversible;
        internal string Note = String.Empty;
    }

    internal sealed class TransactionJournal
    {
        internal string Id = String.Empty;
        internal string Operation = String.Empty;
        internal DateTime CreatedUtc;
        internal DateTime CompletedUtc;
        internal bool Completed;
        internal readonly List<TransactionJournalEntry> Entries = new List<TransactionJournalEntry>();
        internal string Path = String.Empty;

        internal void Add(
            string kind,
            string target,
            string before,
            string after,
            bool reversible,
            string note)
        {
            TransactionJournalEntry entry = new TransactionJournalEntry();
            entry.Kind = kind ?? String.Empty;
            entry.Target = target ?? String.Empty;
            entry.Before = before ?? String.Empty;
            entry.After = after ?? String.Empty;
            entry.Reversible = reversible;
            entry.Note = note ?? String.Empty;
            Entries.Add(entry);
            Save();
        }

        internal void Complete()
        {
            Completed = true;
            CompletedUtc = DateTime.UtcNow;
            Save();
        }

        internal void Save()
        {
            TransactionJournalService.Save(this);
        }
    }

    internal static class TransactionJournalService
    {
        internal static TransactionJournal Begin(string operation)
        {
            TransactionJournal journal = new TransactionJournal();
            journal.Id = DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8);
            journal.Operation = String.IsNullOrWhiteSpace(operation) ? "operation" : operation.Trim();
            journal.CreatedUtc = DateTime.UtcNow;
            journal.Path = System.IO.Path.Combine(GetFolder(), journal.Id + ".json");
            journal.Save();
            Prune();
            return journal;
        }

        internal static void Save(TransactionJournal journal)
        {
            if (journal == null)
                return;

            string path = journal.Path;
            if (String.IsNullOrWhiteSpace(path))
                path = System.IO.Path.Combine(GetFolder(), journal.Id + ".json");

            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \"id\": \"" + Escape(journal.Id) + "\",");
            sb.AppendLine("  \"operation\": \"" + Escape(journal.Operation) + "\",");
            sb.AppendLine("  \"createdUtc\": \"" + journal.CreatedUtc.ToString("o") + "\",");
            sb.AppendLine("  \"completedUtc\": \"" + (journal.Completed ? journal.CompletedUtc.ToString("o") : String.Empty) + "\",");
            sb.AppendLine("  \"completed\": " + (journal.Completed ? "true" : "false") + ",");
            sb.AppendLine("  \"entries\": [");
            for (int i = 0; i < journal.Entries.Count; i++)
            {
                TransactionJournalEntry entry = journal.Entries[i];
                sb.AppendLine("    {");
                sb.AppendLine("      \"kind\": \"" + Escape(entry.Kind) + "\",");
                sb.AppendLine("      \"target\": \"" + Escape(entry.Target) + "\",");
                sb.AppendLine("      \"before\": \"" + Escape(entry.Before) + "\",");
                sb.AppendLine("      \"after\": \"" + Escape(entry.After) + "\",");
                sb.AppendLine("      \"reversible\": " + (entry.Reversible ? "true" : "false") + ",");
                sb.AppendLine("      \"note\": \"" + Escape(entry.Note) + "\"");
                sb.Append("    }");
                if (i + 1 < journal.Entries.Count)
                    sb.Append(',');
                sb.AppendLine();
            }
            sb.AppendLine("  ]");
            sb.AppendLine("}");

            Directory.CreateDirectory(System.IO.Path.GetDirectoryName(path));
            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(false));
            journal.Path = path;
        }

        internal static void RecordRegistryDwordChange(
            TransactionJournal journal,
            string registryPath,
            string valueName,
            int? before,
            int? after,
            bool reversible)
        {
            if (journal == null)
                return;

            journal.Add(
                "RegistryDword",
                registryPath + "|" + valueName,
                FormatNullable(before),
                FormatNullable(after),
                reversible,
                "Local registry change");
        }

        internal static void RecordServiceChange(
            TransactionJournal journal,
            string serviceName,
            ServiceControllerStatus before,
            ServiceControllerStatus after)
        {
            if (journal == null)
                return;

            journal.Add(
                "ServiceState",
                serviceName,
                before.ToString(),
                after.ToString(),
                before == ServiceControllerStatus.Running || before == ServiceControllerStatus.Stopped,
                "Service state before/after local recovery action");
        }

        internal static void RecordNote(
            TransactionJournal journal,
            string target,
            string note)
        {
            if (journal == null)
                return;
            journal.Add("Note", target, String.Empty, String.Empty, false, note);
        }

        internal static string GetLatestJournalPath()
        {
            string folder = GetFolderPath();
            if (!Directory.Exists(folder))
                return String.Empty;

            FileInfo[] files = new DirectoryInfo(folder).GetFiles("*.json");
            if (files.Length == 0)
                return String.Empty;

            Array.Sort(files, delegate(FileInfo a, FileInfo b)
            {
                return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc);
            });
            return files[0].FullName;
        }

        internal static string ToText(string path)
        {
            if (String.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return "No transaction journal was found.";

            return File.ReadAllText(path);
        }

        internal static bool RollbackLatest(out string report)
        {
            string path = GetLatestJournalPath();
            if (String.IsNullOrWhiteSpace(path))
            {
                report = "No transaction journal was found.";
                return false;
            }

            return Rollback(path, out report);
        }

        internal static bool Rollback(string path, out string report)
        {
            StringBuilder sb = new StringBuilder();
            bool success = true;

            try
            {
                string json = File.ReadAllText(path);
                List<TransactionJournalEntry> entries = ParseEntries(json);
                if (entries.Count == 0)
                {
                    report = "The transaction journal has no entries that can be parsed.";
                    return false;
                }

                for (int i = entries.Count - 1; i >= 0; i--)
                {
                    TransactionJournalEntry entry = entries[i];
                    if (!entry.Reversible)
                    {
                        sb.AppendLine("SKIP: " + entry.Kind + " " + entry.Target + " is not automatically reversible.");
                        continue;
                    }

                    if (!IsAllowedRollbackTarget(entry.Kind, entry.Target))
                    {
                        success = false;
                        sb.AppendLine("BLOCKED: journal target is not in the rollback allowlist: " +
                            entry.Kind + " " + entry.Target);
                        continue;
                    }

                    if (String.Equals(entry.Kind, "RegistryDword", StringComparison.OrdinalIgnoreCase))
                    {
                        string error;
                        if (RestoreRegistry(entry, out error))
                            sb.AppendLine("OK: restored registry " + entry.Target + " -> " + entry.Before);
                        else
                        {
                            success = false;
                            sb.AppendLine("FAIL: registry " + entry.Target + ": " + error);
                        }
                    }
                    else if (String.Equals(entry.Kind, "ServiceState", StringComparison.OrdinalIgnoreCase))
                    {
                        string error;
                        if (RestoreService(entry, out error))
                            sb.AppendLine("OK: restored service " + entry.Target + " -> " + entry.Before);
                        else
                        {
                            success = false;
                            sb.AppendLine("FAIL: service " + entry.Target + ": " + error);
                        }
                    }
                }

                sb.AppendLine();
                sb.AppendLine("Journal: " + path);
                report = sb.ToString();
                return success;
            }
            catch (Exception ex)
            {
                report = "Rollback failed: " + ex.Message;
                return false;
            }
        }

        internal static int? ReadLocalMachineDword(string subKey, string valueName)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey))
                {
                    if (key == null)
                        return null;
                    object value = key.GetValue(valueName, null);
                    return value == null ? (int?)null : Convert.ToInt32(value);
                }
            }
            catch
            {
                return null;
            }
        }

        internal static bool IsAllowedRollbackTarget(string kind, string target)
        {
            string k = (kind ?? String.Empty).Trim();
            string t = (target ?? String.Empty).Trim();

            if (String.Equals(k, "RegistryDword", StringComparison.OrdinalIgnoreCase))
            {
                return String.Equals(
                           t,
                           @"HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceGuard|MachineIdentityIsolation",
                           StringComparison.OrdinalIgnoreCase) ||
                       String.Equals(
                           t,
                           @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa|MachineIdentityIsolation",
                           StringComparison.OrdinalIgnoreCase);
            }

            if (String.Equals(k, "ServiceState", StringComparison.OrdinalIgnoreCase))
                return String.Equals(t, "Netlogon", StringComparison.OrdinalIgnoreCase);

            return false;
        }

        private static bool RestoreRegistry(TransactionJournalEntry entry, out string error)
        {
            error = String.Empty;
            try
            {
                string[] parts = entry.Target.Split(new char[] { '|' }, 2);
                if (parts.Length != 2 || !parts[0].StartsWith(@"HKLM\", StringComparison.OrdinalIgnoreCase))
                {
                    error = "Unsupported registry target.";
                    return false;
                }

                string subKey = parts[0].Substring(5);
                string valueName = parts[1];

                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(subKey, true))
                {
                    if (key == null)
                    {
                        error = "Registry key is not writable.";
                        return false;
                    }

                    if (String.Equals(entry.Before, "(missing)", StringComparison.OrdinalIgnoreCase))
                        key.DeleteValue(valueName, false);
                    else
                        key.SetValue(valueName, Convert.ToInt32(entry.Before), RegistryValueKind.DWord);
                }

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        private static bool RestoreService(TransactionJournalEntry entry, out string error)
        {
            error = String.Empty;
            try
            {
                using (ServiceController service = new ServiceController(entry.Target))
                {
                    if (String.Equals(entry.Before, ServiceControllerStatus.Running.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                        if (service.Status != ServiceControllerStatus.Running)
                        {
                            service.Start();
                            service.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(15));
                        }
                    }
                    else if (String.Equals(entry.Before, ServiceControllerStatus.Stopped.ToString(), StringComparison.OrdinalIgnoreCase))
                    {
                        if (service.Status != ServiceControllerStatus.Stopped)
                        {
                            service.Stop();
                            service.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(15));
                        }
                    }
                    else
                    {
                        error = "Only Running/Stopped states are automatically reversible.";
                        return false;
                    }
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        internal static List<TransactionJournalEntry> ParseEntries(string json)
        {
            List<TransactionJournalEntry> entries = new List<TransactionJournalEntry>();
            if (String.IsNullOrWhiteSpace(json))
                return entries;

            int entriesIndex = json.IndexOf("\"entries\"", StringComparison.OrdinalIgnoreCase);
            if (entriesIndex < 0)
                return entries;

            int arrayStart = json.IndexOf('[', entriesIndex);
            int arrayEnd = json.LastIndexOf(']');
            if (arrayStart < 0 || arrayEnd <= arrayStart)
                return entries;

            string body = json.Substring(arrayStart + 1, arrayEnd - arrayStart - 1);
            string[] objects = body.Split(new string[] { "}," }, StringSplitOptions.RemoveEmptyEntries);

            foreach (string raw in objects)
            {
                string item = raw.Trim().TrimStart(',').Trim();
                if (!item.EndsWith("}", StringComparison.Ordinal))
                    item += "}";

                TransactionJournalEntry entry = new TransactionJournalEntry();
                entry.Kind = Extract(item, "kind");
                entry.Target = Extract(item, "target");
                entry.Before = Extract(item, "before");
                entry.After = Extract(item, "after");
                entry.Note = Extract(item, "note");
                entry.Reversible = ExtractBool(item, "reversible");

                if (!String.IsNullOrWhiteSpace(entry.Kind))
                    entries.Add(entry);
            }

            return entries;
        }

        private static string Extract(string json, string name)
        {
            string token = "\"" + name + "\"";
            int p = json.IndexOf(token, StringComparison.OrdinalIgnoreCase);
            if (p < 0)
                return String.Empty;
            p = json.IndexOf(':', p + token.Length);
            if (p < 0)
                return String.Empty;
            int q1 = json.IndexOf('"', p + 1);
            if (q1 < 0)
                return String.Empty;
            StringBuilder value = new StringBuilder();
            bool escape = false;
            for (int i = q1 + 1; i < json.Length; i++)
            {
                char c = json[i];
                if (escape)
                {
                    if (c == 'n') value.Append('\n');
                    else if (c == 'r') value.Append('\r');
                    else if (c == 't') value.Append('\t');
                    else value.Append(c);
                    escape = false;
                    continue;
                }
                if (c == '\\')
                {
                    escape = true;
                    continue;
                }
                if (c == '"')
                    break;
                value.Append(c);
            }
            return value.ToString();
        }

        private static bool ExtractBool(string json, string name)
        {
            string token = "\"" + name + "\"";
            int p = json.IndexOf(token, StringComparison.OrdinalIgnoreCase);
            if (p < 0)
                return false;
            p = json.IndexOf(':', p + token.Length);
            if (p < 0)
                return false;
            string tail = json.Substring(p + 1).TrimStart();
            return tail.StartsWith("true", StringComparison.OrdinalIgnoreCase);
        }

        private static string GetFolder()
        {
            string path = GetFolderPath();
            Directory.CreateDirectory(path);
            HardenFolderAcl(path);
            return path;
        }

        private static string GetFolderPath()
        {
            return System.IO.Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "DomainMembershipCheckRepair",
                "Transactions");
        }

        private static void HardenFolderAcl(string path)
        {
            try
            {
                DirectorySecurity security = new DirectorySecurity();
                security.SetAccessRuleProtection(true, false);

                InheritanceFlags inheritance =
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null),
                    FileSystemRights.ReadAndExecute | FileSystemRights.Read,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                Directory.SetAccessControl(path, security);
            }
            catch
            {
                // Rollback still applies its own strict target allowlist even if ACL
                // hardening is unavailable on a non-NTFS or restricted filesystem.
            }
        }

        private static void Prune()
        {
            try
            {
                FileInfo[] files = new DirectoryInfo(GetFolder()).GetFiles("*.json");
                Array.Sort(files, delegate(FileInfo a, FileInfo b)
                {
                    return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc);
                });
                for (int i = 40; i < files.Length; i++)
                {
                    try { files[i].Delete(); } catch { }
                }
            }
            catch
            {
            }
        }

        private static string FormatNullable(int? value)
        {
            return value.HasValue ? value.Value.ToString() : "(missing)";
        }

        private static string Escape(string value)
        {
            string text = value ?? String.Empty;
            return text.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "\\r").Replace("\n", "\\n");
        }
    }
}
