using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class RecoverySnapshotState
    {
        internal DateTime Time;
        internal string ComputerName = String.Empty;
        internal string JoinedDomain = String.Empty;
        internal string TargetDomain = String.Empty;
        internal string DiscoveredDc = String.Empty;
        internal bool SecureChannelApplicable;
        internal bool SecureChannelHealthy;
        internal int SecureChannelStatus;
        internal bool PendingRename;
        internal string PendingName = String.Empty;
        internal string MiiMode = String.Empty;
        internal string AccountGuid = String.Empty;
        internal string AccountOwner = String.Empty;
        internal string AccountPwdLastSet = String.Empty;
        internal bool? AccountEnabled;
    }

    internal sealed class RecoverySnapshotScope : IDisposable
    {
        private readonly string operation;
        private readonly string domain;
        private readonly string preferredDc;
        private string user;
        private string password;
        private readonly string prefix;
        private readonly RecoverySnapshotState before;
        private bool disposed;

        internal string BeforePath { get; private set; }
        internal string AfterPath { get; private set; }
        internal string SummaryPath { get; private set; }

        internal RecoverySnapshotScope(
            string operationName,
            string targetDomain,
            string dc,
            string domainUser,
            string domainPassword)
        {
            operation = Sanitize(operationName);
            domain = targetDomain ?? String.Empty;
            preferredDc = dc ?? String.Empty;
            user = domainUser;
            password = domainPassword;

            string folder = EnsureSnapshotFolder();
            prefix = Path.Combine(
                folder,
                DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" +
                Environment.MachineName + "-" + operation + "-" +
                Guid.NewGuid().ToString("N").Substring(0, 8));

            before = Capture(domain, preferredDc, user, password);
            BeforePath = prefix + ".before.txt";
            SafeWrite(BeforePath, ToText("BEFORE", operation, before));
            Prune(folder);
        }

        public void Dispose()
        {
            if (disposed)
                return;
            disposed = true;

            try
            {
                RecoverySnapshotState after = Capture(domain, preferredDc, user, password);
                AfterPath = prefix + ".after.txt";
                SummaryPath = prefix + ".summary.txt";

                SafeWrite(AfterPath, ToText("AFTER", operation, after));
                SafeWrite(SummaryPath, BuildComparison(operation, before, after));
            }
            catch
            {
            }
            finally
            {
                password = null;
                user = null;
            }
        }

        private static RecoverySnapshotState Capture(
            string domain,
            string preferredDc,
            string user,
            string password)
        {
            RecoverySnapshotState state = new RecoverySnapshotState();
            state.Time = DateTime.Now;
            state.ComputerName = Environment.MachineName;

            DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(domain, preferredDc);
            state.JoinedDomain = snapshot.JoinedDomain ?? String.Empty;
            state.TargetDomain = snapshot.TargetDomain ?? String.Empty;
            state.DiscoveredDc = snapshot.DiscoveredDc ?? String.Empty;
            state.SecureChannelApplicable = snapshot.SecureChannelApplicable;
            state.SecureChannelHealthy = snapshot.SecureChannelHealthy;
            state.SecureChannelStatus = snapshot.SecureChannelStatus;
            state.PendingRename = snapshot.PendingRename;
            state.PendingName = snapshot.PendingComputerName ?? String.Empty;
            state.MiiMode = snapshot.Health == null
                ? String.Empty
                : snapshot.Health.MachineIdentityIsolationMode;

            if (!String.IsNullOrWhiteSpace(user) && password != null)
            {
                string target = !String.IsNullOrWhiteSpace(state.TargetDomain)
                    ? state.TargetDomain
                    : domain;

                AdComputerAccountInfo account = AdDirectoryService.FindComputerAccount(
                    state.ComputerName,
                    user,
                    password,
                    target,
                    preferredDc,
                    null);

                if (account != null && account.LookupSucceeded && account.Exists)
                {
                    state.AccountGuid = account.ObjectGuid ?? String.Empty;
                    state.AccountOwner = account.Owner ?? String.Empty;
                    state.AccountPwdLastSet = account.PwdLastSet ?? String.Empty;
                    state.AccountEnabled = account.Enabled;
                }
            }

            return state;
        }

        private static string BuildComparison(
            string operation,
            RecoverySnapshotState before,
            RecoverySnapshotState after)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("DomainMembershipCheckRepair recovery snapshot comparison");
            sb.AppendLine("=======================================================");
            sb.AppendLine("Operation: " + operation);
            sb.AppendLine();

            AddChange(sb, "Computer name", before.ComputerName, after.ComputerName);
            AddChange(sb, "Joined domain", before.JoinedDomain, after.JoinedDomain);
            AddChange(sb, "Target domain", before.TargetDomain, after.TargetDomain);
            AddChange(sb, "Discovered DC", before.DiscoveredDc, after.DiscoveredDc);
            AddChange(
                sb,
                "Secure channel",
                FormatTrust(before),
                FormatTrust(after));
            AddChange(
                sb,
                "Pending rename",
                FormatPending(before),
                FormatPending(after));
            AddChange(sb, "MII mode", before.MiiMode, after.MiiMode);
            AddChange(sb, "AD object GUID", before.AccountGuid, after.AccountGuid);
            AddChange(sb, "AD owner", before.AccountOwner, after.AccountOwner);
            AddChange(sb, "AD pwdLastSet", before.AccountPwdLastSet, after.AccountPwdLastSet);
            AddChange(
                sb,
                "AD enabled",
                FormatBool(before.AccountEnabled),
                FormatBool(after.AccountEnabled));

            sb.AppendLine();
            sb.AppendLine("No entered domain password is stored in snapshot files.");
            return sb.ToString();
        }

        private static string ToText(
            string phase,
            string operation,
            RecoverySnapshotState s)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("DomainMembershipCheckRepair " + phase + " snapshot");
            sb.AppendLine("===============================================");
            sb.AppendLine("Operation:       " + operation);
            sb.AppendLine("Time:            " + s.Time.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("Computer:        " + s.ComputerName);
            sb.AppendLine("Joined domain:   " + First(s.JoinedDomain, "(none)"));
            sb.AppendLine("Target domain:   " + First(s.TargetDomain, "(none)"));
            sb.AppendLine("DC:              " + First(s.DiscoveredDc, "(none)"));
            sb.AppendLine("Secure channel:  " + FormatTrust(s));
            sb.AppendLine("Pending rename:  " + FormatPending(s));
            sb.AppendLine("MII:             " + First(s.MiiMode, "(unknown)"));
            sb.AppendLine("AD object GUID:  " + First(s.AccountGuid, "(not captured)"));
            sb.AppendLine("AD owner:        " + First(s.AccountOwner, "(not captured)"));
            sb.AppendLine("AD pwdLastSet:   " + First(s.AccountPwdLastSet, "(not captured)"));
            sb.AppendLine("AD enabled:      " + FormatBool(s.AccountEnabled));
            sb.AppendLine();
            sb.AppendLine("No entered domain password is stored in this file.");
            return sb.ToString();
        }

        private static void AddChange(
            StringBuilder sb,
            string name,
            string before,
            string after)
        {
            string b = before ?? String.Empty;
            string a = after ?? String.Empty;
            bool changed = !String.Equals(b, a, StringComparison.OrdinalIgnoreCase);

            sb.AppendLine(
                (changed ? "CHANGED  " : "UNCHANGED") +
                " | " + name +
                " | before=" + First(b, "(empty)") +
                " | after=" + First(a, "(empty)"));
        }

        private static string EnsureSnapshotFolder()
        {
            string primary = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Logs",
                "DomainMembershipCheckRepair",
                "Snapshots");

            try
            {
                Directory.CreateDirectory(primary);
                return primary;
            }
            catch
            {
                string fallback = Path.Combine(
                    Path.GetTempPath(),
                    "DomainMembershipCheckRepair",
                    "Snapshots");
                Directory.CreateDirectory(fallback);
                return fallback;
            }
        }

        private static void Prune(string folder)
        {
            try
            {
                FileInfo[] files = new DirectoryInfo(folder).GetFiles("*.txt");
                Array.Sort(files, delegate(FileInfo a, FileInfo b)
                {
                    return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc);
                });

                for (int i = 60; i < files.Length; i++)
                {
                    try { files[i].Delete(); } catch { }
                }
            }
            catch
            {
            }
        }

        private static void SafeWrite(string path, string text)
        {
            try
            {
                File.WriteAllText(path, text ?? String.Empty, new UTF8Encoding(false));
            }
            catch
            {
            }
        }

        private static string FormatTrust(RecoverySnapshotState s)
        {
            if (!s.SecureChannelApplicable)
                return "N/A";

            return s.SecureChannelHealthy
                ? "Healthy"
                : "Broken (" + NativeMethods.FormatError(s.SecureChannelStatus) + ")";
        }

        private static string FormatPending(RecoverySnapshotState s)
        {
            if (!s.PendingRename)
                return "No";

            return "Yes -> " + First(s.PendingName, "(unknown)");
        }

        private static string FormatBool(bool? value)
        {
            if (!value.HasValue)
                return "(unknown)";
            return value.Value ? "Yes" : "No";
        }

        private static string Sanitize(string value)
        {
            string text = String.IsNullOrWhiteSpace(value) ? "operation" : value.Trim();
            foreach (char c in Path.GetInvalidFileNameChars())
                text = text.Replace(c, '-');
            return text.Replace(' ', '-');
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
