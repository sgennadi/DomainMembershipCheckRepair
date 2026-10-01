using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
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

        internal static bool TryCreate(
            string operationName,
            string targetDomain,
            string dc,
            string domainUser,
            string domainPassword,
            out RecoverySnapshotScope scope,
            out string error)
        {
            scope = null;
            error = String.Empty;

            try
            {
                scope = new RecoverySnapshotScope(
                    operationName,
                    targetDomain,
                    dc,
                    domainUser,
                    domainPassword);
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

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
                operation + "-" +
                Guid.NewGuid().ToString("N").Substring(0, 8));

            before = Capture(domain, preferredDc, user, password);
            BeforePath = prefix + ".before.txt";
            WriteTextAtomically(
                BeforePath,
                ToText("BEFORE", operation, before));
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
            string path = GetSnapshotFolderPath();
            Directory.CreateDirectory(path);

            string pathDetails;
            if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                path,
                out pathDetails))
            {
                throw new IOException(
                    "Recovery snapshot storage path failed reparse-point verification: " +
                    pathDetails);
            }

            HardenSnapshotFolderAcl(path);

            string securityDetails;
            if (!IsSnapshotFolderSecurityTrusted(
                path,
                out securityDetails))
            {
                throw new IOException(
                    "Recovery snapshot storage failed security verification: " +
                    securityDetails);
            }

            return path;
        }

        internal static string GetSnapshotFolderPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData),
                "DomainMembershipCheckRepair",
                "Snapshots");
        }

        private static void HardenSnapshotFolderAcl(string path)
        {
            DirectorySecurity security = new DirectorySecurity();
            security.SetAccessRuleProtection(true, false);

            InheritanceFlags inheritance =
                InheritanceFlags.ContainerInherit |
                InheritanceFlags.ObjectInherit;

            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid,
                    null),
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null),
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));

            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinUsersSid,
                    null),
                FileSystemRights.ReadAndExecute |
                FileSystemRights.Read,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));

            Directory.SetAccessControl(path, security);
        }

        internal static bool IsSnapshotFolderSecurityTrusted(
            string path,
            out string details)
        {
            if (String.IsNullOrWhiteSpace(path) ||
                !Directory.Exists(path))
            {
                details = "Recovery snapshot folder does not exist.";
                return false;
            }

            string pathDetails;
            if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                path,
                out pathDetails))
            {
                details = pathDetails;
                return false;
            }

            try
            {
                DirectorySecurity security =
                    Directory.GetAccessControl(path);

                AuthorizationRuleCollection rules =
                    security.GetAccessRules(
                        true,
                        true,
                        typeof(SecurityIdentifier));

                foreach (FileSystemAccessRule rule in rules)
                {
                    SecurityIdentifier sid =
                        rule.IdentityReference as SecurityIdentifier;

                    if (ProtectedStorageAcl.IsDangerousBroadWriteGrant(
                        sid,
                        rule.FileSystemRights,
                        rule.AccessControlType))
                    {
                        details =
                            "A broad user group has write-capable access to recovery snapshot storage.";
                        return false;
                    }
                }

                details =
                    "Recovery snapshot folder ACL does not grant broad-user write access.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to inspect recovery snapshot folder ACL: " +
                    ex.Message;
                return false;
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
                WriteTextAtomically(path, text);
            }
            catch
            {
            }
        }

        internal static void WriteTextAtomically(
            string path,
            string text)
        {
            if (String.IsNullOrWhiteSpace(path))
                throw new ArgumentException(
                    "A recovery snapshot path is required.",
                    "path");

            string folder = Path.GetDirectoryName(path);
            if (String.IsNullOrWhiteSpace(folder))
            {
                throw new IOException(
                    "The recovery snapshot path has no parent directory.");
            }

            string trustedFolder = Path.GetFullPath(
                GetSnapshotFolderPath());

            string fullFolder =
                trustedFolder.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar) +
                Path.DirectorySeparatorChar;

            string fullPath = Path.GetFullPath(path);
            if (!fullPath.StartsWith(
                fullFolder,
                StringComparison.OrdinalIgnoreCase))
            {
                throw new IOException(
                    "Recovery snapshot path escaped the protected snapshot folder.");
            }

            string storageDetails;
            if (!IsSnapshotFolderSecurityTrusted(
                trustedFolder,
                out storageDetails))
            {
                throw new IOException(
                    "Recovery snapshot storage is not trusted immediately before write: " +
                    storageDetails);
            }

            string tempPath =
                fullPath + ".tmp-" +
                Guid.NewGuid().ToString("N");

            try
            {
                File.WriteAllText(
                    tempPath,
                    text ?? String.Empty,
                    new UTF8Encoding(false));

                if (File.Exists(fullPath))
                    File.Replace(tempPath, fullPath, null);
                else
                    File.Move(tempPath, fullPath);
            }
            finally
            {
                try
                {
                    if (File.Exists(tempPath))
                        File.Delete(tempPath);
                }
                catch
                {
                }
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
