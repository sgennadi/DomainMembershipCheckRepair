using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal static class PrivateApplicationLogService
    {
        internal static string GetLogDirectoryPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.LocalApplicationData),
                "DomainMembershipCheckRepair",
                "Logs");
        }

        internal static string GetLogFilePath()
        {
            return Path.Combine(
                GetLogDirectoryPath(),
                "DomainMembershipRepair.log");
        }

        internal static bool AppendLine(
            string line,
            out string error)
        {
            error = String.Empty;

            try
            {
                string directory = GetLogDirectoryPath();
                if (!EnsurePrivateDirectory(
                    directory,
                    out error))
                {
                    return false;
                }

                string path = GetLogFilePath();
                if (!PreparePrivateFileTarget(
                    path,
                    out error))
                {
                    return false;
                }

                File.AppendAllText(
                    path,
                    (line ?? String.Empty) +
                    Environment.NewLine,
                    Encoding.UTF8);

                if (!HardenPrivateFile(
                    path,
                    out error))
                {
                    return false;
                }

                return IsPrivateFileTrusted(
                    path,
                    out error);
            }
            catch (Exception ex)
            {
                error =
                    "Unable to append the private application log: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool CheckStorageSecurity(
            out string details)
        {
            string directory = GetLogDirectoryPath();
            if (!Directory.Exists(directory))
            {
                details =
                    "Private application log folder does not exist yet: " +
                    directory;
                return true;
            }

            if (!IsPrivateDirectoryTrusted(
                directory,
                out details))
            {
                return false;
            }

            string path = GetLogFilePath();
            if (!File.Exists(path))
            {
                details =
                    "Private application log folder is trusted; log file does not exist yet.";
                return true;
            }

            return IsPrivateFileTrusted(
                path,
                out details);
        }

        internal static bool IsUntrustedPrivateAllowRule(
            SecurityIdentifier sid,
            SecurityIdentifier currentUserSid,
            AccessControlType accessType)
        {
            if (sid == null ||
                accessType != AccessControlType.Allow)
            {
                return false;
            }

            return !IsAllowedIdentity(
                sid,
                currentUserSid);
        }

        private static bool EnsurePrivateDirectory(
            string path,
            out string error)
        {
            error = String.Empty;

            SecurityIdentifier currentUser;
            if (!TryGetCurrentUserSid(
                out currentUser,
                out error))
            {
                return false;
            }

            try
            {
                string fullPath;
                if (!TryNormalizeManagedPath(
                    path,
                    out fullPath,
                    out error))
                {
                    return false;
                }

                string pathDetails;
                if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                    fullPath,
                    out pathDetails))
                {
                    error =
                        "Private application log path failed reparse-point verification: " +
                        pathDetails;
                    return false;
                }

                Directory.CreateDirectory(fullPath);

                if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                    fullPath,
                    out pathDetails))
                {
                    error =
                        "Private application log path failed reparse-point verification after creation: " +
                        pathDetails;
                    return false;
                }

                HardenDirectory(
                    fullPath,
                    currentUser);

                return IsPrivateDirectoryTrusted(
                    fullPath,
                    out error);
            }
            catch (Exception ex)
            {
                error =
                    "Unable to prepare the private application log folder: " +
                    ex.Message;
                return false;
            }
        }

        private static bool IsPrivateDirectoryTrusted(
            string path,
            out string details)
        {
            details = String.Empty;

            SecurityIdentifier currentUser;
            if (!TryGetCurrentUserSid(
                out currentUser,
                out details))
            {
                return false;
            }

            string fullPath;
            if (!TryNormalizeManagedPath(
                path,
                out fullPath,
                out details))
            {
                return false;
            }

            if (!Directory.Exists(fullPath))
            {
                details =
                    "Private application log folder does not exist.";
                return false;
            }

            string pathDetails;
            if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                fullPath,
                out pathDetails))
            {
                details = pathDetails;
                return false;
            }

            try
            {
                DirectorySecurity security =
                    Directory.GetAccessControl(
                        fullPath,
                        AccessControlSections.Owner |
                        AccessControlSections.Access);

                SecurityIdentifier owner =
                    security.GetOwner(
                        typeof(SecurityIdentifier))
                    as SecurityIdentifier;

                if (!IsAllowedIdentity(
                    owner,
                    currentUser))
                {
                    details =
                        "Private application log folder owner is not the current user, LocalSystem or Administrators.";
                    return false;
                }

                if (!security.AreAccessRulesProtected)
                {
                    details =
                        "Private application log folder still inherits ACL rules.";
                    return false;
                }

                AuthorizationRuleCollection rules =
                    security.GetAccessRules(
                        true,
                        true,
                        typeof(SecurityIdentifier));

                foreach (FileSystemAccessRule rule in rules)
                {
                    SecurityIdentifier sid =
                        rule.IdentityReference
                        as SecurityIdentifier;

                    if (IsUntrustedPrivateAllowRule(
                        sid,
                        currentUser,
                        rule.AccessControlType))
                    {
                        details =
                            "Another identity has allow access to the private application log folder.";
                        return false;
                    }
                }

                details =
                    "Private application log folder ACL is restricted to the current user, LocalSystem and Administrators.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to inspect private application log folder ACL: " +
                    ex.Message;
                return false;
            }
        }

        private static bool PreparePrivateFileTarget(
            string path,
            out string error)
        {
            error = String.Empty;

            string fullPath;
            if (!TryNormalizeManagedPath(
                path,
                out fullPath,
                out error))
            {
                return false;
            }

            try
            {
                if (!File.Exists(fullPath))
                    return true;

                FileAttributes attributes =
                    File.GetAttributes(fullPath);

                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    error =
                        "Private application log target is a reparse point.";
                    return false;
                }

                return IsPrivateFileTrusted(
                    fullPath,
                    out error);
            }
            catch (Exception ex)
            {
                error =
                    "Unable to inspect private application log target: " +
                    ex.Message;
                return false;
            }
        }

        private static bool HardenPrivateFile(
            string path,
            out string error)
        {
            error = String.Empty;

            SecurityIdentifier currentUser;
            if (!TryGetCurrentUserSid(
                out currentUser,
                out error))
            {
                return false;
            }

            try
            {
                string fullPath;
                if (!TryNormalizeManagedPath(
                    path,
                    out fullPath,
                    out error))
                {
                    return false;
                }

                FileSecurity security =
                    new FileSecurity();

                security.SetOwner(currentUser);
                security.SetAccessRuleProtection(
                    true,
                    false);

                security.AddAccessRule(
                    new FileSystemAccessRule(
                        currentUser,
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));

                security.AddAccessRule(
                    new FileSystemAccessRule(
                        new SecurityIdentifier(
                            WellKnownSidType.LocalSystemSid,
                            null),
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));

                security.AddAccessRule(
                    new FileSystemAccessRule(
                        new SecurityIdentifier(
                            WellKnownSidType.BuiltinAdministratorsSid,
                            null),
                        FileSystemRights.FullControl,
                        AccessControlType.Allow));

                File.SetAccessControl(
                    fullPath,
                    security);

                return true;
            }
            catch (Exception ex)
            {
                error =
                    "Unable to harden private application log ACL: " +
                    ex.Message;
                return false;
            }
        }

        private static bool IsPrivateFileTrusted(
            string path,
            out string details)
        {
            details = String.Empty;

            SecurityIdentifier currentUser;
            if (!TryGetCurrentUserSid(
                out currentUser,
                out details))
            {
                return false;
            }

            string fullPath;
            if (!TryNormalizeManagedPath(
                path,
                out fullPath,
                out details))
            {
                return false;
            }

            if (!File.Exists(fullPath))
            {
                details =
                    "Private application log file does not exist.";
                return false;
            }

            try
            {
                FileAttributes attributes =
                    File.GetAttributes(fullPath);

                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    details =
                        "Private application log file is a reparse point.";
                    return false;
                }

                FileSecurity security =
                    File.GetAccessControl(
                        fullPath,
                        AccessControlSections.Owner |
                        AccessControlSections.Access);

                SecurityIdentifier owner =
                    security.GetOwner(
                        typeof(SecurityIdentifier))
                    as SecurityIdentifier;

                if (!IsAllowedIdentity(
                    owner,
                    currentUser))
                {
                    details =
                        "Private application log file owner is not the current user, LocalSystem or Administrators.";
                    return false;
                }

                if (!security.AreAccessRulesProtected)
                {
                    details =
                        "Private application log file still inherits ACL rules.";
                    return false;
                }

                AuthorizationRuleCollection rules =
                    security.GetAccessRules(
                        true,
                        true,
                        typeof(SecurityIdentifier));

                foreach (FileSystemAccessRule rule in rules)
                {
                    SecurityIdentifier sid =
                        rule.IdentityReference
                        as SecurityIdentifier;

                    if (IsUntrustedPrivateAllowRule(
                        sid,
                        currentUser,
                        rule.AccessControlType))
                    {
                        details =
                            "Another identity has allow access to the private application log file.";
                        return false;
                    }
                }

                details =
                    "Private application log file ACL is restricted to the current user, LocalSystem and Administrators.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to inspect private application log file ACL: " +
                    ex.Message;
                return false;
            }
        }

        private static bool TryNormalizeManagedPath(
            string path,
            out string fullPath,
            out string error)
        {
            fullPath = String.Empty;
            error = String.Empty;

            if (String.IsNullOrWhiteSpace(path))
            {
                error =
                    "Private application log path is empty.";
                return false;
            }

            try
            {
                string root =
                    Path.GetFullPath(
                        GetLogDirectoryPath())
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);

                fullPath =
                    Path.GetFullPath(path)
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);

                string prefix =
                    root +
                    Path.DirectorySeparatorChar;

                if (!String.Equals(
                        fullPath,
                        root,
                        StringComparison.OrdinalIgnoreCase) &&
                    !fullPath.StartsWith(
                        prefix,
                        StringComparison.OrdinalIgnoreCase))
                {
                    error =
                        "Private application log path is outside the managed Logs root.";
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                error =
                    "Unable to normalize private application log path: " +
                    ex.Message;
                return false;
            }
        }

        private static bool TryGetCurrentUserSid(
            out SecurityIdentifier sid,
            out string error)
        {
            sid = null;
            error = String.Empty;

            try
            {
                using (WindowsIdentity identity =
                    WindowsIdentity.GetCurrent())
                {
                    if (identity == null ||
                        identity.User == null)
                    {
                        error =
                            "Current Windows user SID is unavailable.";
                        return false;
                    }

                    sid = identity.User;
                    return true;
                }
            }
            catch (Exception ex)
            {
                error =
                    "Unable to resolve current Windows user SID: " +
                    ex.Message;
                return false;
            }
        }

        private static bool IsAllowedIdentity(
            SecurityIdentifier sid,
            SecurityIdentifier currentUserSid)
        {
            if (sid == null)
                return false;

            if (currentUserSid != null &&
                sid.Equals(currentUserSid))
            {
                return true;
            }

            return ProtectedStorageAcl.IsTrustedOwner(
                sid);
        }

        private static void HardenDirectory(
            string path,
            SecurityIdentifier currentUser)
        {
            DirectorySecurity security =
                new DirectorySecurity();

            security.SetOwner(currentUser);
            security.SetAccessRuleProtection(
                true,
                false);

            InheritanceFlags inheritance =
                InheritanceFlags.ContainerInherit |
                InheritanceFlags.ObjectInherit;

            security.AddAccessRule(
                new FileSystemAccessRule(
                    currentUser,
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

            security.AddAccessRule(
                new FileSystemAccessRule(
                    new SecurityIdentifier(
                        WellKnownSidType.LocalSystemSid,
                        null),
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

            security.AddAccessRule(
                new FileSystemAccessRule(
                    new SecurityIdentifier(
                        WellKnownSidType.BuiltinAdministratorsSid,
                        null),
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

            Directory.SetAccessControl(
                path,
                security);
        }
    }
}
