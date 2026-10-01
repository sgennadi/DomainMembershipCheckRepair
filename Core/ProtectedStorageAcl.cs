using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DomainMembershipCheckRepair
{
    internal static class ProtectedStorageAcl
    {
        internal static string GetApplicationRootPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData),
                "DomainMembershipCheckRepair");
        }

        internal static bool EnsureProtectedDirectory(
            string path,
            out string error)
        {
            error = String.Empty;

            string fullPath;
            string rootPath;
            if (!TryNormalizeManagedPath(
                path,
                out fullPath,
                out rootPath,
                out error))
            {
                return false;
            }

            try
            {
                string pathDetails;
                if (!IsDirectoryPathFreeOfReparsePoints(
                    rootPath,
                    out pathDetails))
                {
                    error =
                        "Protected storage root path failed reparse-point verification: " +
                        pathDetails;
                    return false;
                }

                Directory.CreateDirectory(rootPath);

                if (!IsDirectoryPathFreeOfReparsePoints(
                    rootPath,
                    out pathDetails))
                {
                    error =
                        "Protected storage root failed reparse-point verification after creation: " +
                        pathDetails;
                    return false;
                }

                HardenDirectory(rootPath);

                string rootSecurity;
                if (!VerifyDirectorySecurity(
                    rootPath,
                    out rootSecurity))
                {
                    error =
                        "Protected storage root failed owner/ACL verification: " +
                        rootSecurity;
                    return false;
                }

                if (!String.Equals(
                    fullPath,
                    rootPath,
                    StringComparison.OrdinalIgnoreCase))
                {
                    if (!IsDirectoryPathFreeOfReparsePoints(
                        fullPath,
                        out pathDetails))
                    {
                        error =
                            "Protected storage child path failed reparse-point verification: " +
                            pathDetails;
                        return false;
                    }

                    Directory.CreateDirectory(fullPath);

                    if (!IsDirectoryPathFreeOfReparsePoints(
                        fullPath,
                        out pathDetails))
                    {
                        error =
                            "Protected storage child path failed reparse-point verification after creation: " +
                            pathDetails;
                        return false;
                    }

                    HardenDirectory(fullPath);

                    string childSecurity;
                    if (!VerifyDirectorySecurity(
                        fullPath,
                        out childSecurity))
                    {
                        error =
                            "Protected storage child failed owner/ACL verification: " +
                            childSecurity;
                        return false;
                    }
                }

                return IsProtectedDirectoryTrusted(
                    fullPath,
                    out error);
            }
            catch (Exception ex)
            {
                error =
                    "Unable to prepare protected storage: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool IsProtectedDirectoryTrusted(
            string path,
            out string details)
        {
            details = String.Empty;

            string fullPath;
            string rootPath;
            if (!TryNormalizeManagedPath(
                path,
                out fullPath,
                out rootPath,
                out details))
            {
                return false;
            }

            if (!Directory.Exists(rootPath))
            {
                details =
                    "Protected storage root does not exist: " +
                    rootPath;
                return false;
            }

            if (!Directory.Exists(fullPath))
            {
                details =
                    "Protected storage directory does not exist: " +
                    fullPath;
                return false;
            }

            string pathDetails;
            if (!IsDirectoryPathFreeOfReparsePoints(
                fullPath,
                out pathDetails))
            {
                details = pathDetails;
                return false;
            }

            string rootSecurity;
            if (!VerifyDirectorySecurity(
                rootPath,
                out rootSecurity))
            {
                details =
                    "Protected storage root is not trusted: " +
                    rootSecurity;
                return false;
            }

            if (!String.Equals(
                fullPath,
                rootPath,
                StringComparison.OrdinalIgnoreCase))
            {
                string childSecurity;
                if (!VerifyDirectorySecurity(
                    fullPath,
                    out childSecurity))
                {
                    details =
                        "Protected storage child is not trusted: " +
                        childSecurity;
                    return false;
                }
            }

            details =
                "Protected storage root and target directory have trusted owners, protected ACLs, no broad-user write access, and no reparse-point redirection.";
            return true;
        }

        internal static bool PrepareProtectedFileTarget(
            string path,
            out string error)
        {
            error = String.Empty;

            string fullPath;
            string rootPath;
            if (!TryNormalizeManagedFilePath(
                path,
                out fullPath,
                out rootPath,
                out error))
            {
                return false;
            }

            try
            {
                string folder =
                    Path.GetDirectoryName(fullPath);

                string folderDetails;
                if (!IsProtectedDirectoryTrusted(
                    folder,
                    out folderDetails))
                {
                    error =
                        "Protected file parent directory is not trusted: " +
                        folderDetails;
                    return false;
                }

                if (!File.Exists(fullPath))
                    return true;

                FileAttributes attributes =
                    File.GetAttributes(fullPath);

                if (IsReparsePoint(attributes))
                {
                    error =
                        "Protected file target is a reparse point: " +
                        fullPath;
                    return false;
                }

                string fileDetails;
                if (!IsProtectedFileTrusted(
                    fullPath,
                    out fileDetails))
                {
                    error =
                        "Existing protected file target is not trusted: " +
                        fileDetails;
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                error =
                    "Unable to verify protected file target: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool HardenProtectedFile(
            string path,
            out string error)
        {
            error = String.Empty;

            string fullPath;
            string rootPath;
            if (!TryNormalizeManagedFilePath(
                path,
                out fullPath,
                out rootPath,
                out error))
            {
                return false;
            }

            if (!File.Exists(fullPath))
            {
                error =
                    "Protected file does not exist: " +
                    fullPath;
                return false;
            }

            try
            {
                FileAttributes attributes =
                    File.GetAttributes(fullPath);

                if (IsReparsePoint(attributes))
                {
                    error =
                        "Protected file is a reparse point: " +
                        fullPath;
                    return false;
                }

                string folder =
                    Path.GetDirectoryName(fullPath);

                string folderDetails;
                if (!IsProtectedDirectoryTrusted(
                    folder,
                    out folderDetails))
                {
                    error =
                        "Protected file parent directory is not trusted: " +
                        folderDetails;
                    return false;
                }

                HardenFile(fullPath);

                return IsProtectedFileTrusted(
                    fullPath,
                    out error);
            }
            catch (Exception ex)
            {
                error =
                    "Unable to harden protected file: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool IsProtectedFileTrusted(
            string path,
            out string details)
        {
            details = String.Empty;

            string fullPath;
            string rootPath;
            if (!TryNormalizeManagedFilePath(
                path,
                out fullPath,
                out rootPath,
                out details))
            {
                return false;
            }

            if (!File.Exists(fullPath))
            {
                details =
                    "Protected file does not exist: " +
                    fullPath;
                return false;
            }

            try
            {
                string folder =
                    Path.GetDirectoryName(fullPath);

                string folderDetails;
                if (!IsProtectedDirectoryTrusted(
                    folder,
                    out folderDetails))
                {
                    details =
                        "Protected file parent directory is not trusted: " +
                        folderDetails;
                    return false;
                }

                FileAttributes attributes =
                    File.GetAttributes(fullPath);

                if (IsReparsePoint(attributes))
                {
                    details =
                        "Protected file is a reparse point: " +
                        fullPath;
                    return false;
                }

                return VerifyFileSecurity(
                    fullPath,
                    out details);
            }
            catch (Exception ex)
            {
                details =
                    "Unable to inspect protected file: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool IsDangerousBroadWriteGrant(
            SecurityIdentifier sid,
            FileSystemRights rights,
            AccessControlType accessType)
        {
            if (sid == null || accessType != AccessControlType.Allow)
                return false;

            if (!IsBroadIdentity(sid))
                return false;

            return HasWriteCapability(rights);
        }

        internal static bool IsUntrustedWriteGrant(
            SecurityIdentifier sid,
            FileSystemRights rights,
            AccessControlType accessType)
        {
            if (sid == null || accessType != AccessControlType.Allow)
                return false;

            if (!HasWriteCapability(rights))
                return false;

            return !IsTrustedOwner(sid);
        }

        internal static bool IsTrustedOwner(
            SecurityIdentifier sid)
        {
            if (sid == null)
                return false;

            return
                sid.Equals(new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid,
                    null)) ||
                sid.Equals(new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null));
        }

        internal static bool IsDirectoryPathFreeOfReparsePoints(
            string path,
            out string details)
        {
            details = String.Empty;

            if (String.IsNullOrWhiteSpace(path))
            {
                details = "Protected storage path is empty.";
                return false;
            }

            try
            {
                string fullPath = Path.GetFullPath(path);
                string root = Path.GetPathRoot(fullPath);
                if (String.IsNullOrWhiteSpace(root))
                {
                    details = "Protected storage path has no filesystem root.";
                    return false;
                }

                string current = root;
                if (Directory.Exists(current) &&
                    IsReparsePoint(File.GetAttributes(current)))
                {
                    details =
                        "Protected storage filesystem root is a reparse point: " +
                        current;
                    return false;
                }

                string relative = fullPath.Substring(root.Length);
                string[] parts = relative.Split(
                    new char[]
                    {
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar
                    },
                    StringSplitOptions.RemoveEmptyEntries);

                foreach (string part in parts)
                {
                    current = Path.Combine(current, part);

                    if (!Directory.Exists(current))
                    {
                        details =
                            "Existing protected storage path components contain no reparse points; " +
                            "remaining components do not exist yet.";
                        return true;
                    }

                    FileAttributes attributes = File.GetAttributes(current);
                    if (IsReparsePoint(attributes))
                    {
                        details =
                            "Protected storage path contains a reparse point: " +
                            current;
                        return false;
                    }
                }

                details =
                    "Protected storage path contains no directory reparse points.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to verify protected storage path components: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool IsReparsePoint(FileAttributes attributes)
        {
            return (attributes & FileAttributes.ReparsePoint) != 0;
        }

        internal static bool HasWriteCapability(FileSystemRights rights)
        {
            FileSystemRights dangerous =
                FileSystemRights.WriteData |
                FileSystemRights.AppendData |
                FileSystemRights.WriteExtendedAttributes |
                FileSystemRights.WriteAttributes |
                FileSystemRights.DeleteSubdirectoriesAndFiles |
                FileSystemRights.Delete |
                FileSystemRights.ChangePermissions |
                FileSystemRights.TakeOwnership;

            return (rights & dangerous) != 0;
        }

        private static bool TryNormalizeManagedPath(
            string path,
            out string fullPath,
            out string rootPath,
            out string error)
        {
            fullPath = String.Empty;
            rootPath = String.Empty;
            error = String.Empty;

            if (String.IsNullOrWhiteSpace(path))
            {
                error = "Protected storage path is empty.";
                return false;
            }

            try
            {
                rootPath =
                    Path.GetFullPath(
                        GetApplicationRootPath())
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);

                fullPath =
                    Path.GetFullPath(path)
                    .TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar);

                string rootPrefix =
                    rootPath +
                    Path.DirectorySeparatorChar;

                if (!String.Equals(
                        fullPath,
                        rootPath,
                        StringComparison.OrdinalIgnoreCase) &&
                    !fullPath.StartsWith(
                        rootPrefix,
                        StringComparison.OrdinalIgnoreCase))
                {
                    error =
                        "Protected storage path is outside the managed ProgramData root.";
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                error =
                    "Unable to normalize protected storage path: " +
                    ex.Message;
                return false;
            }
        }

        private static bool TryNormalizeManagedFilePath(
            string path,
            out string fullPath,
            out string rootPath,
            out string error)
        {
            if (!TryNormalizeManagedPath(
                path,
                out fullPath,
                out rootPath,
                out error))
            {
                return false;
            }

            if (String.Equals(
                fullPath,
                rootPath,
                StringComparison.OrdinalIgnoreCase))
            {
                error =
                    "Protected file path cannot be the managed ProgramData root.";
                return false;
            }

            string folder =
                Path.GetDirectoryName(fullPath);

            if (String.IsNullOrWhiteSpace(folder))
            {
                error =
                    "Protected file path has no parent directory.";
                return false;
            }

            return true;
        }

        private static void HardenDirectory(
            string path)
        {
            SecurityIdentifier administrators =
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null);

            DirectorySecurity ownerSecurity =
                Directory.GetAccessControl(
                    path,
                    AccessControlSections.Owner);
            ownerSecurity.SetOwner(administrators);
            Directory.SetAccessControl(
                path,
                ownerSecurity);

            DirectorySecurity security =
                new DirectorySecurity();
            security.SetOwner(administrators);
            security.SetAccessRuleProtection(
                true,
                false);

            InheritanceFlags inheritance =
                InheritanceFlags.ContainerInherit |
                InheritanceFlags.ObjectInherit;

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
                    administrators,
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

            security.AddAccessRule(
                new FileSystemAccessRule(
                    new SecurityIdentifier(
                        WellKnownSidType.BuiltinUsersSid,
                        null),
                    FileSystemRights.ReadAndExecute |
                    FileSystemRights.Read,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

            Directory.SetAccessControl(
                path,
                security);
        }

        private static void HardenFile(
            string path)
        {
            SecurityIdentifier administrators =
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null);

            FileSecurity ownerSecurity =
                File.GetAccessControl(
                    path,
                    AccessControlSections.Owner);
            ownerSecurity.SetOwner(administrators);
            File.SetAccessControl(
                path,
                ownerSecurity);

            FileSecurity security =
                new FileSecurity();
            security.SetOwner(administrators);
            security.SetAccessRuleProtection(
                true,
                false);

            security.AddAccessRule(
                new FileSystemAccessRule(
                    new SecurityIdentifier(
                        WellKnownSidType.LocalSystemSid,
                        null),
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

            security.AddAccessRule(
                new FileSystemAccessRule(
                    administrators,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow));

            security.AddAccessRule(
                new FileSystemAccessRule(
                    new SecurityIdentifier(
                        WellKnownSidType.BuiltinUsersSid,
                        null),
                    FileSystemRights.ReadAndExecute |
                    FileSystemRights.Read,
                    AccessControlType.Allow));

            File.SetAccessControl(
                path,
                security);
        }

        private static bool VerifyFileSecurity(
            string path,
            out string details)
        {
            details = String.Empty;

            try
            {
                FileSecurity security =
                    File.GetAccessControl(
                        path,
                        AccessControlSections.Owner |
                        AccessControlSections.Access);

                SecurityIdentifier owner =
                    security.GetOwner(
                        typeof(SecurityIdentifier))
                    as SecurityIdentifier;

                if (!IsTrustedOwner(owner))
                {
                    details =
                        "File owner is not LocalSystem or Builtin Administrators.";
                    return false;
                }

                if (!security.AreAccessRulesProtected)
                {
                    details =
                        "File ACL still inherits access rules from its parent.";
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

                    if (IsUntrustedWriteGrant(
                        sid,
                        rule.FileSystemRights,
                        rule.AccessControlType))
                    {
                        details =
                            "A non-privileged identity has write-capable file access.";
                        return false;
                    }
                }

                details =
                    "File owner and protected ACL are trusted.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to inspect protected file owner/ACL: " +
                    ex.Message;
                return false;
            }
        }

        private static bool VerifyDirectorySecurity(
            string path,
            out string details)
        {
            details = String.Empty;

            try
            {
                DirectorySecurity security =
                    Directory.GetAccessControl(
                        path,
                        AccessControlSections.Owner |
                        AccessControlSections.Access);

                SecurityIdentifier owner =
                    security.GetOwner(
                        typeof(SecurityIdentifier))
                    as SecurityIdentifier;

                if (!IsTrustedOwner(owner))
                {
                    details =
                        "Directory owner is not LocalSystem or Builtin Administrators.";
                    return false;
                }

                if (!security.AreAccessRulesProtected)
                {
                    details =
                        "Directory ACL still inherits access rules from its parent.";
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

                    if (IsUntrustedWriteGrant(
                        sid,
                        rule.FileSystemRights,
                        rule.AccessControlType))
                    {
                        details =
                            "A non-privileged identity has write-capable access.";
                        return false;
                    }
                }

                details =
                    "Directory owner and protected ACL are trusted.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to inspect protected directory owner/ACL: " +
                    ex.Message;
                return false;
            }
        }

        private static bool IsBroadIdentity(
            SecurityIdentifier sid)
        {
            return
                sid.Equals(new SecurityIdentifier(
                    WellKnownSidType.BuiltinUsersSid,
                    null)) ||
                sid.Equals(new SecurityIdentifier(
                    WellKnownSidType.AuthenticatedUserSid,
                    null)) ||
                sid.Equals(new SecurityIdentifier(
                    WellKnownSidType.WorldSid,
                    null));
        }
    }
}
