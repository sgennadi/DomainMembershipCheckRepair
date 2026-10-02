using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DomainMembershipCheckRepair
{
    internal static class PrivateStagingService
    {
        internal static string GetRootPath()
        {
            return Path.Combine(
                ProtectedStorageAcl.GetApplicationRootPath(),
                "RawStaging");
        }

        internal static string CreateSession(string purpose)
        {
            string root = GetRootPath();
            string error;
            if (!EnsurePrivateDirectory(root, out error))
            {
                throw new IOException(
                    "Private diagnostic staging root could not be prepared: " +
                    error);
            }

            PruneStaleSessions(root);

            string name =
                Sanitize(purpose) + "-" +
                Guid.NewGuid().ToString("N");

            string path = Path.Combine(root, name);
            if (!EnsurePrivateDirectory(path, out error))
            {
                throw new IOException(
                    "Private diagnostic staging session could not be prepared: " +
                    error);
            }

            return path;
        }

        internal static bool EnsurePrivateDirectory(
            string path,
            out string error)
        {
            error = String.Empty;

            string fullPath;
            if (!TryNormalizePrivatePath(
                path,
                out fullPath,
                out error))
            {
                return false;
            }

            try
            {
                string applicationRoot =
                    ProtectedStorageAcl.GetApplicationRootPath();

                string applicationError;
                if (!ProtectedStorageAcl.EnsureProtectedDirectory(
                    applicationRoot,
                    out applicationError))
                {
                    error =
                        "Managed application root is not trusted: " +
                        applicationError;
                    return false;
                }

                string pathDetails;
                if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                    fullPath,
                    out pathDetails))
                {
                    error =
                        "Private staging path failed reparse-point verification: " +
                        pathDetails;
                    return false;
                }

                Directory.CreateDirectory(fullPath);

                if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                    fullPath,
                    out pathDetails))
                {
                    error =
                        "Private staging path failed reparse-point verification after creation: " +
                        pathDetails;
                    return false;
                }

                HardenPrivateDirectory(fullPath);

                return IsPrivateDirectoryTrusted(
                    fullPath,
                    out error);
            }
            catch (Exception ex)
            {
                error =
                    "Unable to prepare private staging directory: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool IsPrivateDirectoryTrusted(
            string path,
            out string details)
        {
            details = String.Empty;

            string fullPath;
            if (!TryNormalizePrivatePath(
                path,
                out fullPath,
                out details))
            {
                return false;
            }

            if (!Directory.Exists(fullPath))
            {
                details =
                    "Private staging directory does not exist: " +
                    fullPath;
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

                if (!ProtectedStorageAcl.IsTrustedOwner(owner))
                {
                    details =
                        "Private staging owner is not LocalSystem or Builtin Administrators.";
                    return false;
                }

                if (!security.AreAccessRulesProtected)
                {
                    details =
                        "Private staging ACL still inherits access rules.";
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
                        rule.AccessControlType))
                    {
                        details =
                            "A non-privileged identity has allow access to private staging.";
                        return false;
                    }
                }

                details =
                    "Private staging owner and ACL are restricted to LocalSystem/Administrators.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to inspect private staging owner/ACL: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool IsUntrustedPrivateAllowRule(
            SecurityIdentifier sid,
            AccessControlType accessType)
        {
            if (sid == null ||
                accessType != AccessControlType.Allow)
            {
                return false;
            }

            return !ProtectedStorageAcl.IsTrustedOwner(sid);
        }

        internal static void DeleteSession(string path)
        {
            if (String.IsNullOrWhiteSpace(path))
                return;

            string fullPath;
            string error;
            if (!TryNormalizePrivatePath(
                path,
                out fullPath,
                out error))
            {
                return;
            }

            string root =
                Path.GetFullPath(GetRootPath())
                .TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar);

            if (String.Equals(
                fullPath,
                root,
                StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            try
            {
                if (Directory.Exists(fullPath))
                    Directory.Delete(fullPath, true);
            }
            catch
            {
            }
        }

        private static void PruneStaleSessions(
            string root)
        {
            try
            {
                if (!Directory.Exists(root))
                    return;

                DateTime cutoff =
                    DateTime.UtcNow.AddHours(-24);

                foreach (string directory in
                    Directory.GetDirectories(root))
                {
                    try
                    {
                        DirectoryInfo info =
                            new DirectoryInfo(directory);

                        if (info.LastWriteTimeUtc >= cutoff)
                            continue;

                        string details;
                        if (!IsPrivateDirectoryTrusted(
                            directory,
                            out details))
                        {
                            continue;
                        }

                        Directory.Delete(
                            directory,
                            true);
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
        }

        private static bool TryNormalizePrivatePath(
            string path,
            out string fullPath,
            out string error)
        {
            fullPath = String.Empty;
            error = String.Empty;

            if (String.IsNullOrWhiteSpace(path))
            {
                error = "Private staging path is empty.";
                return false;
            }

            try
            {
                string root =
                    Path.GetFullPath(GetRootPath())
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
                        "Private staging path is outside the managed RawStaging root.";
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                error =
                    "Unable to normalize private staging path: " +
                    ex.Message;
                return false;
            }
        }

        private static void HardenPrivateDirectory(
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

            Directory.SetAccessControl(
                path,
                security);
        }

        private static string Sanitize(string value)
        {
            string text =
                String.IsNullOrWhiteSpace(value)
                    ? "diagnostics"
                    : value.Trim();

            foreach (char c in Path.GetInvalidFileNameChars())
                text = text.Replace(c, '-');

            text = text.Replace(' ', '-');

            if (text.Length > 48)
                text = text.Substring(0, 48);

            return text;
        }
    }
}
