using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DomainMembershipCheckRepair
{
    internal static class ProtectedStorageAcl
    {
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
            // Use only primitive write/delete/ACL-change bits here.
            // Composite values such as FullControl and Modify include read bits,
            // so OR-ing those composites into a mask would incorrectly classify
            // a read-only rule as writable.
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

        private static bool IsBroadIdentity(SecurityIdentifier sid)
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
