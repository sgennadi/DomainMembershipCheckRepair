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
