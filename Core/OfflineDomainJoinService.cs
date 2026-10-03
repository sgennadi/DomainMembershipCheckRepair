using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal static class OfflineDomainJoinService
    {
        internal static int ApplyBlob(string blobPath, out string output)
        {
            output = String.Empty;
            if (String.IsNullOrWhiteSpace(blobPath) || !File.Exists(blobPath))
            {
                output = "Offline Domain Join blob was not found.";
                return 3;
            }

            string full;
            try
            {
                full = Path.GetFullPath(blobPath);
            }
            catch (Exception ex)
            {
                output =
                    "Invalid Offline Domain Join blob path: " +
                    ex.Message;
                return 3;
            }

            string staging = String.Empty;
            try
            {
                staging =
                    PrivateStagingService.CreateSession(
                        "odj-apply");

                string stagedBlob =
                    Path.Combine(
                        staging,
                        "provisioning-blob.txt");

                string copyError;
                if (!CopyBlobSnapshot(
                    full,
                    stagedBlob,
                    out copyError))
                {
                    output =
                        "Offline Domain Join blob could not be snapshotted securely before apply: " +
                        copyError;
                    return 3;
                }

                string[] arguments = BuildApplyArgumentList(
                    stagedBlob,
                    Environment.GetFolderPath(
                        Environment.SpecialFolder.Windows));

                return RunDjoin(
                    arguments,
                    out output);
            }
            catch (Exception ex)
            {
                output =
                    "Offline Domain Join apply failed before djoin.exe could run: " +
                    ex.Message;
                return 1;
            }
            finally
            {
                PrivateStagingService.DeleteSession(
                    staging);
            }
        }

        internal static bool CopyBlobSnapshot(
            string sourcePath,
            string destinationPath,
            out string error)
        {
            error = String.Empty;

            if (String.IsNullOrWhiteSpace(sourcePath) ||
                !File.Exists(sourcePath))
            {
                error =
                    "Source provisioning blob does not exist.";
                return false;
            }

            if (String.IsNullOrWhiteSpace(destinationPath))
            {
                error =
                    "Private provisioning snapshot destination is empty.";
                return false;
            }

            try
            {
                string source =
                    Path.GetFullPath(sourcePath);
                string destination =
                    Path.GetFullPath(destinationPath);

                FileAttributes attributes =
                    File.GetAttributes(source);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    error =
                        "Source provisioning blob is a reparse point.";
                    return false;
                }

                string sourceFolder =
                    Path.GetDirectoryName(source);
                string pathDetails;
                if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                    sourceFolder,
                    out pathDetails))
                {
                    error =
                        "Source provisioning blob path failed reparse-point verification: " +
                        pathDetails;
                    return false;
                }

                string destinationFolder =
                    Path.GetDirectoryName(destination);
                if (String.IsNullOrWhiteSpace(destinationFolder) ||
                    !Directory.Exists(destinationFolder))
                {
                    error =
                        "Private provisioning snapshot destination folder does not exist.";
                    return false;
                }

                string stagingDetails;
                if (!PrivateStagingService.IsPrivateDirectoryTrusted(
                    destinationFolder,
                    out stagingDetails))
                {
                    error =
                        "Private provisioning snapshot destination is not trusted: " +
                        stagingDetails;
                    return false;
                }

                if (File.Exists(destination))
                {
                    error =
                        "Private provisioning snapshot destination already exists.";
                    return false;
                }

                using (FileStream input =
                    new FileStream(
                        source,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read))
                {
                    FileAttributes openedAttributes =
                        File.GetAttributes(source);
                    if ((openedAttributes & FileAttributes.ReparsePoint) != 0)
                    {
                        error =
                            "Source provisioning blob became a reparse point before snapshot copy.";
                        return false;
                    }

                    string openedPathDetails;
                    if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                        sourceFolder,
                        out openedPathDetails))
                    {
                        error =
                            "Source provisioning blob path changed during secure open: " +
                            openedPathDetails;
                        return false;
                    }

                    if (input.Length <= 0)
                    {
                        error =
                            "Source provisioning blob is empty.";
                        return false;
                    }

                    SecurityIdentifier snapshotUser;
                    using (WindowsIdentity identity =
                        WindowsIdentity.GetCurrent())
                    {
                        if (identity == null ||
                            identity.User == null)
                        {
                            error =
                                "Current Windows user SID is unavailable for snapshot creation.";
                            return false;
                        }

                        snapshotUser = identity.User;
                    }

                    FileSecurity snapshotSecurity =
                        CreateProvisioningBlobSecurity(
                            snapshotUser);

                    using (FileStream outputStream =
                        new FileStream(
                            destination,
                            FileMode.CreateNew,
                            FileSystemRights.FullControl,
                            FileShare.None,
                            4096,
                            FileOptions.WriteThrough,
                            snapshotSecurity))
                    {
                        input.CopyTo(outputStream);
                        outputStream.Flush(true);
                    }
                }

                if (!File.Exists(destination) ||
                    new FileInfo(destination).Length <= 0)
                {
                    error =
                        "Private provisioning snapshot was not created correctly.";
                    return false;
                }

                SecurityIdentifier currentUser;
                using (WindowsIdentity identity =
                    WindowsIdentity.GetCurrent())
                {
                    if (identity == null ||
                        identity.User == null)
                    {
                        error =
                            "Current Windows user SID is unavailable for snapshot verification.";
                        TryDeleteSnapshot(destination);
                        return false;
                    }

                    currentUser = identity.User;
                }

                string snapshotDetails;
                if (!IsProvisioningBlobTrusted(
                    destination,
                    currentUser,
                    out snapshotDetails))
                {
                    error =
                        "Private provisioning snapshot ACL verification failed: " +
                        snapshotDetails;
                    TryDeleteSnapshot(destination);
                    return false;
                }

                return true;
            }
            catch (Exception ex)
            {
                error =
                    "Unable to create private provisioning blob snapshot: " +
                    ex.Message;
                return false;
            }
        }

        private static void TryDeleteSnapshot(string path)
        {
            try
            {
                if (!String.IsNullOrWhiteSpace(path) &&
                    File.Exists(path))
                {
                    File.Delete(path);
                }
            }
            catch
            {
            }
        }

        internal static int ProvisionBlob(string domain, string machine, string outputPath, bool reuse, out string output)
        {
            output = String.Empty;
            if (String.IsNullOrWhiteSpace(domain) || String.IsNullOrWhiteSpace(machine) || String.IsNullOrWhiteSpace(outputPath))
            {
                output = "Domain, machine name, and output path are required.";
                return 3;
            }

            string domainError = DomainValidation.ValidateDomainArgument(domain);
            if (domainError != null)
            {
                output = "Invalid domain: " + domainError;
                return 3;
            }

            string machineError = DomainValidation.ValidateComputerName(machine);
            if (machineError != null)
            {
                output = "Invalid computer name: " + machineError;
                return 3;
            }

            string fullOutputPath;
            try
            {
                fullOutputPath = Path.GetFullPath(outputPath);
            }
            catch (Exception ex)
            {
                output = "Invalid output path: " + ex.Message;
                return 3;
            }

            if (File.Exists(fullOutputPath))
            {
                output =
                    "Offline Domain Join output already exists. Refusing to overwrite a provisioning blob: " +
                    fullOutputPath;
                return 3;
            }

            string staging = String.Empty;
            try
            {
                staging =
                    PrivateStagingService.CreateSession(
                        "odj-provision");

                string stagedBlob =
                    Path.Combine(
                        staging,
                        "provisioning-blob.txt");

                string[] args = BuildProvisionArgumentList(
                    domain.Trim(),
                    machine.Trim(),
                    stagedBlob,
                    reuse);

                string djoinOutput;
                int code =
                    RunDjoin(
                        args,
                        out djoinOutput);

                if (code != 0)
                {
                    output = djoinOutput;
                    return code;
                }

                if (!File.Exists(stagedBlob) ||
                    new FileInfo(stagedBlob).Length == 0)
                {
                    output =
                        "djoin.exe reported success but did not create a non-empty provisioning blob.";
                    return 1;
                }

                string commitError;
                if (!CommitProvisionedBlob(
                    stagedBlob,
                    fullOutputPath,
                    out commitError))
                {
                    output =
                        "Offline Domain Join provisioning succeeded, but the blob could not be committed securely: " +
                        commitError;
                    return 1;
                }

                output =
                    (djoinOutput ?? String.Empty).TrimEnd() +
                    Environment.NewLine +
                    "Protected provisioning blob: " +
                    fullOutputPath;
                return 0;
            }
            catch (Exception ex)
            {
                output =
                    "Offline Domain Join provisioning failed: " +
                    ex.Message;
                return 1;
            }
            finally
            {
                PrivateStagingService.DeleteSession(
                    staging);
            }
        }

        internal static bool CommitProvisionedBlob(
            string sourcePath,
            string destinationPath,
            out string error)
        {
            error = String.Empty;

            if (String.IsNullOrWhiteSpace(sourcePath) ||
                !File.Exists(sourcePath))
            {
                error =
                    "Private staged provisioning blob does not exist.";
                return false;
            }

            string destination;
            try
            {
                destination =
                    Path.GetFullPath(destinationPath);
            }
            catch (Exception ex)
            {
                error =
                    "Invalid provisioning blob destination: " +
                    ex.Message;
                return false;
            }

            if (File.Exists(destination))
            {
                error =
                    "Provisioning blob destination already exists; overwrite is not allowed.";
                return false;
            }

            string folder =
                Path.GetDirectoryName(destination);
            if (String.IsNullOrWhiteSpace(folder))
            {
                error =
                    "Provisioning blob destination has no parent directory.";
                return false;
            }

            string temp =
                destination +
                ".tmp-" +
                Guid.NewGuid().ToString("N");

            bool destinationCreated = false;

            try
            {
                string pathDetails;
                if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                    folder,
                    out pathDetails))
                {
                    error =
                        "Provisioning blob destination path failed reparse-point verification: " +
                        pathDetails;
                    return false;
                }

                Directory.CreateDirectory(folder);

                if (!ProtectedStorageAcl.IsDirectoryPathFreeOfReparsePoints(
                    folder,
                    out pathDetails))
                {
                    error =
                        "Provisioning blob destination path failed reparse-point verification after creation: " +
                        pathDetails;
                    return false;
                }

                SecurityIdentifier currentUser;
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

                    currentUser = identity.User;
                }

                if (!IsProvisioningDestinationDirectoryTrusted(
                    folder,
                    currentUser,
                    out error))
                {
                    return false;
                }

                FileSecurity security =
                    CreateProvisioningBlobSecurity(
                        currentUser);

                using (FileStream input =
                    new FileStream(
                        sourcePath,
                        FileMode.Open,
                        FileAccess.Read,
                        FileShare.Read))
                using (FileStream outputStream =
                    new FileStream(
                        temp,
                        FileMode.CreateNew,
                        FileSystemRights.FullControl,
                        FileShare.None,
                        4096,
                        FileOptions.WriteThrough,
                        security))
                {
                    input.CopyTo(outputStream);
                    outputStream.Flush(true);
                }

                if (!File.Exists(temp) ||
                    new FileInfo(temp).Length == 0)
                {
                    error =
                        "Protected temporary provisioning blob was not written correctly.";
                    return false;
                }

                if (!IsProvisioningBlobTrusted(
                    temp,
                    currentUser,
                    out error))
                {
                    return false;
                }

                File.Move(
                    temp,
                    destination);
                destinationCreated = true;

                if (!IsProvisioningBlobTrusted(
                    destination,
                    currentUser,
                    out error))
                {
                    try
                    {
                        File.Delete(destination);
                    }
                    catch
                    {
                    }

                    destinationCreated = false;
                    return false;
                }

                error = String.Empty;
                return true;
            }
            catch (Exception ex)
            {
                error =
                    "Unable to commit the protected provisioning blob: " +
                    ex.Message;
                return false;
            }
            finally
            {
                try
                {
                    if (File.Exists(temp))
                        File.Delete(temp);
                }
                catch
                {
                }

                if (!String.IsNullOrWhiteSpace(error) &&
                    destinationCreated)
                {
                    try
                    {
                        if (File.Exists(destination))
                            File.Delete(destination);
                    }
                    catch
                    {
                    }
                }
            }
        }

        internal static bool IsUntrustedProvisioningDirectoryWriteGrant(
            SecurityIdentifier sid,
            SecurityIdentifier currentUserSid,
            FileSystemRights rights,
            AccessControlType accessType)
        {
            if (sid == null ||
                accessType != AccessControlType.Allow ||
                !ProtectedStorageAcl.HasWriteCapability(rights))
            {
                return false;
            }

            if (currentUserSid != null &&
                sid.Equals(currentUserSid))
            {
                return false;
            }

            if (sid.IsWellKnown(
                WellKnownSidType.CreatorOwnerSid))
            {
                return false;
            }

            return !ProtectedStorageAcl.IsTrustedOwner(
                sid);
        }

        private static bool IsProvisioningDestinationDirectoryTrusted(
            string path,
            SecurityIdentifier currentUser,
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

                bool ownerTrusted =
                    owner != null &&
                    ((currentUser != null &&
                      owner.Equals(currentUser)) ||
                     ProtectedStorageAcl.IsTrustedOwner(owner));

                if (!ownerTrusted)
                {
                    details =
                        "Provisioning blob destination folder owner is not the current user, LocalSystem or Administrators.";
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

                    if (IsUntrustedProvisioningDirectoryWriteGrant(
                        sid,
                        currentUser,
                        rule.FileSystemRights,
                        rule.AccessControlType))
                    {
                        details =
                            "Another identity has write/delete-capable access to the provisioning blob destination folder.";
                        return false;
                    }
                }

                details =
                    "Provisioning blob destination folder does not grant write/delete-capable access to other identities.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to verify provisioning blob destination folder ACL: " +
                    ex.Message;
                return false;
            }
        }

        internal static bool IsUntrustedProvisioningBlobAllowRule(
            SecurityIdentifier sid,
            SecurityIdentifier currentUserSid,
            AccessControlType accessType)
        {
            if (sid == null ||
                accessType != AccessControlType.Allow)
            {
                return false;
            }

            if (currentUserSid != null &&
                sid.Equals(currentUserSid))
            {
                return false;
            }

            return !ProtectedStorageAcl.IsTrustedOwner(
                sid);
        }

        private static FileSecurity CreateProvisioningBlobSecurity(
            SecurityIdentifier currentUser)
        {
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

            return security;
        }

        private static bool IsProvisioningBlobTrusted(
            string path,
            SecurityIdentifier currentUser,
            out string details)
        {
            details = String.Empty;

            try
            {
                if (!File.Exists(path))
                {
                    details =
                        "Provisioning blob does not exist.";
                    return false;
                }

                FileAttributes attributes =
                    File.GetAttributes(path);
                if ((attributes & FileAttributes.ReparsePoint) != 0)
                {
                    details =
                        "Provisioning blob is a reparse point.";
                    return false;
                }

                FileSecurity security =
                    File.GetAccessControl(
                        path,
                        AccessControlSections.Owner |
                        AccessControlSections.Access);

                SecurityIdentifier owner =
                    security.GetOwner(
                        typeof(SecurityIdentifier))
                    as SecurityIdentifier;

                bool ownerTrusted =
                    owner != null &&
                    ((currentUser != null &&
                      owner.Equals(currentUser)) ||
                     ProtectedStorageAcl.IsTrustedOwner(owner));

                if (!ownerTrusted)
                {
                    details =
                        "Provisioning blob owner is not the current user, LocalSystem or Administrators.";
                    return false;
                }

                if (!security.AreAccessRulesProtected)
                {
                    details =
                        "Provisioning blob ACL still inherits access rules.";
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

                    if (IsUntrustedProvisioningBlobAllowRule(
                        sid,
                        currentUser,
                        rule.AccessControlType))
                    {
                        details =
                            "Another identity has allow access to the provisioning blob.";
                        return false;
                    }
                }

                details =
                    "Provisioning blob ACL is restricted to the current user, LocalSystem and Administrators.";
                return true;
            }
            catch (Exception ex)
            {
                details =
                    "Unable to verify provisioning blob ACL: " +
                    ex.Message;
                return false;
            }
        }

        private static int RunDjoin(
            IEnumerable<string> arguments,
            out string output)
        {
            string djoin =
                Path.Combine(
                    Environment.SystemDirectory,
                    "djoin.exe");
            CommandResult result =
                ProcessRunner.RunArguments(
                    djoin,
                    arguments,
                    120000);

            output = result.CombinedOutput;
            if (!String.IsNullOrWhiteSpace(result.Error))
            {
                output = result.Error + Environment.NewLine + output;
                return 1;
            }

            if (result.TimedOut)
            {
                output += Environment.NewLine + "djoin.exe timed out after 120 seconds.";
                return 1;
            }

            return result.ExitCode;
        }

        internal static string BuildApplyArguments(
            string blobPath,
            string windowsPath)
        {
            return WindowsCommandLine.BuildArguments(
                BuildApplyArgumentList(blobPath, windowsPath));
        }

        internal static string BuildProvisionArguments(
            string domain,
            string machine,
            string outputPath,
            bool reuse)
        {
            return WindowsCommandLine.BuildArguments(
                BuildProvisionArgumentList(
                    domain,
                    machine,
                    outputPath,
                    reuse));
        }
        private static string[] BuildApplyArgumentList(
            string blobPath,
            string windowsPath)
        {
            return new string[]
            {
                "/requestODJ",
                "/loadfile",
                blobPath ?? String.Empty,
                "/windowspath",
                windowsPath ?? String.Empty,
                "/localos"
            };
        }

        private static string[] BuildProvisionArgumentList(
            string domain,
            string machine,
            string outputPath,
            bool reuse)
        {
            List<string> arguments = new List<string>();
            arguments.Add("/provision");
            arguments.Add("/domain");
            arguments.Add(domain ?? String.Empty);
            arguments.Add("/machine");
            arguments.Add(machine ?? String.Empty);
            arguments.Add("/savefile");
            arguments.Add(outputPath ?? String.Empty);

            if (reuse)
                arguments.Add("/reuse");

            return arguments.ToArray();
        }

    }
}
