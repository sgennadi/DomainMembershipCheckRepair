using System;
using System.IO;

namespace DomainMembershipCheckRepair
{
    internal static class SafetyBundleService
    {
        internal static bool TryCreate(
            string operation,
            string domain,
            string preferredDc,
            string computerName,
            string user,
            string password,
            out string path,
            out string error)
        {
            path = String.Empty;
            error = String.Empty;

            try
            {
                string folder = GetSafetyFolderPath();

                string storageDetails;
                if (!ProtectedStorageAcl.EnsureProtectedDirectory(
                    folder,
                    out storageDetails))
                {
                    throw new IOException(
                        "Safety bundle storage could not be prepared securely: " +
                        storageDetails);
                }

                path = Path.Combine(
                    folder,
                    DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" +
                    Sanitize(operation) +
                    "-prechange-sanitized.zip");

                if (!ProtectedStorageAcl.PrepareProtectedFileTarget(
                    path,
                    out storageDetails))
                {
                    throw new IOException(
                        "Safety bundle destination failed protected-file preflight: " +
                        storageDetails);
                }

                AdvancedDiagnosticsResult advanced =
                    AdvancedDiagnosticsService.Analyze(
                        domain,
                        preferredDc,
                        String.IsNullOrWhiteSpace(computerName)
                            ? Environment.MachineName
                            : computerName,
                        user,
                        password);

                path = AdvancedSupportBundleService.Export(
                    advanced,
                    path,
                    false);

                if (!File.Exists(path))
                    throw new IOException(
                        "Safety bundle export did not create the expected archive.");

                if (!ProtectedStorageAcl.HardenProtectedFile(
                    path,
                    out storageDetails))
                {
                    throw new IOException(
                        "Safety bundle archive could not be owner/ACL hardened after commit: " +
                        storageDetails);
                }

                if (!ProtectedStorageAcl.IsProtectedFileTrusted(
                    path,
                    out storageDetails))
                {
                    throw new IOException(
                        "Safety bundle archive failed final trust verification: " +
                        storageDetails);
                }

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                path = String.Empty;
                return false;
            }
        }

        internal static string GetSafetyFolderPath()
        {
            return ProtectedStorageAcl.GetManagedChildPath(
                "SafetyBundles");
        }

        internal static bool CheckStorageSecurity(
            out string details)
        {
            string folder = GetSafetyFolderPath();
            if (!Directory.Exists(folder))
            {
                details =
                    "Safety bundle folder does not exist yet: " +
                    folder;
                return false;
            }

            return ProtectedStorageAcl.IsProtectedDirectoryTrusted(
                folder,
                out details);
        }

        private static string Sanitize(string value)
        {
            string text =
                String.IsNullOrWhiteSpace(value)
                    ? "operation"
                    : value.Trim();

            foreach (char c in Path.GetInvalidFileNameChars())
                text = text.Replace(c, '-');

            return text.Replace(' ', '-');
        }
    }
}
