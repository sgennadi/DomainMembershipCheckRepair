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
                string folder = GetSafetyFolder();
                Directory.CreateDirectory(folder);

                path = Path.Combine(
                    folder,
                    DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" +
                    Environment.MachineName + "-" +
                    Sanitize(operation) + "-prechange.zip");

                AdvancedDiagnosticsResult advanced = AdvancedDiagnosticsService.Analyze(
                    domain,
                    preferredDc,
                    String.IsNullOrWhiteSpace(computerName) ? Environment.MachineName : computerName,
                    user,
                    password);

                path = AdvancedSupportBundleService.Export(
                    advanced,
                    path,
                    false);

                return File.Exists(path);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                path = String.Empty;
                return false;
            }
        }

        private static string GetSafetyFolder()
        {
            string primary = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "Logs",
                "DomainMembershipCheckRepair",
                "SafetyBundles");

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
                    "SafetyBundles");
                Directory.CreateDirectory(fallback);
                return fallback;
            }
        }

        private static string Sanitize(string value)
        {
            string text = String.IsNullOrWhiteSpace(value) ? "operation" : value.Trim();
            foreach (char c in Path.GetInvalidFileNameChars())
                text = text.Replace(c, '-');
            return text.Replace(' ', '-');
        }
    }
}
