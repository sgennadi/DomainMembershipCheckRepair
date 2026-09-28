using System;
using System.IO;
using System.Text;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal static class SupportBundleRedactionService
    {
        internal static void SanitizeDirectory(
            string folder,
            SupportBundleSanitizer sanitizer)
        {
            SanitizeDirectory(
                folder,
                sanitizer,
                CancellationToken.None,
                null);
        }

        internal static void SanitizeDirectory(
            string folder,
            SupportBundleSanitizer sanitizer,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            if (String.IsNullOrWhiteSpace(folder))
                throw new ArgumentException("A source folder is required.", "folder");
            if (sanitizer == null)
                throw new ArgumentNullException("sanitizer");

            foreach (string file in Directory.GetFiles(folder, "*", SearchOption.AllDirectories))
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (progress != null)
                    progress("Sanitizing " + Path.GetFileName(file));

                try
                {
                    string raw = File.ReadAllText(file);
                    string sanitized = sanitizer.Sanitize(raw);
                    File.WriteAllText(
                        file,
                        sanitized,
                        new UTF8Encoding(false));
                }
                catch
                {
                    FailClosed(file);
                }
            }
        }

        internal static void WriteSummary(
            string folder,
            SupportBundleSanitizer sanitizer)
        {
            if (String.IsNullOrWhiteSpace(folder))
                throw new ArgumentException("A source folder is required.", "folder");
            if (sanitizer == null)
                throw new ArgumentNullException("sanitizer");

            File.WriteAllText(
                Path.Combine(folder, "redaction-summary.txt"),
                sanitizer.GetSummary(),
                new UTF8Encoding(false));
        }

        private static void FailClosed(string file)
        {
            try
            {
                File.WriteAllText(
                    file,
                    "[Content omitted because support-bundle sanitization failed.]\r\n",
                    new UTF8Encoding(false));
            }
            catch
            {
                try
                {
                    File.Delete(file);
                }
                catch
                {
                }
            }
        }
    }
}
