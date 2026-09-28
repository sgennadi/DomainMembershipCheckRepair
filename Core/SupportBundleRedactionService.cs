using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal static class SupportBundleRedactionService
    {
        internal static SupportBundleSanitizer CreateSanitizer(
            DiagnosticsSnapshot snapshot,
            AdComputerAccountInfo account)
        {
            List<string> values = new List<string>();
            AddKnownValue(values, Environment.MachineName);

            if (snapshot != null)
            {
                AddKnownValue(values, snapshot.ComputerName);
                AddKnownValue(values, snapshot.PhysicalDnsDomain);
                AddKnownValue(values, snapshot.PendingComputerName);
                AddKnownValue(values, snapshot.JoinedDomain);
                AddKnownValue(values, snapshot.TrustedDc);
                AddKnownValue(values, snapshot.TargetDomain);
                AddKnownValue(values, snapshot.PreferredDirectoryServer);
                AddKnownValue(values, snapshot.DiscoveredDnsDomain);
                AddKnownValue(values, snapshot.DiscoveredDc);
                AddKnownValue(values, snapshot.ForestName);
            }

            if (account != null)
            {
                AddKnownValue(values, account.DistinguishedName);
                AddKnownValue(values, account.LdapPath);
                AddKnownValue(values, account.DnsHostName);
                AddKnownValue(values, account.ObjectGuid);
                AddKnownValue(values, account.SamAccountName);
                AddKnownValue(values, account.Owner);
                AddKnownValue(values, account.CanonicalName);
            }

            return new SupportBundleSanitizer(values);
        }

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

        private static void AddKnownValue(
            List<string> values,
            string value)
        {
            if (!String.IsNullOrWhiteSpace(value))
                values.Add(value.Trim());
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
