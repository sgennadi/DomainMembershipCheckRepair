using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class LabArtifactTool
    {
        private static readonly HashSet<string> TextExtensions =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                ".txt", ".json", ".log", ".xml", ".csv", ".md"
            };

        private static readonly string[] SensitiveEnvironmentVariables =
        {
            "AD_LAB_DOMAIN",
            "AD_LAB_DC",
            "AD_LAB_COMPUTER",
            "AD_LAB_TEST_OU_DN",
            "AD_LAB_USER",
            "AD_LAB_PASSWORD",
            "COMPUTERNAME",
            "USERDOMAIN",
            "USERNAME"
        };

        internal static int Sanitize(CommandLine options)
        {
            string input = Path.GetFullPath(options.Require("input"));
            string output = Path.GetFullPath(options.Require("output"));

            if (!Directory.Exists(input))
                throw new DirectoryNotFoundException("Input lab artifact directory does not exist.");

            if (Directory.Exists(output))
                Directory.Delete(output, true);
            Directory.CreateDirectory(output);

            List<string> knownValues = new List<string>();
            List<string> secretValues = new List<string>();

            foreach (string name in SensitiveEnvironmentVariables)
            {
                string value = Environment.GetEnvironmentVariable(name);
                if (String.IsNullOrWhiteSpace(value))
                    continue;

                if (Regex.IsMatch(name, "(password|secret|token|key)", RegexOptions.IgnoreCase))
                    secretValues.Add(value);
                else
                    knownValues.Add(value);
            }

            SupportBundleSanitizer sanitizer = new SupportBundleSanitizer(knownValues);
            int processed = 0;
            int omitted = 0;

            foreach (string file in Directory.GetFiles(input, "*", SearchOption.AllDirectories))
            {
                string relative = file.Substring(input.TrimEnd(Path.DirectorySeparatorChar).Length)
                    .TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                string destination = Path.Combine(output, relative);
                string directory = Path.GetDirectoryName(destination);
                if (!String.IsNullOrWhiteSpace(directory))
                    Directory.CreateDirectory(directory);

                if (!TextExtensions.Contains(Path.GetExtension(file)))
                {
                    File.WriteAllText(
                        destination + ".omitted.txt",
                        "[OMITTED: non-text lab artifact]" + Environment.NewLine,
                        new UTF8Encoding(false));
                    omitted++;
                    continue;
                }

                try
                {
                    string text = File.ReadAllText(file);
                    foreach (string secret in secretValues)
                        text = ReplaceExact(text, secret, "[REDACTED]");

                    string sanitized = sanitizer.Sanitize(text);
                    File.WriteAllText(destination, sanitized, new UTF8Encoding(false));
                    processed++;
                }
                catch
                {
                    File.WriteAllText(
                        destination,
                        "[OMITTED: artifact could not be sanitized safely]" + Environment.NewLine,
                        new UTF8Encoding(false));
                    omitted++;
                }
            }

            StringBuilder summary = new StringBuilder();
            summary.AppendLine("Sanitized lab artifact set");
            summary.AppendLine("==========================");
            summary.AppendLine("Processed text files: " + processed);
            summary.AppendLine("Omitted files: " + omitted);
            summary.AppendLine();
            summary.AppendLine(sanitizer.GetSummary());
            summary.AppendLine("The per-run HMAC key used for opaque tokens is not persisted.");
            File.WriteAllText(
                Path.Combine(output, "redaction-summary.txt"),
                summary.ToString(),
                new UTF8Encoding(false));

            Console.WriteLine("Sanitized lab artifacts: " + processed + " text file(s), " + omitted + " omitted file(s).");
            return 0;
        }

        internal static int Test()
        {
            string root = Path.Combine(Path.GetTempPath(), "dmcr-lab-redaction-" + Guid.NewGuid().ToString("N"));
            string input = Path.Combine(root, "raw");
            string output = Path.Combine(root, "sanitized");
            Directory.CreateDirectory(input);

            Dictionary<string, string> oldValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string[] names =
            {
                "AD_LAB_DOMAIN",
                "AD_LAB_DC",
                "AD_LAB_COMPUTER",
                "AD_LAB_TEST_OU_DN",
                "AD_LAB_USER",
                "AD_LAB_PASSWORD"
            };

            try
            {
                foreach (string name in names)
                    oldValues[name] = Environment.GetEnvironmentVariable(name);

                Environment.SetEnvironmentVariable("AD_LAB_DOMAIN", "example.test");
                Environment.SetEnvironmentVariable("AD_LAB_DC", "dc01.example.test");
                Environment.SetEnvironmentVariable("AD_LAB_COMPUTER", "LAB-PC01");
                Environment.SetEnvironmentVariable("AD_LAB_TEST_OU_DN", "OU=DMCR-Lab,DC=example,DC=test");
                Environment.SetEnvironmentVariable("AD_LAB_USER", "EXAMPLE\\lab-admin");
                Environment.SetEnvironmentVariable("AD_LAB_PASSWORD", "SuperSecret-123!");

                File.WriteAllText(
                    Path.Combine(input, "sample.txt"),
                    "Computer=LAB-PC01\r\n" +
                    "Domain=example.test\r\n" +
                    "DC=dc01.example.test\r\n" +
                    "User=EXAMPLE\\lab-admin\r\n" +
                    "UPN=admin@example.test\r\n" +
                    "IPv4=10.20.30.40\r\n" +
                    "IPv6=2001:db8:0:0:0:0:0:1234\r\n" +
                    "SID=S-1-5-21-111111111-222222222-333333333-1001\r\n" +
                    "GUID=12345678-1234-1234-1234-123456789abc\r\n" +
                    "MAC=00-11-22-33-44-55\r\n" +
                    "DN=CN=LAB-PC01,OU=DMCR-Lab,DC=example,DC=test\r\n" +
                    "Share=\\\\dc01.example.test\\share\r\n" +
                    "password=SuperSecret-123!\r\n" +
                    "Authorization: Bearer abc.def.ghi.longtoken\r\n",
                    new UTF8Encoding(false));

                CommandLine command = CommandLine.Parse(
                    new string[] { "sanitize-lab", "--input", input, "--output", output },
                    1);

                int result = Sanitize(command);
                if (result != 0)
                    throw new InvalidOperationException("Sanitizer returned a non-zero result.");

                StringBuilder combined = new StringBuilder();
                foreach (string file in Directory.GetFiles(output, "*", SearchOption.AllDirectories))
                    combined.AppendLine(File.ReadAllText(file));

                string all = combined.ToString();
                string[] forbidden =
                {
                    "LAB-PC01",
                    "example.test",
                    "dc01.example.test",
                    "EXAMPLE\\lab-admin",
                    "admin@example.test",
                    "10.20.30.40",
                    "2001:db8:0:0:0:0:0:1234",
                    "S-1-5-21-111111111-222222222-333333333-1001",
                    "12345678-1234-1234-1234-123456789abc",
                    "00-11-22-33-44-55",
                    "OU=DMCR-Lab",
                    "\\\\dc01.example.test\\share",
                    "SuperSecret-123!",
                    "abc.def.ghi.longtoken"
                };

                foreach (string value in forbidden)
                {
                    if (all.IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0)
                        throw new InvalidOperationException("Lab sanitizer regression: sensitive test data remains.");
                }

                if (all.IndexOf("[REDACTED]", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Lab sanitizer regression: secret marker is missing.");

                if (all.IndexOf("<", StringComparison.Ordinal) < 0 ||
                    all.IndexOf(":", StringComparison.Ordinal) < 0)
                    throw new InvalidOperationException("Lab sanitizer regression: opaque identifier token is missing.");

                Console.WriteLine("Lab artifact sanitizer regression test passed.");
                return 0;
            }
            finally
            {
                foreach (string name in names)
                    Environment.SetEnvironmentVariable(name, oldValues[name]);

                try
                {
                    if (Directory.Exists(root))
                        Directory.Delete(root, true);
                }
                catch
                {
                }
            }
        }

        private static string ReplaceExact(string input, string value, string replacement)
        {
            if (String.IsNullOrEmpty(value))
                return input;

            return Regex.Replace(
                input,
                Regex.Escape(value),
                delegate { return replacement; },
                RegexOptions.IgnoreCase);
        }
    }
}
