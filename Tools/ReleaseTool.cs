using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class ReleaseTool
    {
        private sealed class ReleaseBinary
        {
            internal string Name;
            internal string BuildPath;
            internal string ConfigPath;
            internal ushort Machine;
        }

        private static readonly ReleaseBinary[] Binaries =
        {
            new ReleaseBinary
            {
                Name = "DomainMembershipCheckRepair-x86.exe",
                BuildPath = @"bin\Release\x86\DomainMembershipCheckRepair.exe",
                ConfigPath = @"bin\Release\x86\DomainMembershipCheckRepair.exe.config",
                Machine = 0x014c
            },
            new ReleaseBinary
            {
                Name = "DomainMembershipCheckRepair-x64.exe",
                BuildPath = @"bin\Release\x64\DomainMembershipCheckRepair.exe",
                ConfigPath = @"bin\Release\x64\DomainMembershipCheckRepair.exe.config",
                Machine = 0x8664
            },
            new ReleaseBinary
            {
                Name = "DomainMembershipCheckRepair-arm64.exe",
                BuildPath = @"bin\Release\ARM64\DomainMembershipCheckRepair.exe",
                ConfigPath = @"bin\Release\ARM64\DomainMembershipCheckRepair.exe.config",
                Machine = 0xaa64
            }
        };

        internal static int ValidateTag(CommandLine options)
        {
            string root = Path.GetFullPath(options.Get("root", Environment.CurrentDirectory));
            string refName = options.Get("tag", Environment.GetEnvironmentVariable("GITHUB_REF_NAME") ?? String.Empty);
            string version = ReadSourceVersion(root);
            string expected = "v" + version;

            if (!String.Equals(refName, expected, StringComparison.Ordinal))
                throw new InvalidOperationException("Release tag '" + refName + "' does not match VersionInfo.cs ('" + expected + "').");

            Console.WriteLine("Release tag validated: " + refName);
            return 0;
        }

        internal static int Prepare(CommandLine options)
        {
            string root = Path.GetFullPath(options.Get("root", Environment.CurrentDirectory));
            string unsignedDirectory = Path.GetFullPath(options.Get("unsigned", Path.Combine(root, "unsigned")));
            string configDirectory = Path.GetFullPath(options.Get("configs", Path.Combine(root, "release-configs")));
            string githubOutput = options.Get("github-output", Environment.GetEnvironmentVariable("GITHUB_OUTPUT") ?? String.Empty);

            RecreateDirectory(unsignedDirectory);
            RecreateDirectory(configDirectory);

            foreach (ReleaseBinary binary in Binaries)
            {
                string exe = Path.Combine(root, binary.BuildPath);
                string config = Path.Combine(root, binary.ConfigPath);

                RequireFile(exe);
                RequireFile(config);
                RequirePerMonitorV2(config);

                File.Copy(exe, Path.Combine(unsignedDirectory, binary.Name), true);
                File.Copy(config, Path.Combine(configDirectory, binary.Name + ".config"), true);
            }

            string x64 = Path.Combine(root, Binaries[1].BuildPath);
            string builtVersion = FileVersionInfo.GetVersionInfo(x64).ProductVersion ?? String.Empty;
            string sourceVersion = ReadSourceVersion(root);

            if (String.IsNullOrWhiteSpace(builtVersion))
                throw new InvalidOperationException("Unable to read ProductVersion from the built x64 executable.");

            if (!String.Equals(builtVersion, sourceVersion, StringComparison.Ordinal))
                throw new InvalidOperationException("Built ProductVersion does not match VersionInfo.cs.");

            if (!String.IsNullOrWhiteSpace(githubOutput))
                File.AppendAllText(githubOutput, "product_version=" + builtVersion + Environment.NewLine, new UTF8Encoding(false));

            Console.WriteLine("Prepared unsigned release binaries.");
            Console.WriteLine("ProductVersion: " + builtVersion);
            return 0;
        }

        internal static int ValidateSignPathConfiguration(CommandLine options)
        {
            string organizationId = Environment.GetEnvironmentVariable("SIGNPATH_ORGANIZATION_ID");
            string apiToken = Environment.GetEnvironmentVariable("SIGNPATH_API_TOKEN");

            if (String.IsNullOrWhiteSpace(organizationId))
                throw new InvalidOperationException("SIGNPATH_ORGANIZATION_ID repository variable is required.");
            if (String.IsNullOrWhiteSpace(apiToken))
                throw new InvalidOperationException("SIGNPATH_API_TOKEN repository secret is required.");

            Console.WriteLine("Mandatory SignPath configuration is present.");
            return 0;
        }

        internal static int ValidateSigned(CommandLine options)
        {
            string signedDirectory = Path.GetFullPath(options.Get("signed", "signed"));
            string expectedVersion = options.Require("expected-version");
            string expectedSigner = options.Get(
                "expected-signer",
                Environment.GetEnvironmentVariable("SIGNPATH_EXPECTED_SIGNER_SUBJECT") ?? String.Empty);

            string signtool = FindSignTool();

            foreach (ReleaseBinary binary in Binaries)
            {
                string file = FindUniqueFile(signedDirectory, binary.Name);

                ProcessResult verify = ProcessHelper.Run(
                    signtool,
                    new string[] { "verify", "/pa", "/v", file },
                    180000);
                if (verify.TimedOut || verify.ExitCode != 0)
                    throw new InvalidOperationException("Authenticode verification failed for " + binary.Name + ".");

                string verificationText = (verify.StandardOutput ?? String.Empty) + Environment.NewLine + (verify.StandardError ?? String.Empty);
                if (verificationText.IndexOf("timestamp", StringComparison.OrdinalIgnoreCase) < 0)
                    throw new InvalidOperationException("Trusted timestamp evidence is missing for " + binary.Name + ".");

                X509Certificate2 signer;
                try
                {
                    signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("Unable to read signer certificate for " + binary.Name + ": " + ex.Message);
                }

                using (signer)
                {
                    if (!String.IsNullOrWhiteSpace(expectedSigner) &&
                        signer.Subject.IndexOf(expectedSigner, StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        throw new InvalidOperationException("Signer subject does not match the configured expected signer for " + binary.Name + ".");
                    }

                    Console.WriteLine(binary.Name + " signer: " + signer.Subject);
                }

                string version = FileVersionInfo.GetVersionInfo(file).ProductVersion ?? String.Empty;
                if (!String.Equals(version, expectedVersion, StringComparison.Ordinal))
                    throw new InvalidOperationException(binary.Name + " ProductVersion does not match the expected release version.");

                ushort machine = ReadPeMachine(file);
                if (machine != binary.Machine)
                    throw new InvalidOperationException(binary.Name + " has an unexpected PE architecture.");
            }

            Console.WriteLine("All SignPath-signed executables passed Authenticode, timestamp, version and architecture validation.");
            return 0;
        }

        internal static int FinalizeFiles(CommandLine options)
        {
            string signedDirectory = Path.GetFullPath(options.Get("signed", "signed"));
            string configDirectory = Path.GetFullPath(options.Get("configs", "release-configs"));
            string outputDirectory = Path.GetFullPath(options.Get("output", "release-files"));
            string tag = options.Get("tag", Environment.GetEnvironmentVariable("GITHUB_REF_NAME") ?? String.Empty);

            RecreateDirectory(outputDirectory);

            foreach (ReleaseBinary binary in Binaries)
            {
                string signed = FindUniqueFile(signedDirectory, binary.Name);
                string config = Path.Combine(configDirectory, binary.Name + ".config");
                RequireFile(config);

                File.Copy(signed, Path.Combine(outputDirectory, binary.Name), true);
                File.Copy(config, Path.Combine(outputDirectory, binary.Name + ".config"), true);
            }

            WriteChecksums(outputDirectory);
            WriteReleaseNotes(outputDirectory, tag);

            Console.WriteLine("Final release files prepared.");
            return 0;
        }

        internal static int Smoke(CommandLine options)
        {
            string directory = Path.GetFullPath(options.Get("directory", "release-files"));

            string[] runnable =
            {
                "DomainMembershipCheckRepair-x86.exe",
                "DomainMembershipCheckRepair-x64.exe"
            };

            foreach (string name in runnable)
            {
                string file = Path.Combine(directory, name);
                RequireFile(file);

                ProcessResult result = ProcessHelper.Run(
                    file,
                    new string[] { "--cli", "--action", "ui-smoke", "--json" },
                    180000);

                if (result.TimedOut || result.ExitCode != 0)
                    throw new InvalidOperationException(name + " GUI/DPI smoke test failed.");

                Console.WriteLine("GUI/DPI smoke passed: " + name);
            }

            VerifyChecksums(directory);
            Console.WriteLine("Release checksum self-verification passed.");
            return 0;
        }

        private static string ReadSourceVersion(string root)
        {
            string path = Path.Combine(root, "VersionInfo.cs");
            RequireFile(path);
            string source = File.ReadAllText(path);
            Match match = Regex.Match(source, @"ProductVersion\s*=\s*""([^""]+)""");
            if (!match.Success)
                throw new InvalidOperationException("Could not read ProductVersion from VersionInfo.cs.");
            return match.Groups[1].Value;
        }

        private static void RequirePerMonitorV2(string config)
        {
            string text = File.ReadAllText(config);
            if (text.IndexOf("PerMonitorV2", StringComparison.OrdinalIgnoreCase) < 0)
                throw new InvalidOperationException("PerMonitorV2 is missing from release config: " + Path.GetFileName(config));
        }

        private static string FindUniqueFile(string root, string name)
        {
            if (!Directory.Exists(root))
                throw new DirectoryNotFoundException("Directory not found: " + root);

            string[] matches = Directory.GetFiles(root, name, SearchOption.AllDirectories);
            if (matches.Length == 0)
                throw new FileNotFoundException("Required signed artifact is missing: " + name);
            if (matches.Length != 1)
                throw new InvalidOperationException("Expected exactly one signed artifact named " + name + ".");

            return matches[0];
        }

        private static ushort ReadPeMachine(string path)
        {
            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length < 0x40)
                throw new InvalidOperationException("Invalid PE file: " + Path.GetFileName(path));

            int peOffset = BitConverter.ToInt32(bytes, 0x3c);
            if (peOffset < 0 || peOffset + 6 >= bytes.Length)
                throw new InvalidOperationException("Invalid PE header: " + Path.GetFileName(path));

            return BitConverter.ToUInt16(bytes, peOffset + 4);
        }

        private static void WriteChecksums(string directory)
        {
            List<string> files = new List<string>();
            foreach (string file in Directory.GetFiles(directory, "DomainMembershipCheckRepair-*", SearchOption.TopDirectoryOnly))
                files.Add(file);

            files.Sort(StringComparer.OrdinalIgnoreCase);

            using (StreamWriter writer = new StreamWriter(
                Path.Combine(directory, "SHA256SUMS.txt"),
                false,
                new ASCIIEncoding()))
            {
                foreach (string file in files)
                    writer.WriteLine(ComputeSha256(file) + "  " + Path.GetFileName(file));
            }
        }

        private static void VerifyChecksums(string directory)
        {
            string checksumPath = Path.Combine(directory, "SHA256SUMS.txt");
            RequireFile(checksumPath);

            foreach (string raw in File.ReadAllLines(checksumPath))
            {
                if (String.IsNullOrWhiteSpace(raw))
                    continue;
                if (raw.Length < 67 || raw[64] != ' ' || raw[65] != ' ')
                    throw new InvalidOperationException("Invalid SHA256SUMS line.");

                string expected = raw.Substring(0, 64).ToLowerInvariant();
                string name = raw.Substring(66);
                string file = Path.Combine(directory, name);
                RequireFile(file);

                string actual = ComputeSha256(file);
                if (!String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Checksum verification failed for " + name + ".");
            }
        }

        private static string ComputeSha256(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
            {
                byte[] hash = sha.ComputeHash(stream);
                StringBuilder output = new StringBuilder(hash.Length * 2);
                foreach (byte value in hash)
                    output.Append(value.ToString("x2"));
                return output.ToString();
            }
        }

        private static void WriteReleaseNotes(string directory, string tag)
        {
            StringBuilder text = new StringBuilder();
            text.AppendLine("## Code signing policy");
            text.AppendLine();
            text.AppendLine("Free code signing provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).");
            text.AppendLine();
            text.AppendLine("These release executables are Authenticode-signed using SignPath.io with a certificate provided by SignPath Foundation. The workflow refuses to publish unsigned release binaries.");
            text.AppendLine();
            text.AppendLine("See the repository [Code signing policy](https://github.com/sgennadi/DomainMembershipCheckRepair/blob/main/SIGNING.md) for build, approval, privacy, and verification details.");
            text.AppendLine();
            text.AppendLine("## Supply-chain verification");
            text.AppendLine();
            text.AppendLine("SHA-256 checksums are attached to this release. GitHub build-provenance attestations are generated for the final release files.");
            text.AppendLine();
            text.AppendLine("Keep the matching .exe.config file next to the executable. It contains the required WinForms PerMonitorV2/high-DPI configuration.");
            text.AppendLine();
            text.AppendLine("## Source");
            text.AppendLine();
            text.AppendLine("Tag: " + tag);
            text.AppendLine();
            text.AppendLine("Full changelog: https://github.com/sgennadi/DomainMembershipCheckRepair/commits/" + tag);

            File.WriteAllText(
                Path.Combine(directory, "RELEASE_NOTES.md"),
                text.ToString(),
                new UTF8Encoding(false));
        }

        private static void RecreateDirectory(string path)
        {
            if (Directory.Exists(path))
                Directory.Delete(path, true);
            Directory.CreateDirectory(path);
        }

        private static void RequireFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException("Required file is missing.", path);
        }

        private static string FindSignTool()
        {
            string[] roots =
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Kits", "10", "bin"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Kits", "10", "bin")
            };

            foreach (string root in roots)
            {
                if (!Directory.Exists(root))
                    continue;

                string[] candidates = Directory.GetFiles(root, "signtool.exe", SearchOption.AllDirectories);
                Array.Sort(candidates, StringComparer.OrdinalIgnoreCase);
                if (candidates.Length > 0)
                    return candidates[candidates.Length - 1];
            }

            throw new FileNotFoundException("signtool.exe was not found.");
        }
    }
}
