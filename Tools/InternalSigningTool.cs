using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class InternalSigningTool
    {
        internal static int CreateCertificate(CommandLine options)
        {
            if (!IsAdministrator())
                throw new InvalidOperationException("internal-cert must run from an elevated administrator token.");

            string subject = options.Get(
                "subject",
                "CN=DomainMembershipCheckRepair Internal Code Signing");
            string friendlyName = options.Get(
                "friendly-name",
                "DomainMembershipCheckRepair Internal Code Signing");
            int validYears = options.GetInt("valid-years", 2);
            if (validYears < 1 || validYears > 10)
                throw new ArgumentOutOfRangeException("valid-years", "valid-years must be between 1 and 10.");

            string outputDirectory = Path.GetFullPath(options.Get("output", "internal-signing"));
            Directory.CreateDirectory(outputDirectory);

            string temp = Path.Combine(
                Path.GetTempPath(),
                "dmcr-cert-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(temp);

            string inf = Path.Combine(temp, "request.inf");
            string cer = Path.Combine(temp, "certificate.cer");

            try
            {
                StringBuilder content = new StringBuilder();
                content.AppendLine("[Version]");
                content.AppendLine("Signature="$Windows NT$"");
                content.AppendLine();
                content.AppendLine("[NewRequest]");
                content.AppendLine("Subject = "" + EscapeInf(subject) + """);
                content.AppendLine("FriendlyName = "" + EscapeInf(friendlyName) + """);
                content.AppendLine("MachineKeySet = TRUE");
                content.AppendLine("Exportable = FALSE");
                content.AppendLine("KeyAlgorithm = RSA");
                content.AppendLine("KeyLength = 3072");
                content.AppendLine("HashAlgorithm = sha256");
                content.AppendLine("KeySpec = 2");
                content.AppendLine("ProviderName = "Microsoft Enhanced RSA and AES Cryptographic Provider"");
                content.AppendLine("RequestType = Cert");
                content.AppendLine("ValidityPeriod = Years");
                content.AppendLine("ValidityPeriodUnits = " + validYears);
                content.AppendLine();
                content.AppendLine("[Extensions]");
                content.AppendLine("2.5.29.37 = "{text}"");
                content.AppendLine("_continue_ = "1.3.6.1.5.5.7.3.3"");
                File.WriteAllText(inf, content.ToString(), new UnicodeEncoding(false, true));

                ProcessResult create = ProcessHelper.Run(
                    "certreq.exe",
                    new string[] { "-new", inf, cer },
                    120000);
                if (create.TimedOut || create.ExitCode != 0)
                    throw new InvalidOperationException("certreq -new failed: " + SafeError(create));

                ProcessResult accept = ProcessHelper.Run(
                    "certreq.exe",
                    new string[] { "-accept", cer },
                    120000);
                if (accept.TimedOut || accept.ExitCode != 0)
                    throw new InvalidOperationException("certreq -accept failed: " + SafeError(accept));

                X509Certificate2 certificate = FindNewestCertificate(subject, StoreLocation.LocalMachine);
                if (certificate == null || !certificate.HasPrivateKey)
                    throw new InvalidOperationException("The new code-signing certificate was not found in LocalMachine\\My.");

                string publicPath = Path.Combine(outputDirectory, "InternalCodeSigning.cer");
                File.WriteAllBytes(publicPath, certificate.Export(X509ContentType.Cert));

                Console.WriteLine("Internal code-signing certificate created.");
                Console.WriteLine("Subject: " + certificate.Subject);
                Console.WriteLine("Thumbprint: " + certificate.Thumbprint);
                Console.WriteLine("Expires: " + certificate.NotAfter.ToString("u"));
                Console.WriteLine("Public certificate: " + publicPath);
                Console.WriteLine("The private key is non-exportable and remains in LocalMachine\\My.");
                return 0;
            }
            finally
            {
                try
                {
                    Directory.Delete(temp, true);
                }
                catch
                {
                }
            }
        }

        internal static int Sign(CommandLine options)
        {
            IList<string> files = options.GetAll("file");
            if (files.Count == 0)
                throw new ArgumentException("At least one --file is required.");

            string thumbprint = NormalizeThumbprint(options.Get("thumbprint", String.Empty));
            string pfxPath = options.Get("pfx", String.Empty);
            string timestamp = options.Get("timestamp-url", String.Empty);
            bool machineStore = options.GetBool("machine-store", true);

            if (String.IsNullOrWhiteSpace(thumbprint) == String.IsNullOrWhiteSpace(pfxPath))
                throw new ArgumentException("Specify exactly one of --thumbprint or --pfx.");

            X509Certificate2 imported = null;
            X509Store importedStore = null;

            try
            {
                if (!String.IsNullOrWhiteSpace(pfxPath))
                {
                    string fullPfx = Path.GetFullPath(pfxPath);
                    if (!File.Exists(fullPfx))
                        throw new FileNotFoundException("PFX file not found.", fullPfx);

                    string password = ReadSecret("PFX password: ");
                    try
                    {
                        imported = new X509Certificate2(
                            fullPfx,
                            password,
                            X509KeyStorageFlags.UserKeySet |
                            X509KeyStorageFlags.PersistKeySet);
                    }
                    finally
                    {
                        password = null;
                    }

                    if (!imported.HasPrivateKey)
                        throw new InvalidOperationException("The PFX does not contain a private key.");

                    importedStore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                    importedStore.Open(OpenFlags.ReadWrite);
                    importedStore.Add(imported);
                    thumbprint = NormalizeThumbprint(imported.Thumbprint);
                    machineStore = false;
                }

                string signtool = FindSignTool();

                foreach (string fileValue in files)
                {
                    string file = Path.GetFullPath(fileValue);
                    if (!File.Exists(file))
                        throw new FileNotFoundException("File to sign not found.", file);

                    List<string> signArgs = new List<string>
                    {
                        "sign",
                        "/fd", "SHA256",
                        "/sha1", thumbprint
                    };

                    if (machineStore)
                        signArgs.Add("/sm");

                    if (!String.IsNullOrWhiteSpace(timestamp))
                    {
                        signArgs.Add("/tr");
                        signArgs.Add(timestamp);
                        signArgs.Add("/td");
                        signArgs.Add("SHA256");
                    }

                    signArgs.Add(file);

                    ProcessResult sign = ProcessHelper.Run(signtool, signArgs, 180000);
                    if (sign.TimedOut || sign.ExitCode != 0)
                        throw new InvalidOperationException("signtool sign failed: " + SafeError(sign));

                    ProcessResult verify = ProcessHelper.Run(
                        signtool,
                        new string[] { "verify", "/pa", "/v", file },
                        120000);
                    if (verify.TimedOut || verify.ExitCode != 0)
                        throw new InvalidOperationException("signtool verify failed: " + SafeError(verify));

                    Console.WriteLine("Signed and verified: " + Path.GetFileName(file));
                }

                return 0;
            }
            finally
            {
                if (importedStore != null)
                {
                    try
                    {
                        if (imported != null)
                            importedStore.Remove(imported);
                    }
                    catch
                    {
                    }

                    importedStore.Close();
                }

                if (imported != null)
                    imported.Dispose();
            }
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

            string path = Environment.GetEnvironmentVariable("PATH") ?? String.Empty;
            foreach (string directory in path.Split(Path.PathSeparator))
            {
                if (String.IsNullOrWhiteSpace(directory))
                    continue;

                string candidate = Path.Combine(directory.Trim(), "signtool.exe");
                if (File.Exists(candidate))
                    return candidate;
            }

            throw new FileNotFoundException("signtool.exe was not found. Install the Windows SDK signing tools.");
        }

        private static X509Certificate2 FindNewestCertificate(string subject, StoreLocation location)
        {
            X509Certificate2 newest = null;
            using (X509Store store = new X509Store(StoreName.My, location))
            {
                store.Open(OpenFlags.ReadOnly);
                foreach (X509Certificate2 certificate in store.Certificates)
                {
                    if (!String.Equals(certificate.Subject, subject, StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (newest == null || certificate.NotBefore > newest.NotBefore)
                        newest = new X509Certificate2(certificate);
                }
            }

            return newest;
        }

        private static bool IsAdministrator()
        {
            WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static string NormalizeThumbprint(string value)
        {
            return (value ?? String.Empty)
                .Replace(" ", String.Empty)
                .Replace("\u200e", String.Empty)
                .Trim()
                .ToUpperInvariant();
        }

        private static string ReadSecret(string prompt)
        {
            if (Console.IsInputRedirected)
                return Console.ReadLine() ?? String.Empty;

            Console.Write(prompt);
            StringBuilder value = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key = Console.ReadKey(true);
                if (key.Key == ConsoleKey.Enter)
                    break;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (value.Length > 0)
                        value.Length--;
                    continue;
                }
                if (!Char.IsControl(key.KeyChar))
                    value.Append(key.KeyChar);
            }
            Console.WriteLine();
            return value.ToString();
        }

        private static string EscapeInf(string value)
        {
            return (value ?? String.Empty).Replace(""", """");
        }

        private static string SafeError(ProcessResult result)
        {
            string text = (result.StandardError ?? String.Empty).Trim();
            if (text.Length == 0)
                text = (result.StandardOutput ?? String.Empty).Trim();
            if (text.Length > 600)
                text = text.Substring(0, 600);
            return text;
        }
    }
}
