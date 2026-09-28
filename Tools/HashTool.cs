using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class HashTool
    {
        internal static int Run(CommandLine options)
        {
            string root = Path.GetFullPath(options.Get("directory", "dist"));
            if (!Directory.Exists(root))
                throw new DirectoryNotFoundException("Distribution directory not found.");

            List<string> files = new List<string>();
            foreach (string file in Directory.GetFiles(root, "*", SearchOption.AllDirectories))
            {
                string name = Path.GetFileName(file);
                if (!name.StartsWith("DomainMembershipCheckRepair-", StringComparison.OrdinalIgnoreCase))
                    continue;

                if (name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ||
                    name.EndsWith(".exe.config", StringComparison.OrdinalIgnoreCase))
                    files.Add(file);
            }

            files.Sort(StringComparer.OrdinalIgnoreCase);
            string checksumPath = Path.Combine(root, "SHA256SUMS.txt");

            using (StreamWriter writer = new StreamWriter(checksumPath, false, new ASCIIEncoding()))
            {
                foreach (string file in files)
                {
                    string relative = file.Substring(root.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    writer.WriteLine(ComputeSha256(file) + "  " + relative.Replace('\\', '/'));
                }
            }

            Console.WriteLine("Wrote " + files.Count + " SHA-256 checksum entries.");
            return 0;
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
    }
}
