using System;
using System.Diagnostics;
using System.IO;
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

            string full = Path.GetFullPath(blobPath);
            return RunDjoin("/requestODJ /loadfile " + Quote(full) + " /windowspath " + Quote(Environment.GetFolderPath(Environment.SpecialFolder.Windows)) + " /localos", out output);
        }

        internal static int ProvisionBlob(string domain, string machine, string outputPath, bool reuse, out string output)
        {
            output = String.Empty;
            if (String.IsNullOrWhiteSpace(domain) || String.IsNullOrWhiteSpace(machine) || String.IsNullOrWhiteSpace(outputPath))
            {
                output = "Domain, machine name, and output path are required.";
                return 3;
            }

            string args = "/provision /domain " + Quote(domain) +
                          " /machine " + Quote(machine) +
                          " /savefile " + Quote(Path.GetFullPath(outputPath));
            if (reuse)
                args += " /reuse";

            return RunDjoin(args, out output);
        }

        private static int RunDjoin(string args, out string output)
        {
            string djoin = Path.Combine(Environment.SystemDirectory, "djoin.exe");
            CommandResult result = ProcessRunner.Run(djoin, args, 120000);

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

        private static string Quote(string value)
        {
            return "\"" + (value ?? String.Empty).Replace("\"", "\\\"") + "\"";
        }
    }
}
