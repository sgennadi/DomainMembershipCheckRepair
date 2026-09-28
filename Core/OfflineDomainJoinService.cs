using System;
using System.Collections.Generic;
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
            string[] arguments = BuildApplyArgumentList(
                full,
                Environment.GetFolderPath(
                    Environment.SpecialFolder.Windows));
            return RunDjoin(arguments, out output);
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

            string[] args = BuildProvisionArgumentList(
                domain.Trim(),
                machine.Trim(),
                fullOutputPath,
                reuse);

            return RunDjoin(args, out output);
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
