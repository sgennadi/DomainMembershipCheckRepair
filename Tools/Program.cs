using System;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class Program
    {
        private static int Main(string[] args)
        {
            try
            {
                if (args == null || args.Length == 0)
                {
                    PrintHelp();
                    return 2;
                }

                string command = (args[0] ?? String.Empty).Trim().ToLowerInvariant();
                CommandLine options = CommandLine.Parse(args, 1);

                switch (command)
                {
                    case "generate-icon":
                        return IconTool.Run(options);
                    case "validate-repository":
                        return RepositoryPolicyTool.Run(options);
                    case "sanitize-lab":
                        return LabArtifactTool.Sanitize(options);
                    case "test-sanitizer":
                        return LabArtifactTool.Test();
                    case "ad-integration":
                        return LabRunnerTool.RunAdIntegration(options);
                    case "ad-destructive":
                        return LabRunnerTool.RunAdDestructive(options);
                    case "epm-integration":
                        return LabRunnerTool.RunEpmIntegration(options);
                    case "internal-cert":
                        return InternalSigningTool.CreateCertificate(options);
                    case "internal-sign":
                        return InternalSigningTool.Sign(options);
                    case "hash-dist":
                        return HashTool.Run(options);
                    case "help":
                    case "--help":
                    case "-h":
                        PrintHelp();
                        return 0;
                    default:
                        Console.Error.WriteLine("Unknown tools command: " + command);
                        PrintHelp();
                        return 2;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("ERROR: " + ex.Message);
                return 1;
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("DomainMembershipCheckRepair native repository tools");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  generate-icon       Generate the application shield .ico");
            Console.WriteLine("  validate-repository Enforce repository/workflow policy");
            Console.WriteLine("  sanitize-lab        Sanitize a lab artifact directory");
            Console.WriteLine("  test-sanitizer      Run synthetic lab redaction regression");
            Console.WriteLine("  ad-integration      Run read-only live AD integration checks");
            Console.WriteLine("  ad-destructive      Run gated disposable AD lab scenario");
            Console.WriteLine("  epm-integration     Run CyberArk EPM live validation");
            Console.WriteLine("  internal-cert       Create an internal code-signing certificate");
            Console.WriteLine("  internal-sign       Sign local binaries with signtool");
            Console.WriteLine("  hash-dist           Generate SHA256SUMS.txt for local dist");
        }
    }
}
