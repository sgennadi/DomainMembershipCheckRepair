using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class RepositoryPolicyTool
    {
        private static readonly Regex UsesRegex = new Regex(
            @"^\s*uses:\s*([^\s#]+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex FullShaRegex = new Regex(
            @"^[0-9a-fA-F]{40}$",
            RegexOptions.Compiled);

        internal static int Run(CommandLine options)
        {
            string root = Path.GetFullPath(options.Get("root", Environment.CurrentDirectory));
            if (!Directory.Exists(root))
                throw new DirectoryNotFoundException("Repository root not found.");

            List<string> failures = new List<string>();

            ValidateNoPowerShellFiles(root, failures);
            ValidateWorkflows(root, failures);

            if (failures.Count > 0)
            {
                Console.Error.WriteLine("Repository policy validation failed:");
                foreach (string failure in failures)
                    Console.Error.WriteLine(" - " + failure);
                return 1;
            }

            Console.WriteLine("Repository policy validation passed.");
            Console.WriteLine("No .ps1 files are present.");
            Console.WriteLine("Remote actions are pinned to immutable commit SHAs.");
            Console.WriteLine("Workflow token permissions and checkout credential policy are explicit.");
            return 0;
        }

        private static void ValidateNoPowerShellFiles(string root, List<string> failures)
        {
            foreach (string file in Directory.GetFiles(root, "*.ps1", SearchOption.AllDirectories))
            {
                if (IsIgnoredPath(root, file))
                    continue;

                failures.Add("PowerShell script files are not allowed: " + Relative(root, file));
            }
        }

        private static void ValidateWorkflows(string root, List<string> failures)
        {
            string workflowDirectory = Path.Combine(root, ".github", "workflows");
            if (!Directory.Exists(workflowDirectory))
            {
                failures.Add(".github/workflows is missing.");
                return;
            }

            foreach (string workflow in Directory.GetFiles(workflowDirectory, "*.yml", SearchOption.TopDirectoryOnly))
                ValidateWorkflow(root, workflow, failures);

            foreach (string workflow in Directory.GetFiles(workflowDirectory, "*.yaml", SearchOption.TopDirectoryOnly))
                ValidateWorkflow(root, workflow, failures);
        }

        private static void ValidateWorkflow(string root, string path, List<string> failures)
        {
            string relative = Relative(root, path);
            string text = File.ReadAllText(path);
            string[] lines = File.ReadAllLines(path);

            if (Regex.IsMatch(text, @"(?m)^pull_request_target\s*:", RegexOptions.IgnoreCase))
                failures.Add(relative + " uses pull_request_target, which is not permitted.");

            if (!Regex.IsMatch(text, @"(?m)^permissions\s*:", RegexOptions.IgnoreCase))
                failures.Add(relative + " must declare explicit top-level permissions.");

            if (Regex.IsMatch(text, @"(?im)^\s*shell\s*:\s*(?:pwsh|powershell)\s*$") ||
                text.IndexOf("powershell.exe", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                failures.Add(relative + " uses PowerShell. Repository workflow orchestration must use native tools/cmd instead.");
            }

            bool selfHosted = text.IndexOf("self-hosted", StringComparison.OrdinalIgnoreCase) >= 0;
            if (selfHosted &&
                text.IndexOf("github.ref == 'refs/heads/main'", StringComparison.Ordinal) < 0)
            {
                failures.Add(relative + " uses a self-hosted runner but is not restricted to refs/heads/main.");
            }

            if (String.Equals(
                Path.GetFileName(path),
                "release.yml",
                StringComparison.OrdinalIgnoreCase))
            {
                if (Regex.IsMatch(
                    text,
                    @"(?m)^\s*workflow_dispatch\s*:",
                    RegexOptions.IgnoreCase))
                {
                    failures.Add(relative + " must remain tag-triggered only; workflow_dispatch is not permitted.");
                }

                if (text.IndexOf(
                    "release-validate-origin",
                    StringComparison.OrdinalIgnoreCase) < 0)
                {
                    failures.Add(relative + " must validate protected-main release origin before signing.");
                }

                if (!Regex.IsMatch(
                    text,
                    @"(?im)^\s*checks\s*:\s*read\s*$"))
                {
                    failures.Add(relative + " must grant checks: read for release-origin validation.");
                }

                if (!Regex.IsMatch(
                    text,
                    @"(?im)^\s*actions\s*:\s*read\s*$"))
                {
                    failures.Add(relative + " must grant actions: read for main-push workflow correlation.");
                }

                if (text.IndexOf(
                    "--required-check build",
                    StringComparison.Ordinal) < 0 ||
                    text.IndexOf(
                    "--required-check \"Analyze C#\"",
                    StringComparison.Ordinal) < 0)
                {
                    failures.Add(relative + " must require the build and Analyze C# checks on the release commit.");
                }
            }

            for (int i = 0; i < lines.Length; i++)
            {
                Match match = UsesRegex.Match(lines[i]);
                if (!match.Success)
                    continue;

                string action = match.Groups[1].Value.Trim();
                if (action.StartsWith("./", StringComparison.Ordinal) ||
                    action.StartsWith(".\\", StringComparison.Ordinal))
                    continue;

                int at = action.LastIndexOf('@');
                if (at <= 0 || at == action.Length - 1)
                {
                    failures.Add(relative + " has an invalid remote action reference: " + action);
                    continue;
                }

                string reference = action.Substring(at + 1);
                if (!FullShaRegex.IsMatch(reference))
                    failures.Add(relative + " must pin remote action to a full 40-character SHA: " + action);

                if (action.StartsWith("actions/checkout@", StringComparison.OrdinalIgnoreCase) &&
                    !CheckoutDisablesCredentialPersistence(lines, i))
                {
                    failures.Add(relative + " checkout must set persist-credentials: false.");
                }
            }
        }

        private static bool CheckoutDisablesCredentialPersistence(string[] lines, int usesLine)
        {
            for (int i = usesLine + 1; i < lines.Length && i <= usesLine + 10; i++)
            {
                string line = lines[i];

                if (Regex.IsMatch(line, @"^\s*-\s+name\s*:", RegexOptions.IgnoreCase))
                    break;

                if (Regex.IsMatch(
                    line,
                    @"^\s*persist-credentials\s*:\s*false\s*(?:#.*)?$",
                    RegexOptions.IgnoreCase))
                    return true;
            }

            return false;
        }

        private static bool IsIgnoredPath(string root, string path)
        {
            string relative = Relative(root, path).Replace('/', '\\');
            return relative.StartsWith(".git\\", StringComparison.OrdinalIgnoreCase) ||
                   relative.IndexOf("\\bin\\", StringComparison.OrdinalIgnoreCase) >= 0 ||
                   relative.IndexOf("\\obj\\", StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static string Relative(string root, string path)
        {
            string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            string fullPath = Path.GetFullPath(path);
            if (fullPath.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
                return fullPath.Substring(fullRoot.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

            return fullPath;
        }
    }
}
