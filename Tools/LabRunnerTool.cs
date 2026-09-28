using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Management;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class LabRunnerTool
    {
        private static readonly int[] AllowedDiagnosticExitCodes = { 0, 20, 21, 22, 23 };

        internal static int RunAdIntegration(CommandLine options)
        {
            string exe = Path.GetFullPath(options.Require("exe"));
            string domain = options.Require("domain");
            string dc = options.Get("dc", String.Empty);
            string computer = options.Get("computer", Environment.MachineName);
            string profile = options.Get("profile", "smoke");
            string output = PrepareOutput(options.Get("output", "integration-artifacts"));

            ComputerSystemState state = GetComputerSystemState();
            WriteJson(Path.Combine(output, "environment.json"), new Dictionary<string, object>
            {
                { "ComputerName", Environment.MachineName },
                { "Identity", WindowsIdentity.GetCurrent().Name },
                { "PartOfDomain", state.PartOfDomain },
                { "LocalDomain", state.Domain },
                { "RequestedDomain", domain },
                { "PreferredDc", dc },
                { "Profile", profile },
                { "TimestampUtc", DateTime.UtcNow.ToString("o") }
            });

            if (!state.PartOfDomain)
                throw new InvalidOperationException("The AD integration runner is not domain joined.");

            string[] actions =
            {
                "self-test",
                "dc-matrix",
                "ldap-compatibility",
                "rpc-endpoints",
                "kerberos-deep",
                "identity-consistency",
                "replication-timeline",
                "spn-collisions",
                "smb-kerberos",
                "ad-recycle-bin",
                "ad-deleted",
                "next-action",
                "advanced"
            };

            List<Dictionary<string, object>> summary = new List<Dictionary<string, object>>();
            List<string> failures = new List<string>();

            foreach (string action in actions)
            {
                List<string> args = new List<string>
                {
                    "--cli", "--action", action,
                    "--domain", domain,
                    "--computer", computer,
                    "--json"
                };

                if (!String.IsNullOrWhiteSpace(dc))
                {
                    args.Add("--dc");
                    args.Add(dc);
                }

                ProcessResult result = RunDmcr(exe, args, null, output, action, 180000);
                if (result.TimedOut)
                    failures.Add(action + " timed out.");

                if (!Contains(AllowedDiagnosticExitCodes, result.ExitCode))
                    failures.Add(action + " returned unexpected exit code " + result.ExitCode + ".");

                Dictionary<string, object> envelope = TryParseJsonObject(result.StandardOutput);
                bool jsonValid = envelope != null;
                if (!jsonValid)
                    failures.Add(action + " did not return valid JSON.");

                if (envelope != null)
                {
                    object value;
                    if (envelope.TryGetValue("action", out value) &&
                        !String.Equals(Convert.ToString(value), action, StringComparison.OrdinalIgnoreCase))
                    {
                        failures.Add(action + " JSON envelope reported a different action.");
                    }

                    if (envelope.TryGetValue("exitCode", out value) &&
                        Convert.ToInt32(value) != result.ExitCode)
                    {
                        failures.Add(action + " process exit code differs from JSON exitCode.");
                    }
                }

                if (String.Equals(profile, "healthy", StringComparison.OrdinalIgnoreCase) &&
                    result.ExitCode == 20)
                {
                    failures.Add(action + " detected a finding in healthy profile.");
                }

                summary.Add(new Dictionary<string, object>
                {
                    { "Action", action },
                    { "ExitCode", result.ExitCode },
                    { "JsonValid", jsonValid },
                    { "StdErrPresent", !String.IsNullOrWhiteSpace(result.StandardError) }
                });

                Console.WriteLine(action + " -> exit " + result.ExitCode);
            }

            WriteJson(Path.Combine(output, "summary.json"), summary);
            File.WriteAllLines(Path.Combine(output, "summary.txt"), FormatSummary(summary), new UTF8Encoding(false));

            if (failures.Count > 0)
            {
                File.WriteAllLines(Path.Combine(output, "failures.txt"), failures, new UTF8Encoding(false));
                foreach (string failure in failures)
                    Console.Error.WriteLine("FAIL: " + failure);
                return 1;
            }

            Console.WriteLine("AD integration validation completed successfully.");
            return 0;
        }

        internal static int RunEpmIntegration(CommandLine options)
        {
            string exe = Path.GetFullPath(options.Require("exe"));
            string output = PrepareOutput(options.Get("output", "epm-artifacts"));
            bool requireStandardUser = options.GetBool("require-standard-user", true);
            bool requireDetection = options.GetBool("require-cyberark-detection", true);

            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            bool isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            WriteJson(Path.Combine(output, "environment.json"), new Dictionary<string, object>
            {
                { "ComputerName", Environment.MachineName },
                { "Identity", identity.Name },
                { "IsAdministrator", isAdmin },
                { "UserInteractive", Environment.UserInteractive },
                { "RequireStandardUser", requireStandardUser },
                { "RequireCyberArkDetection", requireDetection },
                { "TimestampUtc", DateTime.UtcNow.ToString("o") }
            });

            if (!Environment.UserInteractive)
                throw new InvalidOperationException("The EPM lab runner must run in an interactive Windows session.");

            if (requireStandardUser && isAdmin)
                throw new InvalidOperationException("The EPM lab must start from a standard-user token.");

            ProcessResult cyber = RunDmcr(
                exe,
                new string[] { "--cli", "--action", "cyberark", "--json" },
                null,
                output,
                "cyberark",
                120000);

            if (!Contains(AllowedDiagnosticExitCodes, cyber.ExitCode))
                throw new InvalidOperationException("CyberArk diagnostic returned an unexpected exit code.");

            bool detected = ReadNestedBoolean(cyber.StandardOutput, "result", "Detected");
            if (requireDetection && !detected)
                throw new InvalidOperationException("CyberArk/EPM was not detected on the EPM lab runner.");

            ProcessResult probe = RunDmcr(
                exe,
                new string[] { "--cli", "--action", "elevation-probe", "--json" },
                null,
                output,
                "elevation-probe",
                180000);

            if (probe.ExitCode != 0)
                throw new InvalidOperationException("Elevation probe failed.");

            ProcessResult dryRun = RunDmcr(
                exe,
                new string[] { "--cli", "--action", "safe-fixes", "--dry-run", "--no-restart" },
                null,
                output,
                "safe-fixes-dry-run",
                120000);

            if (dryRun.ExitCode != 0)
                throw new InvalidOperationException("Safe Fixes dry-run failed.");

            WriteJson(Path.Combine(output, "summary.json"), new Dictionary<string, object>
            {
                { "CyberArkDetected", detected },
                { "ElevationProbeExitCode", probe.ExitCode },
                { "SafeFixesDryRunExitCode", dryRun.ExitCode },
                { "Passed", true },
                { "TimestampUtc", DateTime.UtcNow.ToString("o") }
            });

            Console.WriteLine("CyberArk/EPM live validation completed successfully.");
            return 0;
        }

        internal static int RunAdDestructive(CommandLine options)
        {
            string exe = Path.GetFullPath(options.Require("exe"));
            string scenario = options.Require("scenario");
            string domain = options.Require("domain");
            string dc = options.Get("dc", String.Empty);
            string expectedComputer = options.Get("computer", String.Empty);
            string testOu = options.Get("test-ou", String.Empty);
            string output = PrepareOutput(options.Get("output", "destructive-artifacts"));

            ComputerSystemState state = GetComputerSystemState();
            if (!state.PartOfDomain)
                throw new InvalidOperationException("The destructive lab runner must be domain joined.");
            if (!String.Equals(state.Domain, domain, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Runner domain does not match the configured lab domain.");
            if (!String.IsNullOrWhiteSpace(expectedComputer) &&
                !String.Equals(Environment.MachineName, expectedComputer, StringComparison.OrdinalIgnoreCase))
                throw new InvalidOperationException("Runner computer name does not match the configured disposable lab computer.");

            WindowsPrincipal principal = new WindowsPrincipal(WindowsIdentity.GetCurrent());
            if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
                throw new InvalidOperationException("The destructive lab runner must run elevated.");

            WriteJson(Path.Combine(output, "environment.json"), new Dictionary<string, object>
            {
                { "Scenario", scenario },
                { "ComputerName", Environment.MachineName },
                { "Identity", WindowsIdentity.GetCurrent().Name },
                { "Domain", domain },
                { "PreferredDc", dc },
                { "TestOuDn", testOu },
                { "TimestampUtc", DateTime.UtcNow.ToString("o") }
            });

            List<string> baseArgs = new List<string> { "--cli", "--domain", domain, "--no-restart", "--no-log" };
            if (!String.IsNullOrWhiteSpace(dc))
            {
                baseArgs.Add("--dc");
                baseArgs.Add(dc);
            }

            List<Dictionary<string, object>> summary = new List<Dictionary<string, object>>();

            ProcessResult selfTest = RunDmcr(
                exe,
                Append(baseArgs, "--action", "self-test", "--json"),
                null,
                output,
                "preflight-self-test",
                180000);
            RequireAllowedDiagnostic(selfTest, "self-test");
            AddSummary(summary, "self-test", "PASS", "Preflight completed.");

            ProcessResult recycle = RunDmcr(
                exe,
                Append(baseArgs, "--action", "ad-recycle-bin", "--json"),
                null,
                output,
                "preflight-recycle-bin",
                180000);
            RequireAllowedDiagnostic(recycle, "ad-recycle-bin");
            AddSummary(summary, "ad-recycle-bin", "PASS", "Recycle Bin readiness query completed.");

            if (String.Equals(scenario, "preflight", StringComparison.OrdinalIgnoreCase))
            {
                AddSummary(summary, "scenario", "PASS", "Preflight-only run completed.");
            }
            else if (String.Equals(scenario, "safe-fixes", StringComparison.OrdinalIgnoreCase))
            {
                ProcessResult result = RunDmcr(
                    exe,
                    Append(baseArgs, "--action", "safe-fixes"),
                    new string[] { "y" },
                    output,
                    "safe-fixes",
                    180000);
                RequireExitZero(result, "safe-fixes");
                AddSummary(summary, "safe-fixes", "PASS", "Safe Fixes completed.");
            }
            else if (String.Equals(scenario, "repair-if-broken", StringComparison.OrdinalIgnoreCase))
            {
                ProcessResult check = RunDmcr(
                    exe,
                    Append(baseArgs, "--action", "check"),
                    null,
                    output,
                    "trust-check",
                    120000);

                if (check.ExitCode == 0)
                {
                    AddSummary(summary, "repair-if-broken", "SKIP", "Secure channel is already healthy.");
                }
                else if (check.ExitCode == 2)
                {
                    ProcessResult repair = RunDmcr(
                        exe,
                        Append(baseArgs, "--action", "repair"),
                        null,
                        output,
                        "trust-repair",
                        180000);
                    RequireExitZero(repair, "trust-repair");

                    ProcessResult verify = RunDmcr(
                        exe,
                        Append(baseArgs, "--action", "check"),
                        null,
                        output,
                        "trust-verify",
                        120000);
                    RequireExitZero(verify, "trust-verify");
                    AddSummary(summary, "repair-if-broken", "PASS", "Broken secure channel was repaired and verified.");
                }
                else
                {
                    throw new InvalidOperationException("Trust check returned an unexpected exit code.");
                }
            }
            else if (String.Equals(scenario, "mii-disable-rollback", StringComparison.OrdinalIgnoreCase))
            {
                ProcessResult dry = RunDmcr(
                    exe,
                    Append(baseArgs, "--action", "mii-disable", "--dry-run"),
                    null,
                    output,
                    "mii-preflight",
                    120000);

                if ((dry.StandardOutput ?? String.Empty).IndexOf("not enabled", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    AddSummary(summary, "mii-disable-rollback", "SKIP", "Machine Identity Isolation is not enabled.");
                }
                else
                {
                    ProcessResult disable = RunDmcr(
                        exe,
                        Append(baseArgs, "--action", "mii-disable"),
                        new string[] { "y" },
                        output,
                        "mii-disable",
                        180000);
                    RequireExitZero(disable, "mii-disable");

                    ProcessResult rollback = RunDmcr(
                        exe,
                        Append(baseArgs, "--action", "rollback-local"),
                        new string[] { "y" },
                        output,
                        "mii-rollback",
                        180000);
                    RequireExitZero(rollback, "mii-rollback");
                    AddSummary(summary, "mii-disable-rollback", "PASS", "MII local change and rollback completed.");
                }
            }
            else if (String.Equals(scenario, "recycle-bin-restore", StringComparison.OrdinalIgnoreCase))
            {
                RunRecycleRestoreScenario(exe, baseArgs, domain, dc, testOu, output, summary);
            }
            else
            {
                throw new ArgumentException("Unsupported destructive lab scenario.");
            }

            WriteJson(Path.Combine(output, "summary.json"), summary);
            File.WriteAllLines(Path.Combine(output, "summary.txt"), FormatSummary(summary), new UTF8Encoding(false));
            Console.WriteLine("Disposable AD lab scenario completed successfully.");
            return 0;
        }

        private static void RunRecycleRestoreScenario(
            string exe,
            List<string> baseArgs,
            string domain,
            string dc,
            string testOu,
            string output,
            List<Dictionary<string, object>> summary)
        {
            if (String.IsNullOrWhiteSpace(testOu))
                throw new InvalidOperationException("A disposable test OU DN is required.");

            string user = Environment.GetEnvironmentVariable("AD_LAB_USER");
            string password = Environment.GetEnvironmentVariable("AD_LAB_PASSWORD");
            if (String.IsNullOrWhiteSpace(user) || String.IsNullOrEmpty(password))
                throw new InvalidOperationException("AD lab credentials are required for recycle-bin-restore.");

            string runId = Environment.GetEnvironmentVariable("GITHUB_RUN_ID");
            if (String.IsNullOrWhiteSpace(runId))
                runId = DateTime.UtcNow.ToString("HHmmss");

            if (runId.Length > 8)
                runId = runId.Substring(runId.Length - 8);

            string testName = ("DCRLAB" + runId).ToUpperInvariant();
            if (testName.Length > 15)
                testName = testName.Substring(0, 15);

            string sam = testName + "$";
            if (FindComputer(domain, dc, sam, user, password) != null)
                throw new InvalidOperationException("Generated disposable test account already exists.");

            Guid originalGuid = Guid.Empty;
            DirectoryEntry created = null;

            try
            {
                using (DirectoryEntry parent = OpenEntry(dc, testOu, user, password))
                {
                    created = parent.Children.Add("CN=" + EscapeRdn(testName), "computer");
                    created.Properties["sAMAccountName"].Value = sam;
                    created.CommitChanges();
                    originalGuid = created.Guid;
                    created.DeleteTree();
                    created.Dispose();
                    created = null;
                }

                bool foundDeleted = false;
                for (int attempt = 1; attempt <= 12; attempt++)
                {
                    Thread.Sleep(5000);
                    ProcessResult deleted = RunDmcr(
                        exe,
                        Append(baseArgs, "--action", "ad-deleted", "--computer", testName, "--json"),
                        null,
                        output,
                        "ad-deleted-" + attempt,
                        120000);
                    if (deleted.ExitCode == 20)
                    {
                        foundDeleted = true;
                        break;
                    }
                }

                if (!foundDeleted)
                    throw new InvalidOperationException("The disposable deleted object was not detected within 60 seconds.");

                ProcessResult restore = RunDmcr(
                    exe,
                    Append(
                        baseArgs,
                        "--action", "ad-restore",
                        "--computer", testName,
                        "--user", user,
                        "--password-stdin"),
                    new string[] { password, "y" },
                    output,
                    "ad-restore",
                    180000);
                RequireExitZero(restore, "ad-restore");

                DirectoryEntry restored = FindComputer(domain, dc, sam, user, password);
                if (restored == null)
                    throw new InvalidOperationException("Restored disposable object was not found.");

                using (restored)
                {
                    if (restored.Guid != originalGuid)
                        throw new InvalidOperationException("Restored computer ObjectGUID differs from the original object.");

                    AddSummary(summary, "recycle-bin-restore", "PASS", "Disposable object was deleted, restored, and verified by ObjectGUID.");
                    restored.DeleteTree();
                }
            }
            finally
            {
                if (created != null)
                {
                    try
                    {
                        created.Dispose();
                    }
                    catch
                    {
                    }
                }

                try
                {
                    DirectoryEntry leftover = FindComputer(domain, dc, sam, user, password);
                    if (leftover != null)
                    {
                        using (leftover)
                            leftover.DeleteTree();
                    }
                }
                catch
                {
                }
            }
        }

        private static DirectoryEntry FindComputer(
            string domain,
            string dc,
            string sam,
            string user,
            string password)
        {
            string baseDn = DomainToDn(domain);
            using (DirectoryEntry root = OpenEntry(dc, baseDn, user, password))
            using (DirectorySearcher searcher = new DirectorySearcher(root))
            {
                searcher.Filter = "(&(objectClass=computer)(sAMAccountName=" + EscapeLdap(sam) + "))";
                searcher.SearchScope = SearchScope.Subtree;
                searcher.PropertiesToLoad.Add("distinguishedName");
                searcher.SizeLimit = 2;

                SearchResultCollection results = searcher.FindAll();
                try
                {
                    if (results.Count == 0)
                        return null;
                    if (results.Count != 1)
                        throw new InvalidOperationException("Expected exactly one disposable computer object.");

                    SearchResult result = results[0];
                    return OpenEntry(dc, Convert.ToString(result.Properties["distinguishedName"][0]), user, password);
                }
                finally
                {
                    results.Dispose();
                }
            }
        }

        private static DirectoryEntry OpenEntry(
            string dc,
            string distinguishedName,
            string user,
            string password)
        {
            string server = (dc ?? String.Empty).Trim().TrimStart('\\');
            string path = "LDAP://" +
                (String.IsNullOrWhiteSpace(server) ? String.Empty : server + "/") +
                distinguishedName;

            return new DirectoryEntry(
                path,
                String.IsNullOrWhiteSpace(user) ? null : user,
                String.IsNullOrEmpty(password) ? null : password,
                AuthenticationTypes.Secure | AuthenticationTypes.Sealing | AuthenticationTypes.Signing);
        }

        private static string DomainToDn(string domain)
        {
            string[] parts = (domain ?? String.Empty).Split(new char[] { '.' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
                throw new ArgumentException("Invalid DNS domain.");

            StringBuilder output = new StringBuilder();
            foreach (string part in parts)
            {
                if (output.Length > 0)
                    output.Append(',');
                output.Append("DC=").Append(EscapeRdn(part));
            }
            return output.ToString();
        }

        private static string EscapeRdn(string value)
        {
            if (value == null)
                return String.Empty;

            return value
                .Replace("\\", "\\5c")
                .Replace(",", "\\2c")
                .Replace("+", "\\2b")
                .Replace(""", "\\22")
                .Replace("<", "\\3c")
                .Replace(">", "\\3e")
                .Replace(";", "\\3b")
                .Replace("=", "\\3d");
        }

        private static string EscapeLdap(string value)
        {
            if (value == null)
                return String.Empty;

            return value
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }

        private static ProcessResult RunDmcr(
            string exe,
            IEnumerable<string> args,
            IEnumerable<string> input,
            string outputDirectory,
            string artifactName,
            int timeout)
        {
            ProcessResult result = ProcessHelper.Run(exe, args, input, timeout);
            File.WriteAllText(
                Path.Combine(outputDirectory, artifactName + ".stdout.txt"),
                result.StandardOutput ?? String.Empty,
                new UTF8Encoding(false));
            File.WriteAllText(
                Path.Combine(outputDirectory, artifactName + ".stderr.txt"),
                result.StandardError ?? String.Empty,
                new UTF8Encoding(false));

            if (result.TimedOut)
                throw new TimeoutException("DomainMembershipCheckRepair timed out for lab step '" + artifactName + "'.");

            return result;
        }

        private static string PrepareOutput(string path)
        {
            string full = Path.GetFullPath(path);
            if (Directory.Exists(full))
                Directory.Delete(full, true);
            Directory.CreateDirectory(full);
            return full;
        }

        private static ComputerSystemState GetComputerSystemState()
        {
            using (ManagementObjectSearcher searcher =
                new ManagementObjectSearcher("SELECT PartOfDomain, Domain FROM Win32_ComputerSystem"))
            {
                foreach (ManagementObject item in searcher.Get())
                {
                    return new ComputerSystemState
                    {
                        PartOfDomain = Convert.ToBoolean(item["PartOfDomain"]),
                        Domain = Convert.ToString(item["Domain"]) ?? String.Empty
                    };
                }
            }

            throw new InvalidOperationException("Unable to read Win32_ComputerSystem.");
        }

        private static Dictionary<string, object> TryParseJsonObject(string json)
        {
            try
            {
                object parsed = new JavaScriptSerializer().DeserializeObject(json ?? String.Empty);
                return parsed as Dictionary<string, object>;
            }
            catch
            {
                return null;
            }
        }

        private static bool ReadNestedBoolean(string json, string objectName, string propertyName)
        {
            Dictionary<string, object> root = TryParseJsonObject(json);
            if (root == null)
                return false;

            object nestedValue;
            if (!root.TryGetValue(objectName, out nestedValue))
                return false;

            Dictionary<string, object> nested = nestedValue as Dictionary<string, object>;
            if (nested == null)
                return false;

            object value;
            if (!nested.TryGetValue(propertyName, out value))
                return false;

            try
            {
                return Convert.ToBoolean(value);
            }
            catch
            {
                return false;
            }
        }

        private static void WriteJson(string path, object value)
        {
            string json = new JavaScriptSerializer().Serialize(value);
            File.WriteAllText(path, json, new UTF8Encoding(false));
        }

        private static IList<string> FormatSummary(IEnumerable<Dictionary<string, object>> rows)
        {
            List<string> lines = new List<string>();
            foreach (Dictionary<string, object> row in rows)
            {
                List<string> parts = new List<string>();
                foreach (KeyValuePair<string, object> pair in row)
                    parts.Add(pair.Key + "=" + Convert.ToString(pair.Value));
                lines.Add(String.Join(" | ", parts.ToArray()));
            }
            return lines;
        }

        private static void AddSummary(
            List<Dictionary<string, object>> summary,
            string step,
            string status,
            string details)
        {
            summary.Add(new Dictionary<string, object>
            {
                { "Step", step },
                { "Status", status },
                { "Details", details }
            });
        }

        private static List<string> Append(List<string> source, params string[] values)
        {
            List<string> result = new List<string>(source);
            result.AddRange(values);
            return result;
        }

        private static bool Contains(int[] values, int target)
        {
            foreach (int value in values)
            {
                if (value == target)
                    return true;
            }
            return false;
        }

        private static void RequireAllowedDiagnostic(ProcessResult result, string step)
        {
            if (!Contains(AllowedDiagnosticExitCodes, result.ExitCode))
                throw new InvalidOperationException(step + " returned an unexpected diagnostic exit code.");
        }

        private static void RequireExitZero(ProcessResult result, string step)
        {
            if (result.ExitCode != 0)
                throw new InvalidOperationException(step + " failed with exit code " + result.ExitCode + ".");
        }

        private sealed class ComputerSystemState
        {
            internal bool PartOfDomain;
            internal string Domain;
        }
    }
}
