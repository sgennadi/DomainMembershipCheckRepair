using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class CliOptions
    {
        internal string Action = String.Empty;
        internal string Domain = String.Empty;
        internal string User = String.Empty;
        internal string NewName = String.Empty;
        internal string ComputerName = String.Empty;
        internal string PreferredDc = String.Empty;
        internal string OutputPath = String.Empty;
        internal string BlobPath = String.Empty;
        internal bool ReuseComputerAccount;
        internal bool FileLogging;
        internal bool RestartAlways;
        internal bool RestartNever;
        internal bool Json;
        internal bool DryRun;
        internal bool IncludeApplicationLog;
        internal bool ElevationAttempted;
        internal bool Help;
    }

    internal sealed class CliLogger
    {
        internal const string LogFile = @"C:\Windows\Logs\DomainMembershipRepair.log";
        private readonly bool fileLogging;
        private readonly bool quietConsole;

        internal CliLogger(bool enabled, bool quiet)
        {
            fileLogging = enabled;
            quietConsole = quiet;
        }

        internal void Log(string level, string message)
        {
            string line = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] [" + level + "] " + message;
            if (!quietConsole)
                Console.WriteLine(line);

            if (!fileLogging)
                return;

            try
            {
                string directory = Path.GetDirectoryName(LogFile);
                if (!Directory.Exists(directory))
                    Directory.CreateDirectory(directory);
                File.AppendAllText(LogFile, line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
            }
        }
    }

    internal static class CliRunner
    {
        private const uint ATTACH_PARENT_PROCESS = 0xFFFFFFFF;
        private static CliLogger logger;
        private static CliOptions options;
        private static string[] originalArgs = new string[0];

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AttachConsole(uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AllocConsole();

        internal static int Run(string[] args, bool enableFileLogging)
        {
            EnsureConsole();
            originalArgs = args ?? new string[0];

            string parseError;
            options = ParseOptions(args, enableFileLogging, out parseError);
            logger = new CliLogger(options.FileLogging, options.Json);

            if (!String.IsNullOrWhiteSpace(parseError))
            {
                Console.Error.WriteLine("ERROR: " + parseError);
                Console.Error.WriteLine();
                PrintHelp();
                return 3;
            }

            if (options.Help)
            {
                PrintHelp();
                return 0;
            }

            if (!options.Json)
                PrintHeader();

            if (String.IsNullOrWhiteSpace(options.Action))
                return InteractiveMenu();

            return ExecuteAction(options.Action);
        }

        private static void EnsureConsole()
        {
            if (!AttachConsole(ATTACH_PARENT_PROCESS))
                AllocConsole();

            try
            {
                StreamWriter output = new StreamWriter(Console.OpenStandardOutput(), new UTF8Encoding(false));
                output.AutoFlush = true;
                Console.SetOut(output);

                StreamWriter error = new StreamWriter(Console.OpenStandardError(), new UTF8Encoding(false));
                error.AutoFlush = true;
                Console.SetError(error);

                StreamReader input = new StreamReader(Console.OpenStandardInput(), Encoding.UTF8, false, 1024, true);
                Console.SetIn(input);
            }
            catch
            {
            }

            try
            {
                Console.OutputEncoding = new UTF8Encoding(false);
                Console.Title = "Domain Membership Check & Repair - CLI";
            }
            catch
            {
            }
        }

        private static CliOptions ParseOptions(string[] args, bool enableFileLogging, out string error)
        {
            CliOptions result = new CliOptions();
            result.FileLogging = enableFileLogging;
            error = null;

            if (args == null)
                return result;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = (args[i] ?? String.Empty).Trim();
                if (arg.Length == 0)
                    continue;

                if (EqualsArg(arg, "--cli", "/cli"))
                    continue;
                if (EqualsArg(arg, "--help", "-h", "/?"))
                {
                    result.Help = true;
                    continue;
                }
                if (EqualsArg(arg, "--log", "/log"))
                {
                    result.FileLogging = true;
                    continue;
                }
                if (EqualsArg(arg, "--no-log", "/no-log"))
                {
                    result.FileLogging = false;
                    continue;
                }
                if (EqualsArg(arg, "--restart"))
                {
                    result.RestartAlways = true;
                    result.RestartNever = false;
                    continue;
                }
                if (EqualsArg(arg, "--no-restart"))
                {
                    result.RestartNever = true;
                    result.RestartAlways = false;
                    continue;
                }
                if (EqualsArg(arg, "--json"))
                {
                    result.Json = true;
                    continue;
                }
                if (EqualsArg(arg, "--dry-run"))
                {
                    result.DryRun = true;
                    continue;
                }
                if (EqualsArg(arg, "--include-app-log"))
                {
                    result.IncludeApplicationLog = true;
                    continue;
                }
                if (EqualsArg(arg, "--reuse"))
                {
                    result.ReuseComputerAccount = true;
                    continue;
                }
                if (EqualsArg(arg, "--elevation-attempted"))
                {
                    result.ElevationAttempted = true;
                    continue;
                }

                if (EqualsArg(arg, "--action"))
                {
                    if (!TryReadValue(args, ref i, out result.Action))
                    {
                        error = "--action requires a value.";
                        return result;
                    }
                    continue;
                }
                if (EqualsArg(arg, "--domain"))
                {
                    if (!TryReadValue(args, ref i, out result.Domain))
                    {
                        error = "--domain requires a value.";
                        return result;
                    }
                    continue;
                }
                if (EqualsArg(arg, "--user"))
                {
                    if (!TryReadValue(args, ref i, out result.User))
                    {
                        error = "--user requires a value.";
                        return result;
                    }
                    continue;
                }
                if (EqualsArg(arg, "--new-name"))
                {
                    if (!TryReadValue(args, ref i, out result.NewName))
                    {
                        error = "--new-name requires a value.";
                        return result;
                    }
                    continue;
                }
                if (EqualsArg(arg, "--computer"))
                {
                    if (!TryReadValue(args, ref i, out result.ComputerName))
                    {
                        error = "--computer requires a value.";
                        return result;
                    }
                    continue;
                }
                if (EqualsArg(arg, "--dc"))
                {
                    if (!TryReadValue(args, ref i, out result.PreferredDc))
                    {
                        error = "--dc requires a value.";
                        return result;
                    }
                    result.PreferredDc = DomainValidation.NormalizeDirectoryServer(result.PreferredDc);
                    continue;
                }
                if (EqualsArg(arg, "--output"))
                {
                    if (!TryReadValue(args, ref i, out result.OutputPath))
                    {
                        error = "--output requires a value.";
                        return result;
                    }
                    continue;
                }
                if (EqualsArg(arg, "--blob"))
                {
                    if (!TryReadValue(args, ref i, out result.BlobPath))
                    {
                        error = "--blob requires a value.";
                        return result;
                    }
                    continue;
                }

                error = "Unknown argument: " + arg;
                return result;
            }

            if (!String.IsNullOrWhiteSpace(result.Action))
            {
                string action = result.Action.Trim().ToLowerInvariant();
                if (action != "status" && action != "check" && action != "repair" && action != "join" && action != "rename" && action != "restart" && action != "mii-disable" && action != "detect" && action != "ad-check" && action != "diagnose" && action != "export-diagnostics" && action != "advanced" && action != "netsetup" && action != "dc-matrix" && action != "recovery-plan" && action != "support-bundle" && action != "cyberark" && action != "safe-fixes" && action != "odj-apply" && action != "odj-provision")
                {
                    error = "Unknown action '" + result.Action + "'. Use status, check, repair, join, rename, restart, mii-disable, detect, ad-check, diagnose, export-diagnostics, advanced, netsetup, dc-matrix, recovery-plan, support-bundle, cyberark, safe-fixes, odj-apply, or odj-provision.";
                    return result;
                }
                result.Action = action;
            }

            if (result.Json && String.IsNullOrWhiteSpace(result.Action))
            {
                error = "--json requires a one-shot --action.";
                return result;
            }

            if (result.Json && (result.Action == "repair" || result.Action == "join" || result.Action == "rename" ||
                                result.Action == "restart" || result.Action == "mii-disable" ||
                                result.Action == "odj-apply" || result.Action == "odj-provision"))
            {
                error = "--json is supported for read-only/reporting actions only.";
                return result;
            }

            return result;
        }

        private static bool TryReadValue(string[] args, ref int index, out string value)
        {
            value = String.Empty;
            if (index + 1 >= args.Length)
                return false;
            index++;
            value = (args[index] ?? String.Empty).Trim();
            return value.Length > 0;
        }

        private static bool EqualsArg(string value, params string[] choices)
        {
            foreach (string choice in choices)
            {
                if (value.Equals(choice, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            return false;
        }

        private static void PrintHeader()
        {
            Console.WriteLine("============================================================");
            Console.WriteLine(" Domain Membership Check & Repair v" + BuildInfo.Version + " - CLI");
            Console.WriteLine("============================================================");
            Console.WriteLine("Computer: " + Environment.MachineName);
            Console.WriteLine("Runtime:  " + BuildInfo.RuntimeSummary);
            Console.WriteLine("File log: " + (options.FileLogging ? "YES - " + CliLogger.LogFile : "NO (default)"));
            Console.WriteLine("Privilege: " + (ElevationHelper.IsAdministrator() ? "Administrator (elevated)" : "Standard user"));
            Console.WriteLine();
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Domain Membership Check & Repair");
            Console.WriteLine();
            Console.WriteLine("GUI:");
            Console.WriteLine("  DomainMembershipCheckRepair.exe");
            Console.WriteLine();
            Console.WriteLine("Interactive CLI:");
            Console.WriteLine("  DomainMembershipCheckRepair.exe --cli");
            Console.WriteLine();
            Console.WriteLine("One-shot CLI actions:");
            Console.WriteLine("  --cli --action status");
            Console.WriteLine("  --cli --action check");
            Console.WriteLine("  --cli --action repair");
            Console.WriteLine("  --cli --action join");
            Console.WriteLine("  --cli --action rename");
            Console.WriteLine("  --cli --action restart");
            Console.WriteLine("  --cli --action mii-disable");
            Console.WriteLine("  --cli --action detect");
            Console.WriteLine("  --cli --action ad-check");
            Console.WriteLine("  --cli --action diagnose");
            Console.WriteLine("  --cli --action export-diagnostics");
            Console.WriteLine("  --cli --action advanced");
            Console.WriteLine("  --cli --action netsetup");
            Console.WriteLine("  --cli --action dc-matrix");
            Console.WriteLine("  --cli --action recovery-plan");
            Console.WriteLine("  --cli --action support-bundle");
            Console.WriteLine("  --cli --action cyberark");
            Console.WriteLine("  --cli --action safe-fixes");
            Console.WriteLine("  --cli --action odj-apply --blob PATH");
            Console.WriteLine("  --cli --action odj-provision --domain DOMAIN --computer NAME --output PATH [--reuse]");
            Console.WriteLine();
            Console.WriteLine("Optional arguments:");
            Console.WriteLine("  --domain example.com");
            Console.WriteLine(@"  --user DOMAIN\username");
            Console.WriteLine("  --user username@example.com");
            Console.WriteLine("  --new-name PC-NEW-NAME        (rename action)");
            Console.WriteLine("  --computer PC-NAME            (ad-check; default: current computer)");
            Console.WriteLine("  --dc dc01.example.com         preferred DC for LDAP operations");
            Console.WriteLine("  --json                        JSON output for read-only/reporting actions");
            Console.WriteLine("  --dry-run                     show planned mutating action without changing Windows/AD");
            Console.WriteLine("  --output PATH                 diagnostics/support ZIP or ODJ provisioning output");
            Console.WriteLine("  --blob PATH                   Offline Domain Join provisioning blob to apply");
            Console.WriteLine("  --reuse                       allow djoin /provision to reuse an existing computer account");
            Console.WriteLine("  --include-app-log             include optional application log in diagnostic ZIP");
            Console.WriteLine("  --log                         write application log file");
            Console.WriteLine("  --no-log                      disable application log file (default)");
            Console.WriteLine("  --restart                     restart automatically after success");
            Console.WriteLine("  --no-restart                  never restart automatically");
            Console.WriteLine();
            Console.WriteLine("Passwords are NEVER accepted as command-line arguments and are never saved.");
            Console.WriteLine("When a password is required, the CLI prompts for it without echoing the value.");
            Console.WriteLine();
            Console.WriteLine("Exit codes:");
            Console.WriteLine("  0  Success / trust healthy");
            Console.WriteLine("  1  General operation failure");
            Console.WriteLine("  2  Trust is broken (check action)");
            Console.WriteLine("  3  Invalid argument or input");
            Console.WriteLine("  4  Computer is not a domain member");
            Console.WriteLine("  5  Trust repair failed");
            Console.WriteLine("  6  Domain join/rejoin failed");
            Console.WriteLine("  7  Operation cancelled");
            Console.WriteLine("  8  Rename/join failed");
            Console.WriteLine("  9  AD computer account deletion failed");
            Console.WriteLine(" 10  AD computer account not found (ad-check)");
            Console.WriteLine(" 11  AD lookup failed (ad-check)");
            Console.WriteLine(" 12  Restart required because a rename is pending");
            Console.WriteLine(" 13  Administrator elevation was cancelled, blocked, or ineffective");
        }

        private static int InteractiveMenu()
        {
            while (true)
            {
                Console.WriteLine();
                Console.WriteLine("Choose an operation:");
                Console.WriteLine("  1. Show status / check trust");
                Console.WriteLine("  2. Repair trust");
                Console.WriteLine("  3. Join / rejoin domain with current computer name");
                Console.WriteLine("  4. Rename computer + join domain");
                Console.WriteLine("  5. Detect target domain");
                Console.WriteLine("  6. Check AD computer account (read-only)");
                Console.WriteLine("  7. Diagnostics");
                Console.WriteLine("  8. Export diagnostics ZIP");
                Console.WriteLine("  9. Restart Windows");
                Console.WriteLine("  0. Exit");
                Console.Write("Selection: ");

                string selection = (Console.ReadLine() ?? String.Empty).Trim();
                Console.WriteLine();

                int result;
                switch (selection)
                {
                    case "1": result = ShowStatus(true); break;
                    case "2":
                        result = ExecuteAction("repair");
                        if (result == 5 && AskYesNo("Native trust repair failed. Try Join/Rejoin with the current computer name now?", false))
                            result = ExecuteAction("join");
                        break;
                    case "3": result = ExecuteAction("join"); break;
                    case "4": result = ExecuteAction("rename"); break;
                    case "5": result = DetectAndDisplayDomain(); break;
                    case "6": result = CheckAdAccount(); break;
                    case "7": result = Diagnostics(); break;
                    case "8": result = ExportDiagnostics(); break;
                    case "9": result = ExecuteAction("restart"); break;
                    case "0": return 0;
                    default:
                        Console.WriteLine("Invalid selection.");
                        continue;
                }

                Console.WriteLine("Result code: " + result);
            }
        }


        private static bool TryRelaunchElevatedIfNeeded(string action, out int exitCode)
        {
            exitCode = 0;

            if (!ElevationHelper.RequiresElevation(action) || options.DryRun || ElevationHelper.IsAdministrator())
                return false;

            if (options.ElevationAttempted)
            {
                logger.Log("ERROR",
                    "Administrator privileges are required, but the process is still not elevated after an elevation request. " +
                    "Check the Windows/CyberArk EPM policy for this executable.");
                exitCode = ElevationHelper.ElevationFailureExitCode;
                return true;
            }

            List<string> args = new List<string>(originalArgs ?? new string[0]);
            bool hasAction = false;
            bool hasMarker = false;

            for (int i = 0; i < args.Count; i++)
            {
                if (args[i].Equals("--action", StringComparison.OrdinalIgnoreCase))
                    hasAction = true;
                if (args[i].Equals("--elevation-attempted", StringComparison.OrdinalIgnoreCase))
                    hasMarker = true;
            }

            if (!hasAction)
            {
                args.Add("--action");
                args.Add(action);
            }
            if (!hasMarker)
                args.Add("--elevation-attempted");

            logger.Log("INFO",
                "Administrator privileges are required for '" + action +
                "'. Requesting elevation through the Windows elevation broker (compatible with CyberArk EPM).");

            string elevationError;
            int childExitCode;
            if (!ElevationHelper.TryStartElevated(args.ToArray(), true, out childExitCode, out elevationError))
            {
                logger.Log("ERROR", "Elevation was cancelled or blocked: " + elevationError);
                exitCode = ElevationHelper.ElevationFailureExitCode;
                return true;
            }

            exitCode = childExitCode;
            return true;
        }

        private static int ExecuteAction(string action)
        {
            int elevatedResult;
            if (TryRelaunchElevatedIfNeeded(action, out elevatedResult))
                return elevatedResult;

            switch (action)
            {
                case "status": return ShowStatus(true);
                case "check": return CheckTrustOnly();
                case "repair": return RepairTrust();
                case "join": return JoinCurrentName();
                case "rename": return RenameAndJoin(null, null, null, null);
                case "restart": return RestartWindows();
                case "mii-disable": return DisableMachineIdentityIsolation();
                case "advanced": return AdvancedDiagnostics();
                case "netsetup": return AnalyzeNetSetup();
                case "dc-matrix": return DcMatrix();
                case "recovery-plan": return RecoveryPlan();
                case "support-bundle": return SupportBundle();
                case "cyberark": return CyberArkHealth();
                case "safe-fixes": return SafeFixes();
                case "odj-apply": return ApplyOfflineDomainJoin();
                case "odj-provision": return ProvisionOfflineDomainJoin();
                case "detect": return DetectAndDisplayDomain();
                case "ad-check": return CheckAdAccount();
                case "diagnose": return Diagnostics();
                case "export-diagnostics": return ExportDiagnostics();
                default: return 3;
            }
        }

        private static int ShowStatus(bool verbose)
        {
            if (options.Json)
            {
                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(options.Domain, options.PreferredDc);
                Console.WriteLine(DiagnosticsService.ToJson(snapshot));
                return snapshot.ResultCode;
            }

            JoinInformation join = NativeMethods.GetJoinInformation();
            if (join.StatusCode != NativeMethods.NERR_Success)
            {
                logger.Log("ERROR", "NetGetJoinInformation failed: " + NativeMethods.FormatError(join.StatusCode));
                return 1;
            }

            if (join.Status != NetJoinStatus.NetSetupDomainName || String.IsNullOrWhiteSpace(join.Name))
            {
                Console.WriteLine("Domain membership: Not joined (" + join.Status.ToString() + ")");
                Console.WriteLine("Secure channel:   Not applicable");
                string target = DetectTargetDomain(false, String.Empty);
                Console.WriteLine("Detected target:  " + (String.IsNullOrWhiteSpace(target) ? "Not detected" : target));
                return 4;
            }

            DomainDiscoveryResult canonical = NativeMethods.DiscoverDomain(join.Name, false);
            string displayDomain = canonical.Success && !String.IsNullOrWhiteSpace(canonical.DnsDomainName) ? canonical.DnsDomainName : join.Name;
            TrustCheckResult trust = NativeMethods.VerifySecureChannel(join.Name);

            Console.WriteLine("Domain membership: " + displayDomain);
            Console.WriteLine("Secure channel:   " + (trust.Healthy ? "OK" : "BROKEN - " + NativeMethods.FormatError(trust.StatusCode)));
            if (!String.IsNullOrWhiteSpace(trust.TrustedDc))
                Console.WriteLine("Trusted DC:       " + trust.TrustedDc);

            if (verbose)
            {
                string target = ResolveConfiguredOrDetectedDomain(String.Empty, false);
                Console.WriteLine("Target domain:    " + (String.IsNullOrWhiteSpace(target) ? "Not detected" : target));
            }

            return trust.Healthy ? 0 : 2;
        }

        private static int CheckTrustOnly()
        {
            if (options.Json)
            {
                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(options.Domain, options.PreferredDc);
                Console.WriteLine(DiagnosticsService.ToJson(snapshot));
                return snapshot.ResultCode;
            }

            JoinInformation join = NativeMethods.GetJoinInformation();
            if (join.StatusCode != 0)
            {
                logger.Log("ERROR", "Unable to read domain membership: " + NativeMethods.FormatError(join.StatusCode));
                return 1;
            }

            if (join.Status != NetJoinStatus.NetSetupDomainName || String.IsNullOrWhiteSpace(join.Name))
            {
                logger.Log("INFO", "Computer is not currently joined to a domain.");
                return 4;
            }

            TrustCheckResult trust = NativeMethods.VerifySecureChannel(join.Name);
            if (trust.Healthy)
            {
                logger.Log("SUCCESS", "Secure channel is healthy." + FormatDcSuffix(trust.TrustedDc));
                return 0;
            }

            logger.Log("WARN", "Secure channel is broken: " + NativeMethods.FormatError(trust.StatusCode));
            return 2;
        }

        private static int RepairTrust()
        {
            JoinInformation join = NativeMethods.GetJoinInformation();
            if (join.StatusCode != 0)
            {
                logger.Log("ERROR", "Unable to read domain membership: " + NativeMethods.FormatError(join.StatusCode));
                return 1;
            }

            if (join.Status != NetJoinStatus.NetSetupDomainName || String.IsNullOrWhiteSpace(join.Name))
            {
                logger.Log("INFO", "Computer is not currently joined to a domain. Use the join action instead.");
                return 4;
            }

            string joinedDomain = join.Name;
            TrustCheckResult initial = NativeMethods.VerifySecureChannel(joinedDomain);
            if (initial.Healthy)
            {
                logger.Log("SUCCESS", "Secure channel is already healthy." + FormatDcSuffix(initial.TrustedDc));
                return 0;
            }

            if (options.DryRun)
            {
                Console.WriteLine("DRY RUN: secure channel is broken.");
                Console.WriteLine("Would request DC rediscovery, refresh the machine-account password if necessary, then verify the secure channel again.");
                Console.WriteLine("Domain: " + joinedDomain);
                return 0;
            }

            logger.Log("INFO", "Starting native secure-channel repair for the currently joined domain.");

            int rediscoverStatus = NativeMethods.NetlogonControl(NativeMethods.NETLOGON_CONTROL_REDISCOVER, 2, joinedDomain);
            if (rediscoverStatus != 0)
                logger.Log("WARN", "DC rediscovery returned: " + NativeMethods.FormatError(rediscoverStatus));

            TrustCheckResult afterRediscover = NativeMethods.VerifySecureChannel(joinedDomain);
            if (afterRediscover.Healthy)
            {
                logger.Log("SUCCESS", "Secure channel recovered after DC rediscovery." + FormatDcSuffix(afterRediscover.TrustedDc));
                HandleRestartAfterSuccess("Secure channel recovered successfully.");
                return 0;
            }

            int passwordStatus = NativeMethods.NetlogonControl(NativeMethods.NETLOGON_CONTROL_CHANGE_PASSWORD, 1, joinedDomain);
            logger.Log(passwordStatus == 0 ? "INFO" : "WARN", "Native machine-password refresh returned: " + NativeMethods.FormatError(passwordStatus));

            NativeMethods.NetlogonControl(NativeMethods.NETLOGON_CONTROL_REDISCOVER, 2, joinedDomain);
            TrustCheckResult final = NativeMethods.VerifySecureChannel(joinedDomain);
            if (final.Healthy)
            {
                logger.Log("SUCCESS", "Secure channel repaired successfully." + FormatDcSuffix(final.TrustedDc));
                HandleRestartAfterSuccess("Secure channel repaired successfully.");
                return 0;
            }

            logger.Log("ERROR", "Native trust repair did not restore the secure channel: " + NativeMethods.FormatError(final.StatusCode));
            return 5;
        }


        private static int DisableMachineIdentityIsolation()
        {
            int configuredValue;
            if (!HealthDiagnosticsService.HasMachineIdentityIsolationEnabled(out configuredValue))
            {
                Console.WriteLine("Machine Identity Isolation is not enabled.");
                return 0;
            }

            Console.WriteLine("Machine Identity Isolation: " + HealthDiagnosticsService.FormatMiiMode(configuredValue));
            Console.WriteLine("This changes local policy/LSA registry state and requires a restart.");
            Console.WriteLine("If Group Policy or Intune manages this setting, change the central policy too or it may be re-applied.");

            if (options.DryRun)
            {
                Console.WriteLine("DRY RUN: would set MachineIdentityIsolation=0 where the value is currently configured.");
                return 0;
            }

            if (!AskYesNo("Disable Machine Identity Isolation locally now?", false))
                return 7;

            string details;
            if (!HealthDiagnosticsService.DisableMachineIdentityIsolationLocally(out details))
            {
                logger.Log("ERROR", details);
                return 1;
            }

            logger.Log("SUCCESS", details);
            string resumeError;
            ResumeService.RegisterPostRebootCheck(options.Domain, out resumeError);
            if (!String.IsNullOrWhiteSpace(resumeError))
                logger.Log("WARN", "Unable to register post-reboot recovery check: " + resumeError);
            HandleRestartAfterSuccess("Machine Identity Isolation was disabled locally. A restart is required before trust repair/rejoin.");
            return 0;
        }


        private static void GetOptionalCredentials(out string user, out string password)
        {
            user = String.Empty;
            password = null;

            if (String.IsNullOrWhiteSpace(options.User))
                return;

            string validationError;
            if (!TryValidateUserName(options.User, out user, out validationError))
            {
                logger.Log("WARN", "Ignoring optional AD credentials: " + validationError);
                user = String.Empty;
                return;
            }

            Console.Write("Password for optional AD account analysis: ");
            password = ReadPassword();
            Console.WriteLine();
            if (password == null || password.Length == 0)
            {
                user = String.Empty;
                password = null;
            }
        }

        private static int AdvancedDiagnostics()
        {
            string user;
            string password;
            GetOptionalCredentials(out user, out password);

            AdvancedDiagnosticsResult result = AdvancedDiagnosticsService.Analyze(
                options.Domain,
                options.PreferredDc,
                String.IsNullOrWhiteSpace(options.ComputerName) ? Environment.MachineName : options.ComputerName,
                user,
                password);

            Console.WriteLine(AdvancedDiagnosticsService.ToText(result));
            return result.Snapshot == null ? 1 : result.Snapshot.ResultCode;
        }

        private static int AnalyzeNetSetup()
        {
            NetSetupAnalysis analysis = NetSetupLogAnalyzer.Analyze(DiagnosticsService.NetSetupLogPath);
            Console.WriteLine(NetSetupLogAnalyzer.ToText(analysis));
            return analysis.Present ? 0 : 1;
        }

        private static int DcMatrix()
        {
            string domain = ResolveConfiguredOrDetectedDomain(String.Empty, true);
            if (String.IsNullOrWhiteSpace(domain))
                return 3;

            DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(domain, options.PreferredDc);
            string user;
            string password;
            GetOptionalCredentials(out user, out password);

            DcMatrixResult matrix = DcMatrixService.Analyze(
                snapshot.TargetDomain,
                snapshot.DiscoveredDc,
                String.IsNullOrWhiteSpace(options.ComputerName) ? Environment.MachineName : options.ComputerName,
                user,
                password);
            Console.WriteLine(DcMatrixService.ToText(matrix));
            return matrix.Entries.Count > 0 ? 0 : 1;
        }

        private static int RecoveryPlan()
        {
            string user;
            string password;
            GetOptionalCredentials(out user, out password);

            AdvancedDiagnosticsResult result = AdvancedDiagnosticsService.Analyze(
                options.Domain,
                options.PreferredDc,
                String.IsNullOrWhiteSpace(options.ComputerName) ? Environment.MachineName : options.ComputerName,
                user,
                password);
            Console.WriteLine(RecoveryPlanService.ToText(result.RecoveryPlan));
            return 0;
        }

        private static int SupportBundle()
        {
            string user;
            string password;
            GetOptionalCredentials(out user, out password);

            try
            {
                AdvancedDiagnosticsResult result = AdvancedDiagnosticsService.Analyze(
                    options.Domain,
                    options.PreferredDc,
                    String.IsNullOrWhiteSpace(options.ComputerName) ? Environment.MachineName : options.ComputerName,
                    user,
                    password);

                string archive = AdvancedSupportBundleService.Export(
                    result,
                    options.OutputPath,
                    options.IncludeApplicationLog);
                Console.WriteLine("Support bundle: " + archive);
                return 0;
            }
            catch (Exception ex)
            {
                logger.Log("ERROR", "Support bundle failed: " + ex.Message);
                return 1;
            }
        }

        private static int CyberArkHealth()
        {
            Console.WriteLine(CyberArkDiagnosticsService.ToText(CyberArkDiagnosticsService.Analyze()));
            return 0;
        }


        private static int SafeFixes()
        {
            string domain = (options.Domain ?? String.Empty).Trim();
            if (String.IsNullOrWhiteSpace(domain))
                domain = DetectTargetDomain(false, String.Empty);

            if (options.DryRun)
            {
                Console.WriteLine("DRY RUN: would flush DNS, resync Windows Time, restart Netlogon, and force DC rediscovery.");
                Console.WriteLine("No AD object would be deleted, no rename would be performed, and no domain join/rejoin would be attempted.");
                return 0;
            }

            if (!AskYesNo(
                "Run safe recovery actions (flush DNS, resync time, restart Netlogon, rediscover DC) now?",
                false))
                return 7;

            SafeRecoveryResult result = SafeRecoveryService.Run(domain);
            Console.WriteLine(SafeRecoveryService.ToText(result));
            return result.Success ? 0 : 1;
        }

        private static int ApplyOfflineDomainJoin()
        {
            if (String.IsNullOrWhiteSpace(options.BlobPath))
            {
                logger.Log("ERROR", "--blob PATH is required for odj-apply.");
                return 3;
            }

            if (options.DryRun)
            {
                Console.WriteLine("DRY RUN: would apply Offline Domain Join blob: " + options.BlobPath);
                return 0;
            }

            string output;
            int code = OfflineDomainJoinService.ApplyBlob(options.BlobPath, out output);
            Console.WriteLine(output);
            if (code == 0)
            {
                string resumeError;
                ResumeService.RegisterPostRebootCheck(options.Domain, out resumeError);
                if (!String.IsNullOrWhiteSpace(resumeError))
                    logger.Log("WARN", "Unable to register post-reboot check: " + resumeError);
                HandleRestartAfterSuccess("Offline Domain Join was applied successfully.");
            }
            return code == 0 ? 0 : 1;
        }

        private static int ProvisionOfflineDomainJoin()
        {
            string domain = (options.Domain ?? String.Empty).Trim();
            string machine = (options.ComputerName ?? String.Empty).Trim();
            string outputPath = (options.OutputPath ?? String.Empty).Trim();

            if (String.IsNullOrWhiteSpace(domain) || String.IsNullOrWhiteSpace(machine) || String.IsNullOrWhiteSpace(outputPath))
            {
                logger.Log("ERROR", "odj-provision requires --domain, --computer, and --output.");
                return 3;
            }

            if (options.DryRun)
            {
                Console.WriteLine("DRY RUN: would provision an Offline Domain Join blob for " + machine + " in " + domain + ".");
                return 0;
            }

            string output;
            int code = OfflineDomainJoinService.ProvisionBlob(
                domain,
                machine,
                outputPath,
                options.ReuseComputerAccount,
                out output);
            Console.WriteLine(output);
            return code == 0 ? 0 : 1;
        }

        private static int DetectAndDisplayDomain()
        {
            string domain = ResolveConfiguredOrDetectedDomain(String.Empty, true);
            if (String.IsNullOrWhiteSpace(domain))
            {
                logger.Log("WARN", "A target domain could not be detected automatically.");
                return 1;
            }

            if (options.Json)
                Console.WriteLine("{\"targetDomain\":\"" + JsonEscape(domain) + "\"}");
            else
                Console.WriteLine("Target domain: " + domain);
            return 0;
        }

        private static int Diagnostics()
        {
            DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(options.Domain, options.PreferredDc);
            if (options.Json)
                Console.WriteLine(DiagnosticsService.ToJson(snapshot));
            else
                Console.WriteLine(DiagnosticsService.ToText(snapshot));

            return snapshot.ResultCode;
        }

        private static int ExportDiagnostics()
        {
            try
            {
                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(options.Domain, options.PreferredDc);
                string archive = DiagnosticsService.ExportPackage(snapshot, options.OutputPath, options.IncludeApplicationLog);
                if (options.Json)
                    Console.WriteLine("{\"archive\":\"" + JsonEscape(archive) + "\",\"resultCode\":" + snapshot.ResultCode + "}");
                else
                    Console.WriteLine("Diagnostics archive: " + archive);
                return 0;
            }
            catch (Exception ex)
            {
                if (options.Json)
                    Console.WriteLine("{\"error\":\"" + JsonEscape(ex.Message) + "\"}");
                else
                    logger.Log("ERROR", "Unable to export diagnostics: " + ex.Message);
                return 1;
            }
        }

        private static int CheckAdAccount()
        {
            string user;
            string password;
            if (!GetCredentials(out user, out password))
                return 7;

            string targetDomain = ResolveConfiguredOrDetectedDomain(user, true);
            if (String.IsNullOrWhiteSpace(targetDomain))
                return 3;

            string computerName = (options.ComputerName ?? String.Empty).Trim();
            if (String.IsNullOrWhiteSpace(computerName))
                computerName = Environment.MachineName;

            string validationError = ValidateComputerName(computerName);
            if (validationError != null)
            {
                logger.Log("ERROR", "Invalid computer name for AD lookup: " + validationError);
                return 3;
            }

            logger.Log("INFO", "Performing read-only AD computer account check for '" + computerName + "'.");
            AdComputerAccountInfo account = FindComputerAccount(computerName, user, password, targetDomain);
            if (!account.LookupSucceeded)
            {
                if (options.Json)
                    Console.WriteLine("{\"computer\":\"" + JsonEscape(computerName) + "\",\"domain\":\"" + JsonEscape(targetDomain) + "\",\"lookupSucceeded\":false,\"exists\":false,\"exitCode\":11}");
                else
                    logger.Log("ERROR", "AD computer account lookup could not be completed. No changes were made.");
                return 11;
            }

            if (!account.Exists)
            {
                if (options.Json)
                    Console.WriteLine("{\"computer\":\"" + JsonEscape(computerName) + "\",\"domain\":\"" + JsonEscape(targetDomain) + "\",\"lookupSucceeded\":true,\"exists\":false,\"exitCode\":10}");
                else
                {
                    Console.WriteLine("Computer account: NOT FOUND");
                    Console.WriteLine("Computer:         " + computerName);
                    Console.WriteLine("Domain:           " + targetDomain);
                    Console.WriteLine("Read-only check; no changes were made.");
                }
                return 10;
            }

            if (options.Json)
                Console.WriteLine(FormatAdAccountJson(computerName, targetDomain, account));
            else
                Console.WriteLine(FormatAdAccountReport(computerName, targetDomain, account));
            return 0;
        }

        private static int JoinCurrentName()
        {
            string pendingName;
            if (HasPendingRename(out pendingName))
            {
                logger.Log("WARN", "Join/Rejoin blocked because a computer rename is pending: " + pendingName + ". Restart Windows first.");
                return 12;
            }

            if (options.DryRun)
            {
                string dryRunDomain = ResolveConfiguredOrDetectedDomain(String.Empty, true);
                if (String.IsNullOrWhiteSpace(dryRunDomain))
                    return 3;
                Console.WriteLine("DRY RUN: no domain or Windows changes will be made.");
                Console.WriteLine("Would Join/Rejoin computer '" + Environment.MachineName + "' to domain '" + dryRunDomain + "'.");
                Console.WriteLine("Preferred LDAP DC: " + (String.IsNullOrWhiteSpace(options.PreferredDc) ? "Auto" : options.PreferredDc));
                return 0;
            }

            string user;
            string password;
            if (!GetCredentials(out user, out password))
                return 7;

            string targetDomain = ResolveConfiguredOrDetectedDomain(user, true);
            if (String.IsNullOrWhiteSpace(targetDomain))
                return 3;

            string currentName = Environment.MachineName;
            logger.Log("INFO", "Attempting Join/Rejoin with the current computer name '" + currentName + "'.");

            int status = NativeMethods.JoinDomain(targetDomain, user, password, false);
            if (status == NativeMethods.NERR_Success)
            {
                logger.Log("SUCCESS", "Join/Rejoin succeeded with the current computer name.");
                HandleRestartAfterSuccess("Domain Join/Rejoin completed successfully.");
                return 0;
            }

            logger.Log("ERROR", "Join/Rejoin with current name failed: " + NativeMethods.FormatError(status));

            bool existingAccount = false;
            bool nameConflict = status == NativeMethods.NERR_UserExists || status == NativeMethods.NERR_AccountReuseBlockedByPolicy;

            if (!nameConflict && status == NativeMethods.ERROR_ACCESS_DENIED)
            {
                bool? adExists = ComputerAccountExists(currentName, user, password, targetDomain);
                if (adExists.HasValue && adExists.Value)
                {
                    existingAccount = true;
                    nameConflict = true;
                    logger.Log("WARN", "Access was denied and the same computer account was confirmed to exist in Active Directory.");
                }
            }

            if (status == NativeMethods.NERR_UserExists || status == NativeMethods.NERR_AccountReuseBlockedByPolicy)
                existingAccount = true;

            if (!nameConflict)
            {
                Console.WriteLine("Join/Rejoin failed. This error does not prove that the computer name already exists.");
                Console.WriteLine("Check C:\\Windows\\Debug\\NetSetup.log");
                return 6;
            }

            string reason;
            if (status == NativeMethods.NERR_AccountReuseBlockedByPolicy)
                reason = "An account with the same computer name exists and Windows blocked account reuse by security policy.";
            else if (status == NativeMethods.NERR_UserExists)
                reason = "A computer account with the same name already exists in Active Directory.";
            else if (existingAccount)
                reason = "A computer account with the same name exists and the supplied account cannot reuse it.";
            else
                reason = "The current computer name could not be reused in Active Directory.";

            logger.Log("WARN", reason);

            AdComputerAccountInfo account = FindComputerAccount(currentName, user, password, targetDomain);
            bool canDelete = account.LookupSucceeded && account.Exists && !String.IsNullOrWhiteSpace(account.LdapPath);

            Console.WriteLine();
            Console.WriteLine("Computer account conflict detected.");
            Console.WriteLine("Computer: " + currentName);
            if (canDelete)
            {
                Console.WriteLine("AD object:      " + account.DistinguishedName);
                Console.WriteLine("Owner:          " + FirstNonEmpty(account.Owner, "(unknown)"));
                Console.WriteLine("pwdLastSet:     " + FirstNonEmpty(account.PwdLastSet, "(unknown)"));
                Console.WriteLine("SPN count:      " + account.ServicePrincipalNameCount);
                Console.WriteLine("Child objects:  " + account.ChildObjectCount);
            }
            else
            {
                Console.WriteLine("AD object could not be located with the supplied credentials. Delete is unavailable.");
            }

            Console.WriteLine();
            Console.WriteLine("Recommended order:");
            Console.WriteLine("  1. Safe Fixes + retry SAME name");
            Console.WriteLine("  2. Use a NEW computer name and join");
            if (canDelete)
                Console.WriteLine("  3. DELETE existing AD object + retry SAME name (last resort)");
            Console.WriteLine("  4. Cancel");
            Console.Write("Selection: ");

            string selection = (Console.ReadLine() ?? String.Empty).Trim();
            if (selection == "1")
                return SafeFixesAndRetryJoin(currentName, user, password, targetDomain);
            if (selection == "2")
                return RenameAndJoin(currentName, user, password, targetDomain);
            if (selection == "3" && canDelete)
                return DeleteExistingAccountAndRetryJoin(currentName, user, password, targetDomain, account);

            logger.Log("INFO", "Operation cancelled by the operator.");
            return 7;
        }

        private static int SafeFixesAndRetryJoin(string computerName, string user, string password, string targetDomain)
        {
            logger.Log("INFO", "Running non-destructive Safe Fixes before retrying Join/Rejoin with the same computer name.");
            SafeRecoveryResult safe = SafeRecoveryService.Run(targetDomain);

            foreach (string step in safe.Steps)
                logger.Log(step.StartsWith("OK:", StringComparison.OrdinalIgnoreCase) ? "INFO" : "WARN", step);

            NativeMethods.DiscoverDomain(targetDomain, true);
            int status = NativeMethods.JoinDomain(targetDomain, user, password, false);

            if (status == NativeMethods.NERR_Success)
            {
                logger.Log("SUCCESS", "Join/Rejoin succeeded after Safe Fixes using the existing computer name.");
                HandleRestartAfterSuccess("Safe Fixes completed and Join/Rejoin succeeded with the existing computer name.");
                return 0;
            }

            logger.Log("ERROR", "Join/Rejoin still failed after Safe Fixes: " + NativeMethods.FormatError(status));
            Console.WriteLine();
            Console.WriteLine("No AD computer object was deleted.");
            Console.WriteLine("Run --action advanced or --action recovery-plan before considering Delete + Recreate.");
            return 6;
        }

        private static int RenameAndJoin(string currentName, string existingUser, string existingPassword, string existingTargetDomain)
        {
            if (String.IsNullOrWhiteSpace(currentName))
                currentName = Environment.MachineName;

            string pendingName;
            if (HasPendingRename(out pendingName))
            {
                logger.Log("WARN", "A computer rename is already pending: " + pendingName + ". Restart Windows before trying another rename.");
                return 8;
            }

            if (options.DryRun)
            {
                string dryRunDomain = !String.IsNullOrWhiteSpace(existingTargetDomain)
                    ? existingTargetDomain
                    : ResolveConfiguredOrDetectedDomain(String.Empty, true);
                if (String.IsNullOrWhiteSpace(dryRunDomain))
                    return 3;

                string dryRunName = (options.NewName ?? String.Empty).Trim();
                if (String.IsNullOrWhiteSpace(dryRunName))
                {
                    string defaultName = DomainValidation.CreateSuggestedName(currentName);
                    Console.Write("New computer name [" + defaultName + "]: ");
                    dryRunName = (Console.ReadLine() ?? String.Empty).Trim();
                    if (dryRunName.Length == 0)
                        dryRunName = defaultName;
                }

                string dryRunValidation = DomainValidation.ValidateComputerName(dryRunName);
                if (dryRunValidation != null)
                {
                    Console.WriteLine("Invalid computer name: " + dryRunValidation);
                    return 3;
                }

                Console.WriteLine("DRY RUN: no computer name or domain changes will be made.");
                Console.WriteLine("Would set pending computer name to '" + dryRunName + "' and join domain '" + dryRunDomain + "'.");
                Console.WriteLine("Current computer name: " + currentName);
                return 0;
            }

            string user = existingUser;
            string password = existingPassword;
            if (String.IsNullOrWhiteSpace(user) || password == null)
            {
                if (!GetCredentials(out user, out password))
                    return 7;
            }

            string targetDomain = !String.IsNullOrWhiteSpace(existingTargetDomain)
                ? existingTargetDomain
                : ResolveConfiguredOrDetectedDomain(user, true);
            if (String.IsNullOrWhiteSpace(targetDomain))
                return 3;

            string requestedName = (options.NewName ?? String.Empty).Trim();
            string suggested = CreateSuggestedName(currentName);

            while (true)
            {
                if (String.IsNullOrWhiteSpace(requestedName))
                {
                    Console.Write("New computer name [" + suggested + "]: ");
                    requestedName = (Console.ReadLine() ?? String.Empty).Trim();
                    if (requestedName.Length == 0)
                        requestedName = suggested;
                }

                string validationError = ValidateComputerName(requestedName);
                if (validationError != null)
                {
                    Console.WriteLine("Invalid computer name: " + validationError);
                    if (!String.IsNullOrWhiteSpace(options.NewName))
                        return 3;
                    requestedName = String.Empty;
                    continue;
                }

                bool? exists = ComputerAccountExists(requestedName, user, password, targetDomain);
                if (exists.HasValue && exists.Value)
                {
                    Console.WriteLine("The computer account '" + requestedName + "$' already exists in Active Directory.");
                    if (!String.IsNullOrWhiteSpace(options.NewName))
                        return 8;
                    suggested = CreateSuggestedName(requestedName);
                    requestedName = String.Empty;
                    continue;
                }

                break;
            }

            logger.Log("INFO", "Setting pending computer name to '" + requestedName + "'.");
            int renameError;
            if (!NativeMethods.SetPendingComputerName(requestedName, out renameError))
            {
                logger.Log("ERROR", "SetComputerNameEx failed: " + NativeMethods.FormatError(renameError));
                return 8;
            }

            logger.Log("INFO", "Attempting domain join with pending new name '" + requestedName + "'.");
            int joinStatus = NativeMethods.JoinDomain(targetDomain, user, password, true);

            if (joinStatus == NativeMethods.NERR_Success)
            {
                logger.Log("SUCCESS", "Rename + domain join succeeded. New name after reboot: " + requestedName);
                HandleRestartAfterSuccess("Rename and domain join completed successfully. New computer name after restart: " + requestedName);
                return 0;
            }

            logger.Log("ERROR", "Rename + domain join failed: " + NativeMethods.FormatError(joinStatus));

            int rollbackError;
            bool rollbackOk = NativeMethods.SetPendingComputerName(currentName, out rollbackError);
            if (rollbackOk)
                logger.Log("INFO", "Pending computer name was rolled back to '" + currentName + "'.");
            else
                logger.Log("WARN", "Unable to roll back the pending computer name: " + NativeMethods.FormatError(rollbackError));

            Console.WriteLine("Check C:\\Windows\\Debug\\NetSetup.log");
            return 8;
        }

        private static bool GetCredentials(out string user, out string password)
        {
            user = String.Empty;
            password = null;

            string candidate = (options.User ?? String.Empty).Trim();
            while (true)
            {
                if (String.IsNullOrWhiteSpace(candidate))
                {
                    Console.WriteLine(@"User format: DOMAIN\username   or   username@example.com");
                    Console.Write("Domain user: ");
                    candidate = (Console.ReadLine() ?? String.Empty).Trim();
                    if (candidate.Length == 0)
                    {
                        Console.WriteLine("Cancelled.");
                        return false;
                    }
                }

                string validationError;
                if (TryValidateUserName(candidate, out user, out validationError))
                    break;

                Console.WriteLine("Invalid user name: " + validationError);
                Console.WriteLine(@"Use: DOMAIN\username   or   username@example.com");
                if (!String.IsNullOrWhiteSpace(options.User))
                    return false;
                candidate = String.Empty;
            }

            Console.Write("Password: ");
            password = ReadPassword();
            Console.WriteLine();

            if (password == null)
            {
                Console.WriteLine("Cancelled.");
                return false;
            }
            if (password.Length == 0)
            {
                Console.WriteLine("Password cannot be empty.");
                return false;
            }

            return true;
        }

        private static string ReadPassword()
        {
            StringBuilder password = new StringBuilder();
            while (true)
            {
                ConsoleKeyInfo key;
                try
                {
                    key = Console.ReadKey(true);
                }
                catch
                {
                    return null;
                }

                if (key.Key == ConsoleKey.Enter)
                    break;
                if (key.Key == ConsoleKey.Escape)
                    return null;
                if (key.Key == ConsoleKey.Backspace)
                {
                    if (password.Length > 0)
                    {
                        password.Length--;
                        Console.Write("\b \b");
                    }
                    continue;
                }

                if (!Char.IsControl(key.KeyChar))
                {
                    password.Append(key.KeyChar);
                    Console.Write("*");
                }
            }
            return password.ToString();
        }

        private static string ResolveConfiguredOrDetectedDomain(string user, bool allowPrompt)
        {
            string candidate = (options.Domain ?? String.Empty).Trim();
            if (String.IsNullOrWhiteSpace(candidate))
                candidate = DetectTargetDomain(false, user);
            if (String.IsNullOrWhiteSpace(candidate))
                candidate = ExtractDomainHintFromUser(user);

            if (allowPrompt && String.IsNullOrWhiteSpace(options.Action))
            {
                if (String.IsNullOrWhiteSpace(candidate))
                {
                    Console.Write("Target domain (for example, example.com): ");
                    candidate = (Console.ReadLine() ?? String.Empty).Trim();
                }
                else
                {
                    Console.Write("Target domain [" + candidate + "]: ");
                    string overrideDomain = (Console.ReadLine() ?? String.Empty).Trim();
                    if (!String.IsNullOrWhiteSpace(overrideDomain))
                        candidate = overrideDomain;
                }
            }
            else if (String.IsNullOrWhiteSpace(candidate) && allowPrompt)
            {
                Console.Write("Target domain (for example, example.com): ");
                candidate = (Console.ReadLine() ?? String.Empty).Trim();
            }

            if (String.IsNullOrWhiteSpace(candidate))
                return String.Empty;

            DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(candidate, true);
            if (resolved.Success && !String.IsNullOrWhiteSpace(resolved.DnsDomainName))
            {
                logger.Log("INFO", "Target domain validated by domain controller discovery." + FormatDcSuffix(resolved.DomainControllerName));
                return resolved.DnsDomainName;
            }

            logger.Log("WARN", "Domain controller discovery could not validate the target domain: " + NativeMethods.FormatError(resolved.StatusCode));
            return candidate;
        }

        private static string DetectTargetDomain(bool forceRediscovery, string user)
        {
            if (!String.IsNullOrWhiteSpace(options.Domain))
                return options.Domain.Trim();

            JoinInformation join = NativeMethods.GetJoinInformation();
            if (join.StatusCode == 0 && join.Status == NetJoinStatus.NetSetupDomainName && !String.IsNullOrWhiteSpace(join.Name))
            {
                DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(join.Name, forceRediscovery);
                return resolved.Success && !String.IsNullOrWhiteSpace(resolved.DnsDomainName) ? resolved.DnsDomainName : join.Name;
            }

            string physicalSuffix = NativeMethods.GetPhysicalDnsDomain();
            if (!String.IsNullOrWhiteSpace(physicalSuffix))
            {
                DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(physicalSuffix, forceRediscovery);
                if (resolved.Success)
                    return !String.IsNullOrWhiteSpace(resolved.DnsDomainName) ? resolved.DnsDomainName : physicalSuffix;
            }

            string userDnsDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            if (!String.IsNullOrWhiteSpace(userDnsDomain))
            {
                DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(userDnsDomain, forceRediscovery);
                if (resolved.Success)
                    return !String.IsNullOrWhiteSpace(resolved.DnsDomainName) ? resolved.DnsDomainName : userDnsDomain;
            }

            string hint = ExtractDomainHintFromUser(user);
            if (!String.IsNullOrWhiteSpace(hint))
            {
                DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(hint, forceRediscovery);
                return resolved.Success && !String.IsNullOrWhiteSpace(resolved.DnsDomainName) ? resolved.DnsDomainName : hint;
            }

            return String.Empty;
        }

        private static string ExtractDomainHintFromUser(string user)
        {
            return DomainValidation.ExtractDomainHintFromUser(user);
        }

        private static bool TryValidateUserName(string input, out string normalized, out string error)
        {
            return DomainValidation.TryValidateUserName(input, out normalized, out error);
        }

        private static bool? ComputerAccountExists(string computerName, string user, string password, string targetDomain)
        {
            AdComputerAccountInfo info = FindComputerAccount(computerName, user, password, targetDomain);
            if (!info.LookupSucceeded)
                return null;
            return info.Exists;
        }

        private static AdComputerAccountInfo FindComputerAccount(string computerName, string user, string password, string targetDomain)
        {
            return AdDirectoryService.FindComputerAccount(
                computerName,
                user,
                password,
                targetDomain,
                options.PreferredDc,
                logger.Log);
        }

        private static string FormatAdAccountReport(string computerName, string targetDomain, AdComputerAccountInfo account)
        {
            StringBuilder report = new StringBuilder();
            report.AppendLine("Computer account:   FOUND");
            report.AppendLine("Computer:           " + computerName);
            report.AppendLine("Domain:             " + targetDomain);
            report.AppendLine("Distinguished name: " + FirstNonEmpty(account.DistinguishedName, "(not returned)"));
            report.AppendLine("DNS host name:      " + FirstNonEmpty(account.DnsHostName, "(not set)"));
            report.AppendLine("Enabled:            " + (account.Enabled.HasValue ? (account.Enabled.Value ? "Yes" : "No") : "(unknown)"));
            report.AppendLine("Operating system:   " + FirstNonEmpty(account.OperatingSystem, "(not set)"));
            report.AppendLine("Description:        " + FirstNonEmpty(account.Description, "(not set)"));
            report.AppendLine("Object GUID:        " + FirstNonEmpty(account.ObjectGuid, "(not returned)"));
            report.AppendLine("Created:            " + FirstNonEmpty(account.WhenCreated, "(not returned)"));
            report.AppendLine("Changed:            " + FirstNonEmpty(account.WhenChanged, "(not returned)"));
            report.AppendLine("Owner:              " + FirstNonEmpty(account.Owner, "(not returned)"));
            report.AppendLine("pwdLastSet:         " + FirstNonEmpty(account.PwdLastSet, "(not returned)"));
            report.AppendLine("Last logon:         " + FirstNonEmpty(account.LastLogonTimestamp, "(not returned)"));
            report.AppendLine("Canonical name:     " + FirstNonEmpty(account.CanonicalName, "(not returned)"));
            report.AppendLine("SPN count:          " + account.ServicePrincipalNameCount);
            report.AppendLine("Child objects:      " + account.ChildObjectCount);
            report.AppendLine("Encryption types:   " + (account.SupportedEncryptionTypes.HasValue ? account.SupportedEncryptionTypes.Value.ToString() : "(unknown)"));
            if (!String.IsNullOrWhiteSpace(account.ServicePrincipalNames))
                report.AppendLine("SPNs:               " + account.ServicePrincipalNames);
            report.AppendLine("Read-only check; no changes were made.");
            return report.ToString();
        }

        private static int DeleteExistingAccountAndRetryJoin(string computerName, string user, string password, string targetDomain, AdComputerAccountInfo account)
        {
            if (account == null || !account.LookupSucceeded || !account.Exists || String.IsNullOrWhiteSpace(account.LdapPath))
            {
                logger.Log("ERROR", "The existing AD computer account could not be located reliably, so it will not be deleted.");
                return 9;
            }

            string dn = String.IsNullOrWhiteSpace(account.DistinguishedName) ? computerName + "$" : account.DistinguishedName;
            Console.WriteLine();
            Console.WriteLine("WARNING: DESTRUCTIVE ACTIVE DIRECTORY OPERATION");
            Console.WriteLine("Object: " + dn);
            Console.WriteLine("Owner: " + FirstNonEmpty(account.Owner, "(unknown)"));
            Console.WriteLine("pwdLastSet: " + FirstNonEmpty(account.PwdLastSet, "(unknown)"));
            Console.WriteLine("SPN count: " + account.ServicePrincipalNameCount);
            Console.WriteLine("Child objects: " + account.ChildObjectCount);
            Console.WriteLine("Deleting the computer object can also delete child data stored below it, including recovery information such as LAPS or BitLocker recovery child objects.");
            Console.WriteLine("After deletion, the tool will retry Join/Rejoin using the SAME computer name.");
            Console.WriteLine();
            Console.Write("Type DELETE to confirm: ");
            string confirm = (Console.ReadLine() ?? String.Empty).Trim();
            if (!confirm.Equals("DELETE", StringComparison.Ordinal))
            {
                logger.Log("INFO", "AD computer account deletion cancelled by the operator.");
                return 7;
            }

            string deleteError;
            if (!AdDirectoryService.DeleteComputerAccount(account, computerName, user, password, logger.Log, out deleteError))
            {
                logger.Log("ERROR", "Unable to delete the AD computer account safely: " + deleteError);
                return 9;
            }

            int[] retryDelays = new int[] { 2, 4, 8, 12 };
            int status = NativeMethods.ERROR_ACCESS_DENIED;

            for (int attempt = 0; attempt < retryDelays.Length; attempt++)
            {
                int delay = retryDelays[attempt];
                logger.Log("INFO", "Waiting " + delay + " second(s) before Join/Rejoin retry " + (attempt + 1) + " of " + retryDelays.Length + " to allow AD replication.");
                Thread.Sleep(delay * 1000);

                NativeMethods.DiscoverDomain(targetDomain, true);
                status = NativeMethods.JoinDomain(targetDomain, user, password, false);
                if (status == NativeMethods.NERR_Success)
                {
                    logger.Log("SUCCESS", "Join/Rejoin succeeded after deleting and recreating the AD computer account.");
                    HandleRestartAfterSuccess("The old AD computer account was deleted and the computer was joined to the domain again successfully.");
                    return 0;
                }

                logger.Log("WARN", "Join/Rejoin retry " + (attempt + 1) + " failed: " + NativeMethods.FormatError(status));

                if (status != NativeMethods.NERR_UserExists &&
                    status != NativeMethods.NERR_AccountReuseBlockedByPolicy &&
                    status != NativeMethods.ERROR_ACCESS_DENIED &&
                    status != NativeMethods.ERROR_NO_LOGON_SERVERS &&
                    status != NativeMethods.ERROR_NO_SUCH_DOMAIN)
                    break;
            }

            logger.Log("ERROR", "Join/Rejoin after AD account deletion failed after retry/backoff: " + NativeMethods.FormatError(status));

            if (status == NativeMethods.NERR_UserExists || status == NativeMethods.NERR_AccountReuseBlockedByPolicy || status == NativeMethods.ERROR_ACCESS_DENIED)
            {
                if (AskYesNo("The join still reports an account/name conflict. Try a NEW computer name now?", false))
                    return RenameAndJoin(computerName, user, password, targetDomain);
            }

            Console.WriteLine("Check C:\\Windows\\Debug\\NetSetup.log");
            return 6;
        }

        private static string EscapeLdapFilterValue(string value)
        {
            return DomainValidation.EscapeLdapFilterValue(value);
        }

        private static string ValidateComputerName(string name)
        {
            return DomainValidation.ValidateComputerName(name);
        }

        private static string CreateSuggestedName(string currentName)
        {
            return DomainValidation.CreateSuggestedName(currentName);
        }

        private static bool HasPendingRename(out string pendingName)
        {
            return DiagnosticsService.HasPendingRename(out pendingName);
        }

        private static string FormatAdAccountJson(string computerName, string targetDomain, AdComputerAccountInfo account)
        {
            StringBuilder json = new StringBuilder();
            json.Append("{");
            json.Append("\"computer\":\"").Append(JsonEscape(computerName)).Append("\",");
            json.Append("\"domain\":\"").Append(JsonEscape(targetDomain)).Append("\",");
            json.Append("\"lookupSucceeded\":true,");
            json.Append("\"exists\":true,");
            json.Append("\"distinguishedName\":\"").Append(JsonEscape(account.DistinguishedName)).Append("\",");
            json.Append("\"dnsHostName\":\"").Append(JsonEscape(account.DnsHostName)).Append("\",");
            json.Append("\"enabled\":");
            if (account.Enabled.HasValue)
                json.Append(account.Enabled.Value ? "true" : "false");
            else
                json.Append("null");
            json.Append(",");
            json.Append("\"operatingSystem\":\"").Append(JsonEscape(account.OperatingSystem)).Append("\",");
            json.Append("\"description\":\"").Append(JsonEscape(account.Description)).Append("\",");
            json.Append("\"objectGuid\":\"").Append(JsonEscape(account.ObjectGuid)).Append("\",");
            json.Append("\"whenCreated\":\"").Append(JsonEscape(account.WhenCreated)).Append("\",");
            json.Append("\"whenChanged\":\"").Append(JsonEscape(account.WhenChanged)).Append("\",");
            json.Append("\"owner\":\"").Append(JsonEscape(account.Owner)).Append("\",");
            json.Append("\"pwdLastSet\":\"").Append(JsonEscape(account.PwdLastSet)).Append("\",");
            json.Append("\"lastLogonTimestamp\":\"").Append(JsonEscape(account.LastLogonTimestamp)).Append("\",");
            json.Append("\"canonicalName\":\"").Append(JsonEscape(account.CanonicalName)).Append("\",");
            json.Append("\"servicePrincipalNameCount\":").Append(account.ServicePrincipalNameCount).Append(",");
            json.Append("\"childObjectCount\":").Append(account.ChildObjectCount).Append(",");
            json.Append("\"supportedEncryptionTypes\":");
            if (account.SupportedEncryptionTypes.HasValue)
                json.Append(account.SupportedEncryptionTypes.Value);
            else
                json.Append("null");
            json.Append(",");
            json.Append("\"exitCode\":0");
            json.Append("}");
            return json.ToString();
        }

        private static string JsonEscape(string value)
        {
            return DiagnosticsService.JsonEscape(value);
        }

        private static void HandleRestartAfterSuccess(string message)
        {
            Console.WriteLine(message);

            if (options.RestartNever)
            {
                Console.WriteLine("Restart skipped because --no-restart was specified.");
                return;
            }

            if (options.RestartAlways)
            {
                RestartWindows();
                return;
            }

            if (AskYesNo("Restart Windows now?", false))
                RestartWindows();
            else
                Console.WriteLine("Restart postponed.");
        }

        private static int RestartWindows()
        {
            if (options.DryRun)
            {
                Console.WriteLine("DRY RUN: would schedule a Windows restart in 15 seconds.");
                return 0;
            }

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "shutdown.exe";
                psi.Arguments = "/r /t 15 /c \"Domain membership repair operation completed. Restarting Windows.\"";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Process.Start(psi);
                logger.Log("INFO", "Windows restart scheduled in 15 seconds. Use 'shutdown /a' to cancel.");
                return 0;
            }
            catch (Exception ex)
            {
                logger.Log("ERROR", "Unable to schedule restart: " + ex.Message);
                return 1;
            }
        }

        private static bool AskYesNo(string question, bool defaultYes)
        {
            Console.Write(question + (defaultYes ? " [Y/n]: " : " [y/N]: "));
            string answer = (Console.ReadLine() ?? String.Empty).Trim();
            if (answer.Length == 0)
                return defaultYes;
            return answer.Equals("y", StringComparison.OrdinalIgnoreCase) ||
                   answer.Equals("yes", StringComparison.OrdinalIgnoreCase);
        }

        private static string FirstNonEmpty(string first, string second)
        {
            return !String.IsNullOrWhiteSpace(first) ? first : (second ?? String.Empty);
        }

        private static string FormatDcSuffix(string dc)
        {
            return String.IsNullOrWhiteSpace(dc) ? String.Empty : " DC: " + dc;
        }
    }
}
