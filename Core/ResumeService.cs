using System;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Security.Principal;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal static class ResumeService
    {
        private const string RunOnceSubPath = @"Software\Microsoft\Windows\CurrentVersion\RunOnce";
        private const string ValueName = "DomainMembershipCheckRepairResume";

        internal static bool RegisterPostRebootCheck(string domain, out string error)
        {
            error = String.Empty;

            try
            {
                string exe = Process.GetCurrentProcess().MainModule.FileName;
                string command = BuildRunOnceCommand(exe, domain);
                string detectedInteractiveSid = GetInteractiveUserSid();
                string currentProcessSid = GetCurrentProcessSid();
                string interactiveSid =
                    SelectPostRebootTargetSid(
                        detectedInteractiveSid,
                        currentProcessSid);

                if (String.IsNullOrWhiteSpace(interactiveSid))
                {
                    error =
                        "No interactive user SID could be identified safely. " +
                        "The post-reboot RunOnce entry was not redirected to the current/elevated process identity.";
                    return false;
                }

                if (TryWriteUserRunOnce(interactiveSid, command))
                    return true;

                error =
                    "Unable to register the one-time post-reboot check in the interactive user's RunOnce key. " +
                    "Registration was not redirected to the elevated/current account.";
                return false;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        internal static void Clear()
        {
            string interactiveSid = GetInteractiveUserSid();
            if (!String.IsNullOrWhiteSpace(interactiveSid))
                TryDeleteUserRunOnce(interactiveSid);

            string currentProcessSid = GetCurrentProcessSid();
            if (!String.IsNullOrWhiteSpace(currentProcessSid) &&
                !String.Equals(
                    currentProcessSid,
                    interactiveSid,
                    StringComparison.OrdinalIgnoreCase))
            {
                TryDeleteUserRunOnce(currentProcessSid);
            }

            try
            {
                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunOnceSubPath, true))
                {
                    if (key != null)
                        key.DeleteValue(ValueName, false);
                }
            }
            catch
            {
            }
        }

        internal static string GetInteractiveUserSid()
        {
            try
            {
                using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
                    "SELECT UserName FROM Win32_ComputerSystem"))
                using (ManagementObjectCollection results = searcher.Get())
                {
                    foreach (ManagementObject item in results)
                    {
                        string userName = Convert.ToString(item["UserName"]);
                        if (String.IsNullOrWhiteSpace(userName))
                            continue;

                        IdentityReference account = new NTAccount(userName);
                        SecurityIdentifier sid = account.Translate(typeof(SecurityIdentifier)) as SecurityIdentifier;
                        if (sid != null)
                            return sid.Value;
                    }
                }
            }
            catch
            {
            }

            return String.Empty;
        }

        internal static string SelectPostRebootTargetSid(
            string detectedInteractiveSid,
            string currentProcessSid)
        {
            string interactive =
                (detectedInteractiveSid ?? String.Empty).Trim();

            if (!String.IsNullOrWhiteSpace(interactive))
                return interactive;

            // Deliberately do not fall back to currentProcessSid here.
            // Recovery registration often runs after runas/CyberArk elevation,
            // where the current process can belong to a different administrator
            // identity than the desktop user who must receive the RunOnce entry.
            return String.Empty;
        }

        private static string GetCurrentProcessSid()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    if (identity != null && identity.User != null)
                        return identity.User.Value;
                }
            }
            catch
            {
            }

            return String.Empty;
        }

        private static bool TryWriteUserRunOnce(string sid, string command)
        {
            try
            {
                using (RegistryKey key = Registry.Users.OpenSubKey(
                    sid + @"\" + RunOnceSubPath,
                    true))
                {
                    if (key == null)
                        return false;

                    key.SetValue(ValueName, command, RegistryValueKind.String);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private static void TryDeleteUserRunOnce(string sid)
        {
            try
            {
                using (RegistryKey key = Registry.Users.OpenSubKey(
                    sid + @"\" + RunOnceSubPath,
                    true))
                {
                    if (key != null)
                        key.DeleteValue(ValueName, false);
                }
            }
            catch
            {
            }
        }

        internal static string BuildRunOnceCommand(string executablePath, string domain)
        {
            string exe = (executablePath ?? String.Empty).Trim();
            if (String.IsNullOrWhiteSpace(exe) ||
                !Path.IsPathRooted(exe) ||
                exe.IndexOf('"') >= 0 ||
                exe.IndexOf('\0') >= 0)
            {
                throw new ArgumentException(
                    "Post-reboot resume requires a trusted absolute executable path.",
                    "executablePath");
            }

            string normalizedDomain = (domain ?? String.Empty).Trim();
            if (!String.IsNullOrWhiteSpace(normalizedDomain))
            {
                string validationError = DomainValidation.ValidateDomainArgument(normalizedDomain);
                if (!String.IsNullOrWhiteSpace(validationError))
                {
                    throw new ArgumentException(
                        "Unsafe domain for post-reboot resume: " + validationError,
                        "domain");
                }

                return WindowsCommandLine.BuildArguments(
                    new string[]
                    {
                        exe,
                        "--resume-action",
                        "post-reboot-check",
                        "--no-log",
                        "--domain",
                        normalizedDomain
                    });
            }

            return WindowsCommandLine.BuildArguments(
                new string[]
                {
                    exe,
                    "--resume-action",
                    "post-reboot-check",
                    "--no-log"
                });
        }
    }
}
