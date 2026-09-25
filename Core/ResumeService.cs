using System;
using System.Diagnostics;
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
                string args = "--resume-action post-reboot-check --no-log";

                if (!String.IsNullOrWhiteSpace(domain))
                    args += " --domain " + QuoteArgument(domain);

                string command = QuoteArgument(exe) + " " + args;
                string interactiveSid = GetInteractiveUserSid();

                if (!String.IsNullOrWhiteSpace(interactiveSid) &&
                    TryWriteUserRunOnce(interactiveSid, command))
                {
                    return true;
                }

                using (RegistryKey key = Registry.CurrentUser.OpenSubKey(RunOnceSubPath, true))
                {
                    if (key != null)
                    {
                        key.SetValue(ValueName, command, RegistryValueKind.String);
                        return true;
                    }
                }

                error =
                    "Unable to register the one-time post-reboot check for the interactive user. " +
                    "The repair itself can still continue, but the tool will not reopen automatically after restart.";
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

        private static string QuoteArgument(string value)
        {
            string input = value ?? String.Empty;
            if (input.Length == 0)
                return "\"\"";

            bool needsQuotes = input.IndexOfAny(new char[] { ' ', '\t', '"' }) >= 0;
            if (!needsQuotes)
                return input;

            System.Text.StringBuilder result = new System.Text.StringBuilder();
            result.Append('"');
            int slashes = 0;

            foreach (char c in input)
            {
                if (c == '\\')
                {
                    slashes++;
                    continue;
                }

                if (c == '"')
                {
                    result.Append('\\', slashes * 2 + 1);
                    result.Append('"');
                    slashes = 0;
                    continue;
                }

                if (slashes > 0)
                {
                    result.Append('\\', slashes);
                    slashes = 0;
                }

                result.Append(c);
            }

            if (slashes > 0)
                result.Append('\\', slashes * 2);

            result.Append('"');
            return result.ToString();
        }
    }
}
