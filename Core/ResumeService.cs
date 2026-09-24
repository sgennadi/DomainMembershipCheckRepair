using System;
using System.Diagnostics;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal static class ResumeService
    {
        private const string RunOncePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce";
        private const string ValueName = "DomainMembershipCheckRepairResume";

        internal static bool RegisterPostRebootCheck(string domain, out string error)
        {
            error = String.Empty;
            try
            {
                string exe = Process.GetCurrentProcess().MainModule.FileName;
                string args = "--resume-action post-reboot-check --no-log";
                if (!String.IsNullOrWhiteSpace(domain))
                    args += " --domain " + Quote(domain);

                string command = Quote(exe) + " " + args;
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(RunOncePath, true))
                {
                    if (key == null)
                    {
                        error = "Unable to open HKLM RunOnce for writing.";
                        return false;
                    }
                    key.SetValue(ValueName, command, RegistryValueKind.String);
                }
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        internal static void Clear()
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(RunOncePath, true))
                    if (key != null) key.DeleteValue(ValueName, false);
            }
            catch { }
        }

        private static string Quote(string value)
        {
            return "\"" + (value ?? String.Empty).Replace("\"", "\\\"") + "\"";
        }
    }
}
