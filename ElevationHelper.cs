using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal sealed class GuiResumeOptions
    {
        internal string Action = String.Empty;
        internal string Domain = String.Empty;
        internal string User = String.Empty;
        internal string PreferredDc = String.Empty;
        internal bool ElevationAttempted;
    }

    internal static class ElevationHelper
    {
        internal const int ElevationFailureExitCode = 13;
        private const int ErrorCancelled = 1223;
        private const int BcmSetShield = 0x160C;

        internal static bool IsAdministrator()
        {
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    if (identity == null)
                        return false;
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch
            {
                return false;
            }
        }

        internal static bool RequiresElevation(string action)
        {
            string value = (action ?? String.Empty).Trim().ToLowerInvariant();
            return value == "repair" || value == "join" || value == "rename" || value == "restart";
        }

        internal static GuiResumeOptions ParseGuiResumeOptions(string[] args)
        {
            GuiResumeOptions result = new GuiResumeOptions();
            if (args == null)
                return result;

            for (int i = 0; i < args.Length; i++)
            {
                string arg = (args[i] ?? String.Empty).Trim();
                if (arg.Equals("--elevation-attempted", StringComparison.OrdinalIgnoreCase))
                {
                    result.ElevationAttempted = true;
                    continue;
                }

                if (arg.Equals("--resume-action", StringComparison.OrdinalIgnoreCase))
                    result.Action = ReadNext(args, ref i);
                else if (arg.Equals("--domain", StringComparison.OrdinalIgnoreCase))
                    result.Domain = ReadNext(args, ref i);
                else if (arg.Equals("--user", StringComparison.OrdinalIgnoreCase))
                    result.User = ReadNext(args, ref i);
                else if (arg.Equals("--dc", StringComparison.OrdinalIgnoreCase))
                    result.PreferredDc = DomainValidation.NormalizeDirectoryServer(ReadNext(args, ref i));
            }

            result.Action = (result.Action ?? String.Empty).Trim().ToLowerInvariant();
            if (result.Action != "repair" && result.Action != "join" && result.Action != "restart")
                result.Action = String.Empty;

            return result;
        }

        internal static bool TryStartElevated(string[] args, bool waitForExit, out int exitCode, out string error)
        {
            exitCode = ElevationFailureExitCode;
            error = String.Empty;

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = Application.ExecutablePath;
                psi.Arguments = BuildArgumentString(args);
                psi.WorkingDirectory = AppDomain.CurrentDomain.BaseDirectory;
                psi.Verb = "runas";
                psi.UseShellExecute = true;

                Process process = Process.Start(psi);
                if (process == null)
                {
                    error = "Windows did not start the elevated process.";
                    return false;
                }

                if (waitForExit)
                {
                    process.WaitForExit();
                    exitCode = process.ExitCode;
                }
                else
                {
                    exitCode = 0;
                }

                return true;
            }
            catch (Win32Exception ex)
            {
                error = ex.NativeErrorCode == ErrorCancelled
                    ? "The elevation request was cancelled by the user or privilege broker."
                    : "Windows could not start the elevated process: " + ex.Message;
                return false;
            }
            catch (Exception ex)
            {
                error = "Unable to request administrator privileges: " + ex.Message;
                return false;
            }
        }

        internal static void SetElevationShield(Button button, bool required)
        {
            if (button == null)
                return;
            try
            {
                button.FlatStyle = FlatStyle.System;
                SendMessage(button.Handle, BcmSetShield, IntPtr.Zero, new IntPtr(required ? 1 : 0));
            }
            catch
            {
            }
        }

        private static string ReadNext(string[] args, ref int index)
        {
            if (index + 1 >= args.Length)
                return String.Empty;
            index++;
            return (args[index] ?? String.Empty).Trim();
        }

        private static string BuildArgumentString(IEnumerable<string> args)
        {
            StringBuilder builder = new StringBuilder();
            if (args != null)
            {
                foreach (string arg in args)
                {
                    if (builder.Length > 0)
                        builder.Append(' ');
                    builder.Append(QuoteArgument(arg ?? String.Empty));
                }
            }
            return builder.ToString();
        }

        private static string QuoteArgument(string value)
        {
            if (value.Length == 0)
                return """";

            bool needsQuotes = value.IndexOfAny(new char[] { ' ', '\t', '"' }) >= 0;
            if (!needsQuotes)
                return value;

            StringBuilder result = new StringBuilder();
            result.Append('"');
            int slashes = 0;

            foreach (char c in value)
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

        [DllImport("user32.dll", CharSet = CharSet.Auto)]
        private static extern IntPtr SendMessage(IntPtr hWnd, int msg, IntPtr wParam, IntPtr lParam);
    }
}
