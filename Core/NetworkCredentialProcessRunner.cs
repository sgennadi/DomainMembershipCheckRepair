using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace DomainMembershipCheckRepair
{
    internal static class NetworkCredentialProcessRunner
    {
        private const int LOGON_NETCREDENTIALS_ONLY = 0x00000002;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint WAIT_OBJECT_0 = 0x00000000;
        private const uint WAIT_TIMEOUT = 0x00000102;
        private const uint INFINITE = 0xFFFFFFFF;

        internal static CommandResult Run(
            string fileName,
            string arguments,
            int timeoutMs,
            string user,
            string password)
        {
            if (String.IsNullOrWhiteSpace(user) || password == null)
                return ProcessRunner.Run(fileName, arguments, timeoutMs);

            CommandResult result = new CommandResult();
            string account;
            string domain;
            if (!TrySplitUser(user, out account, out domain))
            {
                result.Error = "The supplied DOMAIN\\username or username@domain value is not valid for network-only authentication.";
                return result;
            }

            string executable = ResolveExecutable(fileName);
            if (String.IsNullOrWhiteSpace(executable))
            {
                result.Error = "Executable was not found: " + (fileName ?? String.Empty);
                return result;
            }

            IntPtr stdoutRead = IntPtr.Zero;
            IntPtr stdoutWrite = IntPtr.Zero;
            IntPtr stderrRead = IntPtr.Zero;
            IntPtr stderrWrite = IntPtr.Zero;
            PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
            StreamReader stdoutReader = null;
            StreamReader stderrReader = null;

            try
            {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.bInheritHandle = true;

                if (!CreatePipe(out stdoutRead, out stdoutWrite, ref sa, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create stdout pipe.");

                if (!SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to protect stdout read handle.");

                if (!CreatePipe(out stderrRead, out stderrWrite, ref sa, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to create stderr pipe.");

                if (!SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to protect stderr read handle.");

                STARTUPINFO startup = new STARTUPINFO();
                startup.cb = Marshal.SizeOf(typeof(STARTUPINFO));
                startup.dwFlags = STARTF_USESTDHANDLES;
                startup.hStdOutput = stdoutWrite;
                startup.hStdError = stderrWrite;
                startup.hStdInput = IntPtr.Zero;

                StringBuilder commandLine = new StringBuilder();
                commandLine.Append(Quote(executable));
                if (!String.IsNullOrWhiteSpace(arguments))
                {
                    commandLine.Append(' ');
                    commandLine.Append(arguments);
                }

                bool started = CreateProcessWithLogonW(
                    account,
                    String.IsNullOrWhiteSpace(domain) ? null : domain,
                    password,
                    LOGON_NETCREDENTIALS_ONLY,
                    executable,
                    commandLine,
                    CREATE_NO_WINDOW,
                    IntPtr.Zero,
                    Path.GetDirectoryName(executable),
                    ref startup,
                    out processInfo);

                if (!started)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.Error = error + " - " + new Win32Exception(error).Message;
                    return result;
                }

                result.Started = true;

                CloseHandleSafe(ref stdoutWrite);
                CloseHandleSafe(ref stderrWrite);

                stdoutReader = CreateReader(stdoutRead);
                stderrReader = CreateReader(stderrRead);
                stdoutRead = IntPtr.Zero;
                stderrRead = IntPtr.Zero;

                Task<string> stdoutTask = stdoutReader.ReadToEndAsync();
                Task<string> stderrTask = stderrReader.ReadToEndAsync();

                int effectiveTimeout = timeoutMs <= 0 ? 30000 : timeoutMs;
                uint wait = WaitForSingleObject(processInfo.hProcess, (uint)effectiveTimeout);

                if (wait == WAIT_TIMEOUT)
                {
                    result.TimedOut = true;
                    try { TerminateProcess(processInfo.hProcess, 1460); } catch { }
                    WaitForSingleObject(processInfo.hProcess, 2000);
                }
                else if (wait != WAIT_OBJECT_0)
                {
                    int error = Marshal.GetLastWin32Error();
                    result.Error = error + " - " + new Win32Exception(error).Message;
                }

                try
                {
                    Task.WaitAll(new Task[] { stdoutTask, stderrTask }, 3000);
                }
                catch
                {
                }

                if (stdoutTask.IsCompleted)
                {
                    try { result.StandardOutput = stdoutTask.Result ?? String.Empty; } catch { }
                }

                if (stderrTask.IsCompleted)
                {
                    try { result.StandardError = stderrTask.Result ?? String.Empty; } catch { }
                }

                if (!result.TimedOut && processInfo.hProcess != IntPtr.Zero)
                {
                    uint exitCode;
                    if (GetExitCodeProcess(processInfo.hProcess, out exitCode))
                        result.ExitCode = unchecked((int)exitCode);
                }

                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                return result;
            }
            finally
            {
                if (stdoutReader != null) stdoutReader.Dispose();
                if (stderrReader != null) stderrReader.Dispose();
                CloseHandleSafe(ref stdoutRead);
                CloseHandleSafe(ref stdoutWrite);
                CloseHandleSafe(ref stderrRead);
                CloseHandleSafe(ref stderrWrite);
                CloseHandleSafe(ref processInfo.hThread);
                CloseHandleSafe(ref processInfo.hProcess);
            }
        }

        internal static bool TrySplitUser(string value, out string user, out string domain)
        {
            user = String.Empty;
            domain = null;

            if (String.IsNullOrWhiteSpace(value))
                return false;

            string normalized = value.Trim();
            int slash = normalized.IndexOf('\\');
            if (slash > 0 && slash < normalized.Length - 1)
            {
                domain = normalized.Substring(0, slash).Trim();
                user = normalized.Substring(slash + 1).Trim();
                return domain.Length > 0 && user.Length > 0;
            }

            int at = normalized.LastIndexOf('@');
            if (at > 0 && at < normalized.Length - 1)
            {
                user = normalized;
                domain = null;
                return true;
            }

            return false;
        }

        private static string ResolveExecutable(string fileName)
        {
            if (String.IsNullOrWhiteSpace(fileName))
                return String.Empty;

            string value = fileName.Trim().Trim('"');
            if (Path.IsPathRooted(value))
                return File.Exists(value) ? value : String.Empty;

            string systemPath = Path.Combine(Environment.SystemDirectory, value);
            if (File.Exists(systemPath))
                return systemPath;

            string current = Path.GetFullPath(value);
            return File.Exists(current) ? current : String.Empty;
        }

        private static StreamReader CreateReader(IntPtr handle)
        {
            SafeFileHandle safe = new SafeFileHandle(handle, true);
            FileStream stream = new FileStream(safe, FileAccess.Read, 4096, false);
            return new StreamReader(stream, Encoding.Default, true);
        }

        private static string Quote(string value)
        {
            return "\"" + (value ?? String.Empty).Replace("\"", "\\\"") + "\"";
        }

        private static void CloseHandleSafe(ref IntPtr handle)
        {
            if (handle == IntPtr.Zero || handle == new IntPtr(-1))
                return;

            try { CloseHandle(handle); } catch { }
            handle = IntPtr.Zero;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES
        {
            internal int nLength;
            internal IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)]
            internal bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO
        {
            internal int cb;
            internal string lpReserved;
            internal string lpDesktop;
            internal string lpTitle;
            internal int dwX;
            internal int dwY;
            internal int dwXSize;
            internal int dwYSize;
            internal int dwXCountChars;
            internal int dwYCountChars;
            internal int dwFillAttribute;
            internal uint dwFlags;
            internal short wShowWindow;
            internal short cbReserved2;
            internal IntPtr lpReserved2;
            internal IntPtr hStdInput;
            internal IntPtr hStdOutput;
            internal IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION
        {
            internal IntPtr hProcess;
            internal IntPtr hThread;
            internal uint dwProcessId;
            internal uint dwThreadId;
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreateProcessWithLogonW(
            string lpUsername,
            string lpDomain,
            string lpPassword,
            int dwLogonFlags,
            string lpApplicationName,
            StringBuilder lpCommandLine,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CreatePipe(
            out IntPtr hReadPipe,
            out IntPtr hWritePipe,
            ref SECURITY_ATTRIBUTES lpPipeAttributes,
            uint nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetHandleInformation(
            IntPtr hObject,
            uint dwMask,
            uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);
    }
}
