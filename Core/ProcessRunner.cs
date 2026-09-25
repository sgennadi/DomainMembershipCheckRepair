using System;
using System.Diagnostics;
using System.Threading.Tasks;

namespace DomainMembershipCheckRepair
{
    internal sealed class CommandResult
    {
        internal bool Started;
        internal bool TimedOut;
        internal int ExitCode = -1;
        internal string StandardOutput = String.Empty;
        internal string StandardError = String.Empty;
        internal string Error = String.Empty;

        internal string CombinedOutput
        {
            get
            {
                if (String.IsNullOrWhiteSpace(StandardOutput))
                    return StandardError ?? String.Empty;
                if (String.IsNullOrWhiteSpace(StandardError))
                    return StandardOutput ?? String.Empty;
                return StandardOutput + Environment.NewLine + StandardError;
            }
        }
    }

    internal static class ProcessRunner
    {
        internal static CommandResult Run(string fileName, string arguments, int timeoutMs)
        {
            CommandResult result = new CommandResult();
            Process process = null;

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = fileName;
                psi.Arguments = arguments ?? String.Empty;
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.RedirectStandardError = true;
                psi.CreateNoWindow = true;

                process = new Process();
                process.StartInfo = psi;

                if (!process.Start())
                {
                    result.Error = "Process did not start.";
                    return result;
                }

                result.Started = true;

                Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
                Task<string> stderrTask = process.StandardError.ReadToEndAsync();

                int effectiveTimeout = timeoutMs <= 0 ? 30000 : timeoutMs;
                if (!process.WaitForExit(effectiveTimeout))
                {
                    result.TimedOut = true;
                    try { process.Kill(); } catch { }
                    try { process.WaitForExit(2000); } catch { }
                }

                try
                {
                    Task.WaitAll(new Task[] { stdoutTask, stderrTask }, 2000);
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

                if (!result.TimedOut && process.HasExited)
                    result.ExitCode = process.ExitCode;

                return result;
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                return result;
            }
            finally
            {
                if (process != null)
                    process.Dispose();
            }
        }
    }
}
