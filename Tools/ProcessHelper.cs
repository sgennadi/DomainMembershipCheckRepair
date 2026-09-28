using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Threading.Tasks;

namespace DomainMembershipCheckRepair.Tools
{
    internal sealed class ProcessResult
    {
        internal int ExitCode;
        internal string StandardOutput;
        internal string StandardError;
        internal bool TimedOut;
    }

    internal static class ProcessHelper
    {
        internal static ProcessResult Run(
            string fileName,
            IEnumerable<string> arguments,
            IEnumerable<string> inputLines,
            int timeoutMilliseconds)
        {
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = fileName;
            start.Arguments = JoinArguments(arguments);
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            start.RedirectStandardInput = true;

            using (Process process = new Process())
            {
                process.StartInfo = start;
                if (!process.Start())
                    throw new InvalidOperationException("Unable to start process: " + fileName);

                if (inputLines != null)
                {
                    foreach (string line in inputLines)
                        process.StandardInput.WriteLine(line ?? String.Empty);
                }
                process.StandardInput.Close();

                Task<string> stdout = process.StandardOutput.ReadToEndAsync();
                Task<string> stderr = process.StandardError.ReadToEndAsync();

                bool exited = process.WaitForExit(timeoutMilliseconds);
                if (!exited)
                {
                    try
                    {
                        process.Kill();
                    }
                    catch
                    {
                    }

                    return new ProcessResult
                    {
                        ExitCode = -1,
                        StandardOutput = SafeTaskResult(stdout),
                        StandardError = SafeTaskResult(stderr),
                        TimedOut = true
                    };
                }

                Task.WaitAll(new Task[] { stdout, stderr }, 10000);

                return new ProcessResult
                {
                    ExitCode = process.ExitCode,
                    StandardOutput = SafeTaskResult(stdout),
                    StandardError = SafeTaskResult(stderr),
                    TimedOut = false
                };
            }
        }

        internal static ProcessResult Run(
            string fileName,
            IEnumerable<string> arguments,
            int timeoutMilliseconds)
        {
            return Run(fileName, arguments, null, timeoutMilliseconds);
        }

        internal static string JoinArguments(IEnumerable<string> arguments)
        {
            if (arguments == null)
                return String.Empty;

            StringBuilder output = new StringBuilder();
            foreach (string argument in arguments)
            {
                if (output.Length > 0)
                    output.Append(' ');
                output.Append(QuoteWindowsArgument(argument ?? String.Empty));
            }

            return output.ToString();
        }

        private static string QuoteWindowsArgument(string value)
        {
            if (value.Length > 0 &&
                value.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0)
                return value;

            StringBuilder output = new StringBuilder();
            output.Append('"');

            int backslashes = 0;
            foreach (char ch in value)
            {
                if (ch == '\\')
                {
                    backslashes++;
                    continue;
                }

                if (ch == '"')
                {
                    output.Append('\\', backslashes * 2 + 1);
                    output.Append('"');
                    backslashes = 0;
                    continue;
                }

                if (backslashes > 0)
                {
                    output.Append('\\', backslashes);
                    backslashes = 0;
                }

                output.Append(ch);
            }

            if (backslashes > 0)
                output.Append('\\', backslashes * 2);

            output.Append('"');
            return output.ToString();
        }

        private static string SafeTaskResult(Task<string> task)
        {
            if (task == null || !task.IsCompleted || task.IsFaulted || task.IsCanceled)
                return String.Empty;

            return task.Result ?? String.Empty;
        }
    }
}
