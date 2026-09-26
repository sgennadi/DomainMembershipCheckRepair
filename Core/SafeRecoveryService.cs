using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal sealed class SafeRecoveryResult
    {
        internal readonly List<string> Steps = new List<string>();
        internal bool Success = true;
    }

    internal static class SafeRecoveryService
    {
        internal static SafeRecoveryResult Run(string domain)
        {
            return Run(domain, null);
        }

        internal static SafeRecoveryResult Run(string domain, TransactionJournal journal)
        {
            SafeRecoveryResult result = new SafeRecoveryResult();

            RunCommand(result, "Flush DNS resolver cache", "ipconfig.exe", "/flushdns", 10000);
            TransactionJournalService.RecordNote(journal, "DNS resolver cache", "Flush DNS cache executed; no meaningful rollback exists.");

            RunCommand(result, "Request Windows Time resync", "w32tm.exe", "/resync /force", 15000);
            TransactionJournalService.RecordNote(journal, "Windows Time", "Time resync requested; no automatic rollback is performed.");

            RestartService(result, "Netlogon", 15000, journal);

            if (!String.IsNullOrWhiteSpace(domain))
            {
                RunCommand(result, "Force DC locator rediscovery", "nltest.exe", "/dsgetdc:" + domain + " /force", 15000);
                TransactionJournalService.RecordNote(journal, "DC Locator", "Forced DC rediscovery executed; no rollback is required.");
            }

            return result;
        }

        internal static string ToText(SafeRecoveryResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Safe Recovery Actions");
            sb.AppendLine("=====================");
            sb.AppendLine("Overall: " + (result.Success ? "Completed" : "Completed with one or more failures"));
            sb.AppendLine();
            foreach (string step in result.Steps)
                sb.AppendLine(step);
            sb.AppendLine();
            sb.AppendLine("No AD computer object was deleted, no computer rename was performed, and no domain join/rejoin was attempted.");
            return sb.ToString();
        }

        private static void RestartService(
            SafeRecoveryResult result,
            string serviceName,
            int timeoutMs,
            TransactionJournal journal)
        {
            try
            {
                using (ServiceController service = new ServiceController(serviceName))
                {
                    ServiceControllerStatus before = service.Status;
                    TimeSpan timeout = TimeSpan.FromMilliseconds(timeoutMs);
                    if (service.Status != ServiceControllerStatus.Stopped &&
                        service.Status != ServiceControllerStatus.StopPending)
                    {
                        service.Stop();
                        service.WaitForStatus(ServiceControllerStatus.Stopped, timeout);
                    }

                    service.Start();
                    service.WaitForStatus(ServiceControllerStatus.Running, timeout);
                    service.Refresh();
                    TransactionJournalService.RecordServiceChange(journal, serviceName, before, service.Status);
                    result.Steps.Add("OK: Restart " + serviceName + " service.");
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Steps.Add("FAIL: Restart " + serviceName + " service: " + ex.Message);
            }
        }

        private static void RunCommand(
            SafeRecoveryResult result,
            string title,
            string fileName,
            string arguments,
            int timeoutMs)
        {
            CommandResult command = ProcessRunner.Run(fileName, arguments, timeoutMs);

            if (!String.IsNullOrWhiteSpace(command.Error))
            {
                result.Success = false;
                result.Steps.Add("FAIL: " + title + ": " + command.Error);
                return;
            }

            if (command.TimedOut)
            {
                result.Success = false;
                result.Steps.Add("FAIL: " + title + ": timed out.");
                return;
            }

            string detail = Collapse(command.CombinedOutput, 240);
            if (command.ExitCode == 0)
            {
                result.Steps.Add("OK: " + title + (detail.Length > 0 ? " - " + detail : String.Empty));
                return;
            }

            result.Success = false;
            result.Steps.Add("FAIL: " + title + " (exit " + command.ExitCode + ")" +
                (detail.Length > 0 ? " - " + detail : String.Empty));
        }

        private static string Collapse(string value, int max)
        {
            string text = (value ?? String.Empty).Replace("\r", " ").Replace("\n", " ").Trim();
            while (text.Contains("  "))
                text = text.Replace("  ", " ");
            if (text.Length > max)
                text = text.Substring(0, max) + "...";
            return text;
        }
    }
}
