using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal sealed partial class MainForm
    {
        private sealed class DiagnosticInputs
        {
            internal string Domain = String.Empty;
            internal string PreferredDc = String.Empty;
            internal string User = String.Empty;
            internal string Password;
            internal string ComputerName = String.Empty;
        }

        private Button cancelDiagnosticsButton;
        private Label diagnosticsProgressLabel;
        private CancellationTokenSource diagnosticsCancellation;

        private DiagnosticInputs CaptureDiagnosticInputs()
        {
            DiagnosticInputs inputs = new DiagnosticInputs();
            inputs.Domain = domainBox == null ? String.Empty : (domainBox.Text ?? String.Empty).Trim();
            inputs.PreferredDc = dcBox == null ? String.Empty : (dcBox.Text ?? String.Empty).Trim();
            inputs.User = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
            inputs.Password = passwordBox == null ? null : passwordBox.Text;
            inputs.ComputerName = Environment.MachineName;

            if (String.IsNullOrWhiteSpace(inputs.User) || String.IsNullOrEmpty(inputs.Password))
            {
                inputs.User = String.Empty;
                inputs.Password = null;
            }

            return inputs;
        }

        private async void RunBackgroundDiagnostic<T>(
            string operationName,
            Func<CancellationToken, Action<string>, T> work,
            Action<T> completed)
        {
            if (diagnosticsCancellation != null)
            {
                MessageBox.Show(
                    this,
                    "Another diagnostic operation is already running.",
                    "Diagnostics busy",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            CancellationTokenSource source = new CancellationTokenSource();
            diagnosticsCancellation = source;
            SetBusy(true);
            UpdateDiagnosticProgress(operationName + ": starting...");

            Action<string> progress = delegate(string text)
            {
                if (IsDisposed || Disposing)
                    return;

                try
                {
                    if (InvokeRequired)
                    {
                        BeginInvoke(new Action<string>(UpdateDiagnosticProgress), text);
                    }
                    else
                    {
                        UpdateDiagnosticProgress(text);
                    }
                }
                catch
                {
                }
            };

            try
            {
                T result = await Task.Run(
                    delegate
                    {
                        source.Token.ThrowIfCancellationRequested();
                        return work(source.Token, progress);
                    },
                    source.Token);

                source.Token.ThrowIfCancellationRequested();
                UpdateDiagnosticProgress(operationName + ": completed.");

                if (completed != null)
                    completed(result);
            }
            catch (OperationCanceledException)
            {
                UpdateDiagnosticProgress(operationName + ": cancelled.");
                Log("INFO", operationName + " cancelled by the user.");
            }
            catch (Exception ex)
            {
                UpdateDiagnosticProgress(operationName + ": failed.");
                Log("ERROR", operationName + " failed: " + ex.Message);
                MessageBox.Show(
                    this,
                    ex.Message,
                    operationName + " failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            finally
            {
                if (Object.ReferenceEquals(diagnosticsCancellation, source))
                    diagnosticsCancellation = null;

                source.Dispose();
                SetBusy(false);
            }
        }

        private void CancelDiagnosticOperation()
        {
            CancellationTokenSource source = diagnosticsCancellation;
            if (source == null || source.IsCancellationRequested)
                return;

            UpdateDiagnosticProgress("Cancelling after the current API call...");
            if (cancelDiagnosticsButton != null)
                cancelDiagnosticsButton.Enabled = false;

            source.Cancel();
        }

        private void UpdateDiagnosticProgress(string text)
        {
            if (diagnosticsProgressLabel == null)
                return;

            diagnosticsProgressLabel.Text = String.IsNullOrWhiteSpace(text)
                ? "Diagnostics: Idle"
                : text;
        }

        private void RunPostRebootDiagnosticsWorkflow()
        {
            DiagnosticInputs inputs = CaptureDiagnosticInputs();

            RunBackgroundDiagnostic(
                "Post-reboot diagnostics",
                delegate(CancellationToken token, Action<string> progress)
                {
                    return AdvancedDiagnosticsService.Analyze(
                        inputs.Domain,
                        inputs.PreferredDc,
                        inputs.ComputerName,
                        inputs.User,
                        inputs.Password,
                        token,
                        progress);
                },
                delegate(AdvancedDiagnosticsResult result)
                {
                    lastDiagnosticsSnapshot = result.Snapshot;
                    ReportDialog.ShowReport(
                        this,
                        "Post-reboot Advanced Diagnostics",
                        AdvancedDiagnosticsService.ToText(result));

                    DiagnosticsSnapshot post = DiagnosticsService.Capture(
                        inputs.Domain,
                        inputs.PreferredDc);

                    if (post.SecureChannelApplicable && !post.SecureChannelHealthy)
                    {
                        DialogResult repair = MessageBox.Show(
                            this,
                            "The secure channel is still broken after restart. Request elevation and attempt Repair Trust now?",
                            "Post-reboot recovery",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Warning);

                        if (repair == DialogResult.Yes)
                            RepairTrustWorkflow();
                    }
                });
        }
    }
}
