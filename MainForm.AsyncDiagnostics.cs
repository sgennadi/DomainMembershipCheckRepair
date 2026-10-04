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
        private bool diagnosticsClosing;

        // Read these properties on the UI thread, including inside queued callbacks.
        private bool IsDiagnosticUiAvailable
        {
            get { return !diagnosticsClosing && !IsDisposed && !Disposing && IsHandleCreated; }
        }

        private bool CanUpdateDiagnosticUi(CancellationTokenSource source)
        {
            return IsDiagnosticUiAvailable &&
                Object.ReferenceEquals(diagnosticsCancellation, source);
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            diagnosticsClosing = true;
            try
            {
                // Cancel before the existing handlers. A throwing cancellation
                // callback must not prevent closing or leak an async UI exception.
                TryCancelDiagnosticSource(diagnosticsCancellation);
                base.OnFormClosing(e);
            }
            finally
            {
                if (e.Cancel && !IsDisposed && !Disposing)
                    diagnosticsClosing = false;
            }
        }

        protected override void OnHandleDestroyed(EventArgs e)
        {
            if (!RecreatingHandle)
            {
                // Direct Dispose need not raise FormClosing. Handle recreation
                // is different: it must not permanently disable diagnostics.
                diagnosticsClosing = true;
                TryCancelDiagnosticSource(diagnosticsCancellation);
            }
            base.OnHandleDestroyed(e);
        }

        private void TryCancelDiagnosticSource(CancellationTokenSource source)
        {
            if (source == null)
                return;
            try
            {
                source.Cancel();
            }
            catch (ObjectDisposedException)
            {
                // The operation has already finished its cleanup.
            }
            catch (AggregateException ex)
            {
                // Cancel marks the token before invoking callbacks. Callback
                // failures do not undo cancellation or justify an automatic retry.
                if (IsDiagnosticUiAvailable)
                    Log("WARN", "A diagnostic cancellation callback failed: " + ex.Message);
            }
        }

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
            if (!IsDiagnosticUiAvailable)
                return;

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
            CancellationToken token = source.Token;
            diagnosticsCancellation = source;
            bool acceptingProgress = true;

            Action<string> progress = delegate(string text)
            {
                if (token.IsCancellationRequested)
                    return;
                try
                {
                    // Never fall back to touching controls on a worker thread.
                    // BeginInvoke may fail during teardown; delivery independently
                    // checks lifetime and operation identity on the UI thread.
                    BeginInvoke(new MethodInvoker(delegate
                    {
                        if (acceptingProgress && CanUpdateDiagnosticUi(source) &&
                            !token.IsCancellationRequested)
                            UpdateDiagnosticProgress(text);
                    }));
                }
                catch (InvalidOperationException)
                {
                    // Includes ObjectDisposedException when the UI is gone.
                }
            };

            try
            {
                // SetBusy currently pumps messages. Closing/cancelling during
                // that call must not start work or leave an undisposed source.
                SetBusy(true);
                token.ThrowIfCancellationRequested();
                if (!CanUpdateDiagnosticUi(source))
                    return;
                UpdateDiagnosticProgress(operationName + ": starting...");

                T result = await Task.Run(
                    delegate
                    {
                        token.ThrowIfCancellationRequested();
                        return work(token, progress);
                    },
                    token);

                acceptingProgress = false;
                token.ThrowIfCancellationRequested();
                if (!CanUpdateDiagnosticUi(source))
                    return;

                if (cancelDiagnosticsButton != null && !cancelDiagnosticsButton.IsDisposed)
                    cancelDiagnosticsButton.Enabled = false;
                UpdateDiagnosticProgress(operationName + ": completed.");

                if (completed != null)
                    completed(result);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                acceptingProgress = false;
                if (CanUpdateDiagnosticUi(source))
                {
                    UpdateDiagnosticProgress(operationName + ": cancelled.");
                    Log("INFO", operationName + " cancelled by the user.");
                }
            }
            catch (Exception ex)
            {
                acceptingProgress = false;
                if (CanUpdateDiagnosticUi(source))
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
            }
            finally
            {
                acceptingProgress = false;
                bool ownsOperation = Object.ReferenceEquals(diagnosticsCancellation, source);
                if (ownsOperation)
                    diagnosticsCancellation = null;

                try
                {
                    if (ownsOperation && IsDiagnosticUiAvailable)
                        SetBusy(false);
                }
                finally
                {
                    // Dispose only after the worker has returned, not on Cancel.
                    source.Dispose();
                }
            }
        }

        private void CancelDiagnosticOperation()
        {
            CancellationTokenSource source = diagnosticsCancellation;
            if (source == null || !CanUpdateDiagnosticUi(source) || source.IsCancellationRequested)
                return;

            UpdateDiagnosticProgress("Cancelling after the current API call...");
            if (cancelDiagnosticsButton != null && !cancelDiagnosticsButton.IsDisposed)
                cancelDiagnosticsButton.Enabled = false;

            TryCancelDiagnosticSource(source);
        }

        private void UpdateDiagnosticProgress(string text)
        {
            if (!IsDiagnosticUiAvailable || diagnosticsProgressLabel == null ||
                diagnosticsProgressLabel.IsDisposed)
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

                    if (!IsDiagnosticUiAvailable)
                        return;

                    DiagnosticsSnapshot post = DiagnosticsService.Capture(
                        inputs.Domain,
                        inputs.PreferredDc);

                    if (!IsDiagnosticUiAvailable)
                        return;

                    if (post.SecureChannelApplicable && !post.SecureChannelHealthy)
                    {
                        DialogResult repair = MessageBox.Show(
                            this,
                            "The secure channel is still broken after restart. Request elevation and attempt Repair Trust now?",
                            "Post-reboot recovery",
                            MessageBoxButtons.YesNo,
                            MessageBoxIcon.Warning);

                        if (repair == DialogResult.Yes && IsDiagnosticUiAvailable)
                            RepairTrustWorkflow();
                    }
                });
        }
    }
}
