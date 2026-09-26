using System;
using System.Drawing;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal sealed partial class MainForm
    {
        private enum UiStatusKind
        {
            Neutral,
            Info,
            Success,
            Warning,
            Error
        }

        private Button copyDiagnosticsButton;
        private Label domainStatusBadge;
        private Label trustStatusBadge;
        private Label dcStatusBadge;
        private Label adStatusBadge;
        private Label footerLabel;
        private DiagnosticsSnapshot lastDiagnosticsSnapshot;

        private void ApplyWindowPolish()
        {
            Icon = SystemIcons.Shield;
            ShowIcon = true;
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
        }

        private Control CreateStatusFooterPanel()
        {
            FlowLayoutPanel panel = new FlowLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.AutoSize = true;
            panel.WrapContents = true;
            panel.FlowDirection = FlowDirection.LeftToRight;
            panel.Margin = new Padding(0, 3, 0, 0);
            panel.Padding = new Padding(0);
            panel.BackColor = SystemColors.ControlLightLight;

            domainStatusBadge = CreateStatusBadge("Domain: Checking...");
            trustStatusBadge = CreateStatusBadge("Trust: Checking...");
            dcStatusBadge = CreateStatusBadge("DC: Auto");
            adStatusBadge = CreateStatusBadge("AD: Not checked");

            footerLabel = new Label();
            footerLabel.AutoSize = true;
            footerLabel.AutoEllipsis = true;
            footerLabel.ForeColor = SystemColors.GrayText;
            footerLabel.Font = new Font("Segoe UI", 8.25F);
            footerLabel.Margin = new Padding(10, 7, 2, 1);
            footerLabel.Text = BuildFooterText();

            panel.Controls.Add(domainStatusBadge);
            panel.Controls.Add(trustStatusBadge);
            panel.Controls.Add(dcStatusBadge);
            panel.Controls.Add(adStatusBadge);
            panel.Controls.Add(footerLabel);

            SetStatusBadge(domainStatusBadge, "Domain", "Checking...", UiStatusKind.Info);
            SetStatusBadge(trustStatusBadge, "Trust", "Checking...", UiStatusKind.Info);
            SetStatusBadge(dcStatusBadge, "DC", "Auto", UiStatusKind.Neutral);
            SetStatusBadge(adStatusBadge, "AD", "Not checked", UiStatusKind.Neutral);

            return panel;
        }

        private static Label CreateStatusBadge(string text)
        {
            Label label = new Label();
            label.AutoSize = true;
            label.AutoEllipsis = true;
            label.TextAlign = ContentAlignment.MiddleLeft;
            label.Font = new Font("Segoe UI", 8.25F, FontStyle.Bold);
            label.Margin = new Padding(1);
            label.Padding = new Padding(6, 5, 6, 5);
            label.Text = text;
            return label;
        }

        private static void SetStatusBadge(Label label, string name, string value, UiStatusKind kind)
        {
            if (label == null)
                return;

            label.Text = name + ": " + value;

            switch (kind)
            {
                case UiStatusKind.Success:
                    label.ForeColor = Color.FromArgb(24, 94, 42);
                    label.BackColor = Color.FromArgb(226, 242, 230);
                    break;
                case UiStatusKind.Warning:
                    label.ForeColor = Color.FromArgb(120, 78, 0);
                    label.BackColor = Color.FromArgb(255, 244, 204);
                    break;
                case UiStatusKind.Error:
                    label.ForeColor = Color.FromArgb(151, 22, 22);
                    label.BackColor = Color.FromArgb(252, 228, 228);
                    break;
                case UiStatusKind.Info:
                    label.ForeColor = Color.FromArgb(25, 72, 120);
                    label.BackColor = Color.FromArgb(228, 239, 250);
                    break;
                default:
                    label.ForeColor = SystemColors.GrayText;
                    label.BackColor = SystemColors.ControlLight;
                    break;
            }
        }

        private string BuildFooterText()
        {
            return "v" + BuildInfo.Version + "  |  " + BuildInfo.TargetArchitecture +
                   "  |  " + (Environment.Is64BitProcess ? "64-bit" : "32-bit") +
                   "  |  " + (ElevationHelper.IsAdministrator() ? "Elevated" : "Standard");
        }

        private void RefreshStatusCards()
        {
            if (domainStatusBadge == null)
                return;

            try
            {
                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text);
                lastDiagnosticsSnapshot = snapshot;

                if (snapshot.MembershipApiStatus != NativeMethods.NERR_Success)
                {
                    SetStatusBadge(domainStatusBadge, "Domain", "Unknown", UiStatusKind.Error);
                    SetStatusBadge(trustStatusBadge, "Trust", "Unknown", UiStatusKind.Error);
                }
                else if (snapshot.JoinStatus == NetJoinStatus.NetSetupDomainName && !String.IsNullOrWhiteSpace(snapshot.JoinedDomain))
                {
                    SetStatusBadge(domainStatusBadge, "Domain", "Joined", UiStatusKind.Success);
                    SetStatusBadge(
                        trustStatusBadge,
                        "Trust",
                        snapshot.SecureChannelHealthy ? "Healthy" : "Broken",
                        snapshot.SecureChannelHealthy ? UiStatusKind.Success : UiStatusKind.Error);
                }
                else
                {
                    SetStatusBadge(domainStatusBadge, "Domain", "Not joined", UiStatusKind.Warning);
                    SetStatusBadge(trustStatusBadge, "Trust", "N/A", UiStatusKind.Neutral);
                }

                if (snapshot.DiscoverySucceeded)
                {
                    string dc = String.IsNullOrWhiteSpace(snapshot.DiscoveredDc) ? "Available" : snapshot.DiscoveredDc.TrimStart('\\');
                    SetStatusBadge(dcStatusBadge, "DC", dc, UiStatusKind.Success);
                }
                else if (snapshot.DiscoveryAttempted)
                {
                    string preferred = DomainValidation.NormalizeDirectoryServer(dcBox == null ? String.Empty : dcBox.Text);
                    SetStatusBadge(
                        dcStatusBadge,
                        "DC",
                        String.IsNullOrWhiteSpace(preferred) ? "Not found" : "Preferred: " + preferred,
                        String.IsNullOrWhiteSpace(preferred) ? UiStatusKind.Warning : UiStatusKind.Info);
                }
                else
                {
                    UpdatePreferredDcStatus();
                }

                if (footerLabel != null)
                    footerLabel.Text = BuildFooterText();
            }
            catch
            {
                SetStatusBadge(domainStatusBadge, "Domain", "Unknown", UiStatusKind.Error);
                SetStatusBadge(trustStatusBadge, "Trust", "Unknown", UiStatusKind.Error);
                UpdatePreferredDcStatus();
            }
        }

        private void UpdatePreferredDcStatus()
        {
            string preferred = DomainValidation.NormalizeDirectoryServer(dcBox == null ? String.Empty : dcBox.Text);
            if (String.IsNullOrWhiteSpace(preferred))
                SetStatusBadge(dcStatusBadge, "DC", "Auto", UiStatusKind.Neutral);
            else
                SetStatusBadge(dcStatusBadge, "DC", "Preferred: " + preferred, UiStatusKind.Info);
        }

        private void SetAdStatus(string value, UiStatusKind kind)
        {
            SetStatusBadge(adStatusBadge, "AD", value, kind);
        }

        private void CopyDiagnosticsToClipboard()
        {
            DiagnosticInputs inputs = CaptureDiagnosticInputs();

            RunBackgroundDiagnostic(
                "Copy Diagnostics",
                delegate(System.Threading.CancellationToken token, Action<string> progress)
                {
                    progress("Copy Diagnostics: capturing current state");
                    token.ThrowIfCancellationRequested();
                    DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(
                        inputs.Domain,
                        inputs.PreferredDc);
                    token.ThrowIfCancellationRequested();
                    return snapshot;
                },
                delegate(DiagnosticsSnapshot snapshot)
                {
                    lastDiagnosticsSnapshot = snapshot;
                    Clipboard.SetText(DiagnosticsService.ToText(snapshot));
                    Log("SUCCESS", "Diagnostics copied to clipboard.");
                    MessageBox.Show(
                        this,
                        "Diagnostics copied to the clipboard.\r\n\r\nNo entered domain username or password is included in the diagnostic report.",
                        "Diagnostics copied",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                });
        }
    }
}
