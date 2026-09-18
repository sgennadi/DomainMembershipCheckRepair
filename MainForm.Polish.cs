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
            AutoScaleMode = AutoScaleMode.Dpi;
        }

        private Control CreateStatusFooterPanel()
        {
            TableLayoutPanel panel = new TableLayoutPanel();
            panel.Dock = DockStyle.Fill;
            panel.Margin = new Padding(0, 3, 0, 0);
            panel.Padding = new Padding(0);
            panel.ColumnCount = 5;
            panel.RowCount = 1;
            panel.BackColor = SystemColors.ControlLightLight;

            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 145F));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120F));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190F));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 165F));
            panel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

            domainStatusBadge = CreateStatusBadge("Domain: Checking...");
            trustStatusBadge = CreateStatusBadge("Trust: Checking...");
            dcStatusBadge = CreateStatusBadge("DC: Auto");
            adStatusBadge = CreateStatusBadge("AD: Not checked");

            footerLabel = new Label();
            footerLabel.Dock = DockStyle.Fill;
            footerLabel.TextAlign = ContentAlignment.MiddleRight;
            footerLabel.AutoEllipsis = true;
            footerLabel.ForeColor = SystemColors.GrayText;
            footerLabel.Font = new Font("Segoe UI", 8.25F);
            footerLabel.Margin = new Padding(4, 1, 2, 1);
            footerLabel.Text = BuildFooterText();

            panel.Controls.Add(domainStatusBadge, 0, 0);
            panel.Controls.Add(trustStatusBadge, 1, 0);
            panel.Controls.Add(dcStatusBadge, 2, 0);
            panel.Controls.Add(adStatusBadge, 3, 0);
            panel.Controls.Add(footerLabel, 4, 0);

            SetStatusBadge(domainStatusBadge, "Domain", "Checking...", UiStatusKind.Info);
            SetStatusBadge(trustStatusBadge, "Trust", "Checking...", UiStatusKind.Info);
            SetStatusBadge(dcStatusBadge, "DC", "Auto", UiStatusKind.Neutral);
            SetStatusBadge(adStatusBadge, "AD", "Not checked", UiStatusKind.Neutral);

            return panel;
        }

        private static Label CreateStatusBadge(string text)
        {
            Label label = new Label();
            label.Dock = DockStyle.Fill;
            label.AutoSize = false;
            label.AutoEllipsis = true;
            label.TextAlign = ContentAlignment.MiddleLeft;
            label.Font = new Font("Segoe UI", 8.25F, FontStyle.Bold);
            label.Margin = new Padding(1);
            label.Padding = new Padding(6, 0, 4, 0);
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
                   "  |  " + (Environment.Is64BitProcess ? "64-bit" : "32-bit");
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
            try
            {
                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text);
                lastDiagnosticsSnapshot = snapshot;

                string report = DiagnosticsService.ToText(snapshot);
                Clipboard.SetText(report);
                RefreshStatusCards();
                Log("SUCCESS", "Diagnostics copied to clipboard.");
                MessageBox.Show(
                    this,
                    "Diagnostics copied to the clipboard.\r\n\r\nNo entered domain username or password is included in the diagnostic report.",
                    "Diagnostics copied",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Unable to copy diagnostics: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Copy diagnostics failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
