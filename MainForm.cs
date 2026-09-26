using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed partial class MainForm : Form
    {
        private const string LogFile = DiagnosticsService.ApplicationLogPath;

        private TextBox domainBox;
        private Label domainSourceValue;
        private TextBox dcBox;
        private TextBox userBox;
        private TextBox passwordBox;
        private CheckBox showPasswordBox;
        private Label computerValue;
        private Label membershipValue;
        private Label trustValue;
        private Button detectButton;
        private Button checkButton;
        private Button repairButton;
        private Button joinButton;
        private Button adCheckButton;
        private Button diagnosticsButton;
        private Button exportButton;
        private Button advancedButton;
        private Button recoveryPlanButton;
        private Button dcMatrixButton;
        private Button supportBundleButton;
        private Button cyberArkButton;
        private Button offlineJoinButton;
        private Button safeFixesButton;
        private Button selfTestButton;
        private Button siteSubnetButton;
        private Button protocolsButton;
        private Button hardeningButton;
        private Button joinPermissionsButton;
        private Button hybridEntraButton;
        private Button policySourceButton;
        private Button replicationMetadataButton;
        private Button spnCollisionsButton;
        private Button smbKerberosButton;
        private Button restartButton;
        private Button aboutButton;
        private TextBox logBox;
        private CheckBox fileLogBox;
        private readonly bool initialFileLogging;
        private readonly GuiResumeOptions startupOptions;

        private string joinedDomain = String.Empty;
        private bool settingDomainBox;
        private bool domainManuallyEdited;

        internal MainForm(bool enableFileLogging, string[] args)
        {
            initialFileLogging = enableFileLogging;
            startupOptions = ElevationHelper.ParseGuiResumeOptions(args);
            Text = "Domain Membership Check & Repair v" + BuildInfo.Version;
            Width = 980;
            Height = 820;
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = true;
            Font = new Font("Segoe UI", 9F);
            ApplyWindowPolish();
            UiLayoutHelper.EnableScreenAwareSizing(this, new Size(640, 480));

            BuildUi();
            ApplyStartupOptions();
            RefreshStatus(true);

            if (startupOptions != null && !String.IsNullOrWhiteSpace(startupOptions.Action))
            {
                Shown += delegate
                {
                    BeginInvoke(new MethodInvoker(ResumeElevatedAction));
                };
            }
        }

        private void BuildUi()
        {
            Panel scrollHost = new Panel();
            scrollHost.Dock = DockStyle.Fill;
            scrollHost.AutoScroll = true;

            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Top;
            root.AutoSize = true;
            root.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            root.Padding = new Padding(14);
            root.ColumnCount = 2;
            root.RowCount = 12;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));

            Label title = new Label();
            title.Text = "Domain Membership Check & Repair  v" + BuildInfo.Version;
            title.Font = new Font("Segoe UI", 14F, FontStyle.Bold);
            title.AutoSize = true;
            root.Controls.Add(title, 0, 0);
            root.SetColumnSpan(title, 2);

            root.Controls.Add(CreateLabel("Computer:"), 0, 1);
            computerValue = CreateValueLabel();
            root.Controls.Add(computerValue, 1, 1);

            root.Controls.Add(CreateLabel("Domain membership:"), 0, 2);
            membershipValue = CreateValueLabel();
            root.Controls.Add(membershipValue, 1, 2);

            root.Controls.Add(CreateLabel("Secure channel:"), 0, 3);
            trustValue = CreateValueLabel();
            root.Controls.Add(trustValue, 1, 3);

            root.Controls.Add(CreateLabel("Target domain:"), 0, 4);

            TableLayoutPanel domainPanel = new TableLayoutPanel();
            domainPanel.Dock = DockStyle.Fill;
            domainPanel.ColumnCount = 2;
            domainPanel.RowCount = 3;
            domainPanel.Margin = new Padding(0);
            domainPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            domainPanel.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            domainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            domainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            domainPanel.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            domainBox = new TextBox();
            domainBox.Dock = DockStyle.Fill;
            domainBox.TextChanged += delegate
            {
                if (!settingDomainBox)
                {
                    domainManuallyEdited = true;
                    domainSourceValue.Text = "Manual";
                }
            };
            domainPanel.Controls.Add(domainBox, 0, 0);

            detectButton = CreateButton("Detect Domain", 115);
            detectButton.Margin = new Padding(8, 0, 0, 0);
            detectButton.Click += delegate { DetectDomain(true); };
            domainPanel.Controls.Add(detectButton, 1, 0);

            domainSourceValue = new Label();
            domainSourceValue.AutoSize = true;
            domainSourceValue.ForeColor = SystemColors.GrayText;
            domainSourceValue.Text = "Auto-detecting...";
            domainPanel.Controls.Add(domainSourceValue, 0, 1);
            domainPanel.SetColumnSpan(domainSourceValue, 2);

            FlowLayoutPanel dcPanel = new FlowLayoutPanel();
            dcPanel.Dock = DockStyle.Fill;
            dcPanel.FlowDirection = FlowDirection.LeftToRight;
            dcPanel.WrapContents = true;
            dcPanel.AutoSize = true;
            dcPanel.Margin = new Padding(0, 2, 0, 0);

            Label dcLabel = new Label();
            dcLabel.Text = "Preferred DC (optional):";
            dcLabel.AutoSize = true;
            dcLabel.Margin = new Padding(0, 5, 8, 0);
            dcPanel.Controls.Add(dcLabel);

            dcBox = new TextBox();
            dcBox.Width = 285;
            dcBox.Text = String.Empty;
            dcBox.TextChanged += delegate { UpdatePreferredDcStatus(); };
            dcPanel.Controls.Add(dcBox);

            Label dcHint = new Label();
            dcHint.Text = "LDAP operations only";
            dcHint.AutoSize = true;
            dcHint.ForeColor = SystemColors.GrayText;
            dcHint.Margin = new Padding(8, 5, 0, 0);
            dcPanel.Controls.Add(dcHint);

            domainPanel.Controls.Add(dcPanel, 0, 2);
            domainPanel.SetColumnSpan(dcPanel, 2);

            root.Controls.Add(domainPanel, 1, 4);

            root.Controls.Add(CreateLabel("Domain user:"), 0, 5);

            TableLayoutPanel userPanel = new TableLayoutPanel();
            userPanel.Dock = DockStyle.Fill;
            userPanel.ColumnCount = 1;
            userPanel.RowCount = 2;
            userPanel.Margin = new Padding(0);
            userPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 25F));
            userPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20F));

            userBox = new TextBox();
            userBox.Dock = DockStyle.Fill;
            userBox.Text = String.Empty;
            userPanel.Controls.Add(userBox, 0, 0);

            Label userFormat = new Label();
            userFormat.Text = @"Format: DOMAIN\username   or   username@example.com";
            userFormat.AutoSize = true;
            userFormat.ForeColor = SystemColors.GrayText;
            userPanel.Controls.Add(userFormat, 0, 1);

            root.Controls.Add(userPanel, 1, 5);

            root.Controls.Add(CreateLabel("Password:"), 0, 6);
            FlowLayoutPanel passwordPanel = new FlowLayoutPanel();
            passwordPanel.Dock = DockStyle.Fill;
            passwordPanel.FlowDirection = FlowDirection.LeftToRight;
            passwordPanel.WrapContents = true;
            passwordPanel.AutoSize = true;

            passwordBox = new TextBox();
            passwordBox.Width = 320;
            passwordBox.UseSystemPasswordChar = true;
            passwordPanel.Controls.Add(passwordBox);

            showPasswordBox = new CheckBox();
            showPasswordBox.Text = "Show";
            showPasswordBox.AutoSize = true;
            showPasswordBox.CheckedChanged += delegate
            {
                passwordBox.UseSystemPasswordChar = !showPasswordBox.Checked;
            };
            passwordPanel.Controls.Add(showPasswordBox);
            root.Controls.Add(passwordPanel, 1, 6);

            TabControl actionTabs = new TabControl();
            actionTabs.Dock = DockStyle.Fill;
            actionTabs.Height = 132;
            actionTabs.MinimumSize = new Size(0, 116);

            TabPage basicPage = new TabPage("Basic");
            TabPage advancedPage = new TabPage("Advanced");

            FlowLayoutPanel basicActions = new FlowLayoutPanel();
            basicActions.Dock = DockStyle.Fill;
            basicActions.AutoScroll = true;
            basicActions.WrapContents = true;
            basicActions.Padding = new Padding(6);

            FlowLayoutPanel advancedActions = new FlowLayoutPanel();
            advancedActions.Dock = DockStyle.Fill;
            advancedActions.AutoScroll = true;
            advancedActions.WrapContents = true;
            advancedActions.Padding = new Padding(6);

            basicPage.Controls.Add(basicActions);
            advancedPage.Controls.Add(advancedActions);
            actionTabs.TabPages.Add(basicPage);
            actionTabs.TabPages.Add(advancedPage);

            checkButton = CreateButton("Check Trust", 120);
            diagnosticsButton = CreateButton("Diagnostics", 120);
            copyDiagnosticsButton = CreateButton("Copy Diagnostics", 135);
            exportButton = CreateButton("Export Diagnostics", 145);
            advancedButton = CreateButton("Advanced Diagnostics", 155);
            recoveryPlanButton = CreateButton("Recovery Plan", 125);
            dcMatrixButton = CreateButton("DC Matrix", 105);
            supportBundleButton = CreateButton("Support Bundle", 125);
            cyberArkButton = CreateButton("CyberArk Health", 125);
            offlineJoinButton = CreateButton("Offline Join", 110);
            safeFixesButton = CreateButton("Safe Fixes", 105);
            selfTestButton = CreateButton("Self Test", 105);
            siteSubnetButton = CreateButton("Site / Subnet", 115);
            protocolsButton = CreateButton("Protocol Tests", 120);
            hardeningButton = CreateButton("Hardening", 105);
            joinPermissionsButton = CreateButton("Join Permissions", 135);
            hybridEntraButton = CreateButton("Hybrid Entra", 115);
            policySourceButton = CreateButton("Policy Sources", 120);
            replicationMetadataButton = CreateButton("Replication Metadata", 155);
            spnCollisionsButton = CreateButton("SPN Collisions", 125);
            smbKerberosButton = CreateButton("SMB / Kerberos", 130);
            repairButton = CreateButton("Repair Trust", 120);
            joinButton = CreateButton("Join / Rejoin Domain", 170);
            adCheckButton = CreateButton("Check AD Account", 150);
            restartButton = CreateButton("Restart Windows", 140);
            aboutButton = CreateButton("About", 85);

            bool needsElevation = !ElevationHelper.IsAdministrator();
            ElevationHelper.SetElevationShield(repairButton, needsElevation);
            ElevationHelper.SetElevationShield(joinButton, needsElevation);
            ElevationHelper.SetElevationShield(restartButton, needsElevation);
            ElevationHelper.SetElevationShield(offlineJoinButton, needsElevation);
            ElevationHelper.SetElevationShield(safeFixesButton, needsElevation);

            checkButton.Click += delegate { RefreshStatus(false); };
            diagnosticsButton.Click += delegate { DiagnosticsWorkflow(); };
            copyDiagnosticsButton.Click += delegate { CopyDiagnosticsToClipboard(); };
            exportButton.Click += delegate { ExportDiagnosticsWorkflow(); };
            advancedButton.Click += delegate { AdvancedDiagnosticsWorkflow(); };
            recoveryPlanButton.Click += delegate { RecoveryPlanWorkflow(); };
            dcMatrixButton.Click += delegate { DcMatrixWorkflow(); };
            supportBundleButton.Click += delegate { SupportBundleWorkflow(); };
            cyberArkButton.Click += delegate { CyberArkHealthWorkflow(); };
            offlineJoinButton.Click += delegate { OfflineDomainJoinWorkflow(); };
            safeFixesButton.Click += delegate { SafeFixesWorkflow(); };
            selfTestButton.Click += delegate { SelfTestWorkflow(); };
            siteSubnetButton.Click += delegate { SiteSubnetWorkflow(); };
            protocolsButton.Click += delegate { ProtocolDiagnosticsWorkflow(); };
            hardeningButton.Click += delegate { HardeningWorkflow(); };
            joinPermissionsButton.Click += delegate { JoinPermissionsWorkflow(); };
            hybridEntraButton.Click += delegate { HybridEntraWorkflow(); };
            policySourceButton.Click += delegate { PolicySourceWorkflow(); };
            replicationMetadataButton.Click += delegate { ReplicationMetadataWorkflow(); };
            spnCollisionsButton.Click += delegate { SpnCollisionsWorkflow(); };
            smbKerberosButton.Click += delegate { SmbKerberosWorkflow(); };
            repairButton.Click += delegate { RepairTrustWorkflow(); };
            joinButton.Click += delegate { JoinCurrentNameWorkflow(); };
            adCheckButton.Click += delegate { CheckAdAccountWorkflow(); };
            restartButton.Click += delegate { RestartWindows(); };
            aboutButton.Click += delegate { ShowAbout(); };

            basicActions.Controls.Add(checkButton);
            basicActions.Controls.Add(diagnosticsButton);
            basicActions.Controls.Add(safeFixesButton);
            basicActions.Controls.Add(repairButton);
            basicActions.Controls.Add(joinButton);
            basicActions.Controls.Add(adCheckButton);
            basicActions.Controls.Add(restartButton);

            advancedActions.Controls.Add(copyDiagnosticsButton);
            advancedActions.Controls.Add(exportButton);
            advancedActions.Controls.Add(advancedButton);
            advancedActions.Controls.Add(recoveryPlanButton);
            advancedActions.Controls.Add(dcMatrixButton);
            advancedActions.Controls.Add(supportBundleButton);
            advancedActions.Controls.Add(cyberArkButton);
            advancedActions.Controls.Add(offlineJoinButton);
            advancedActions.Controls.Add(selfTestButton);
            advancedActions.Controls.Add(siteSubnetButton);
            advancedActions.Controls.Add(protocolsButton);
            advancedActions.Controls.Add(hardeningButton);
            advancedActions.Controls.Add(joinPermissionsButton);
            advancedActions.Controls.Add(hybridEntraButton);
            advancedActions.Controls.Add(policySourceButton);
            advancedActions.Controls.Add(replicationMetadataButton);
            advancedActions.Controls.Add(spnCollisionsButton);
            advancedActions.Controls.Add(smbKerberosButton);
            advancedActions.Controls.Add(aboutButton);

            root.Controls.Add(actionTabs, 0, 7);
            root.SetColumnSpan(actionTabs, 2);

            Label note = new Label();
            note.Text = "The target domain is detected automatically when possible and remains editable. Preferred DC pins LDAP lookup/deletion only; Windows chooses the DC used for domain join. Check AD Account is read-only. Destructive AD deletion always requires explicit confirmation.";
            note.AutoSize = true;
            note.Dock = DockStyle.Fill;
            note.MaximumSize = new Size(0, 0);
            root.Controls.Add(note, 0, 8);
            root.SetColumnSpan(note, 2);

            FlowLayoutPanel fileLogPanel = new FlowLayoutPanel();
            fileLogPanel.Dock = DockStyle.Fill;
            fileLogPanel.FlowDirection = FlowDirection.LeftToRight;
            fileLogPanel.WrapContents = true;
            fileLogPanel.AutoSize = true;
            fileLogPanel.Margin = new Padding(0);

            fileLogBox = new CheckBox();
            fileLogBox.Text = "Write application log to file";
            fileLogBox.AutoSize = true;
            fileLogBox.Checked = initialFileLogging;
            fileLogPanel.Controls.Add(fileLogBox);

            Label fileLogPath = new Label();
            fileLogPath.Text = LogFile + "  (default: No)";
            fileLogPath.AutoSize = true;
            fileLogPath.ForeColor = SystemColors.GrayText;
            fileLogPath.Margin = new Padding(12, 4, 0, 0);
            fileLogPanel.Controls.Add(fileLogPath);

            root.Controls.Add(fileLogPanel, 0, 9);
            root.SetColumnSpan(fileLogPanel, 2);

            logBox = new TextBox();
            logBox.Multiline = true;
            logBox.ReadOnly = true;
            logBox.ScrollBars = ScrollBars.Vertical;
            logBox.Dock = DockStyle.Fill;
            logBox.Font = new Font("Consolas", 9F);
            root.Controls.Add(logBox, 0, 10);
            root.SetColumnSpan(logBox, 2);

            Control statusFooter = CreateStatusFooterPanel();
            root.Controls.Add(statusFooter, 0, 11);
            root.SetColumnSpan(statusFooter, 2);

            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 150F));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 220F));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            scrollHost.Controls.Add(root);
            Controls.Add(scrollHost);
        }

        private static Label CreateLabel(string text)
        {
            Label label = new Label();
            label.Text = text;
            label.AutoSize = true;
            label.Anchor = AnchorStyles.Left;
            return label;
        }

        private static Label CreateValueLabel()
        {
            Label label = new Label();
            label.AutoSize = true;
            label.Anchor = AnchorStyles.Left;
            label.Font = new Font("Segoe UI", 9F, FontStyle.Bold);
            return label;
        }

        private static Button CreateButton(string text, int width)
        {
            Button button = new Button();
            button.Text = text;
            button.AutoSize = true;
            button.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            button.MinimumSize = new Size(width, 32);
            button.Padding = new Padding(6, 2, 6, 2);
            return button;
        }


        private void ApplyStartupOptions()
        {
            if (startupOptions == null)
                return;

            if (!String.IsNullOrWhiteSpace(startupOptions.Domain))
                SetDomainBox(startupOptions.Domain, "Preserved across elevation", false);

            if (!String.IsNullOrWhiteSpace(startupOptions.User) && userBox != null)
                userBox.Text = startupOptions.User;

            if (!String.IsNullOrWhiteSpace(startupOptions.PreferredDc) && dcBox != null)
                dcBox.Text = startupOptions.PreferredDc;

            if (passwordBox != null)
                passwordBox.Clear();
        }

        private void ResumeElevatedAction()
        {
            if (startupOptions == null || String.IsNullOrWhiteSpace(startupOptions.Action))
                return;

            if (startupOptions.Action == "post-reboot-check")
            {
                ResumeService.Clear();
                Log("INFO", "Post-reboot recovery check started.");
                AdvancedDiagnosticsWorkflow();

                DiagnosticsSnapshot post = DiagnosticsService.Capture(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text);

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
                return;
            }

            if (!ElevationHelper.IsAdministrator())
            {
                MessageBox.Show(
                    this,
                    "Windows/CyberArk returned control without an administrator token.\r\n\r\n" +
                    "Read-only diagnostics are still available. Check the CyberArk EPM elevation policy for this application.",
                    "Elevation not granted",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                Log("WARN", "Elevation was requested, but the resumed process is not running with administrator privileges.");
                return;
            }

            Log("SUCCESS", "Administrator privileges acquired. Resumed after Windows/CyberArk elevation.");

            switch (startupOptions.Action)
            {
                case "repair":
                    RepairTrustWorkflow();
                    break;

                case "restart":
                    RestartWindows();
                    break;

                case "odj-apply":
                    OfflineDomainJoinWorkflow();
                    break;

                case "safe-fixes":
                    SafeFixesWorkflow();
                    break;

                case "join":
                    MessageBox.Show(
                        this,
                        "Administrator privileges are active.\r\n\r\n" +
                        "For security, the domain password is never transferred between the standard and elevated processes. " +
                        "Enter the domain credentials, then click Join / Rejoin Domain again.",
                        "Elevation successful",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);

                    if (String.IsNullOrWhiteSpace(userBox.Text))
                        userBox.Focus();
                    else
                        passwordBox.Focus();
                    break;
            }
        }

        private bool EnsureElevatedForGui(string action)
        {
            if (ElevationHelper.IsAdministrator())
                return true;

            if (startupOptions != null && startupOptions.ElevationAttempted)
            {
                MessageBox.Show(
                    this,
                    "This operation requires administrator privileges, but the current process is still not elevated.\r\n\r\n" +
                    "Check the CyberArk EPM policy for DomainMembershipCheckRepair.",
                    "Administrator privileges required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return false;
            }

            List<string> args = new List<string>();
            args.Add("--resume-action");
            args.Add(action);
            args.Add("--elevation-attempted");

            string domain = domainBox == null ? String.Empty : (domainBox.Text ?? String.Empty).Trim();
            string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
            string dc = dcBox == null ? String.Empty : (dcBox.Text ?? String.Empty).Trim();

            if (!String.IsNullOrWhiteSpace(domain))
            {
                args.Add("--domain");
                args.Add(domain);
            }
            if (!String.IsNullOrWhiteSpace(user))
            {
                args.Add("--user");
                args.Add(user);
            }
            if (!String.IsNullOrWhiteSpace(dc))
            {
                args.Add("--dc");
                args.Add(dc);
            }

            args.Add(fileLogBox != null && fileLogBox.Checked ? "--log" : "--no-log");

            int ignoredExitCode;
            string elevationError;
            if (ElevationHelper.TryStartElevated(args.ToArray(), false, out ignoredExitCode, out elevationError))
            {
                Log("INFO", "Administrator privileges requested through the Windows elevation broker (compatible with CyberArk EPM).");
                BeginInvoke(new MethodInvoker(Close));
                return false;
            }

            Log("WARN", "Elevation request failed or was cancelled: " + elevationError);
            MessageBox.Show(
                this,
                "Administrator privileges were not granted.\r\n\r\n" +
                elevationError + "\r\n\r\n" +
                "Read-only diagnostics remain available.",
                "Elevation cancelled or blocked",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return false;
        }

        private void RefreshStatus(bool initialLoad)
        {
            SetBusy(true);
            try
            {
                computerValue.Text = Environment.MachineName + "   [" + BuildInfo.TargetArchitecture + "]";

                JoinInformation join = NativeMethods.GetJoinInformation();
                if (join.StatusCode != NativeMethods.NERR_Success)
                {
                    membershipValue.Text = "Unknown - " + NativeMethods.FormatError(join.StatusCode);
                    trustValue.Text = "Unknown";
                    trustValue.ForeColor = SystemColors.ControlText;
                    joinedDomain = String.Empty;
                    Log("ERROR", "NetGetJoinInformation failed: " + NativeMethods.FormatError(join.StatusCode));
                    if (initialLoad)
                        DetectDomain(false);
                    return;
                }

                if (join.Status == NetJoinStatus.NetSetupDomainName)
                {
                    joinedDomain = join.Name ?? String.Empty;
                    string displayDomain = joinedDomain;
                    DomainDiscoveryResult canonical = NativeMethods.DiscoverDomain(joinedDomain, false);
                    if (canonical.Success && !String.IsNullOrWhiteSpace(canonical.DnsDomainName))
                        displayDomain = canonical.DnsDomainName;

                    membershipValue.Text = "Domain: " + displayDomain;
                    if (!domainManuallyEdited || String.IsNullOrWhiteSpace(domainBox.Text))
                        SetDomainBox(displayDomain, "Current domain membership", true);

                    TrustCheckResult trust = NativeMethods.VerifySecureChannel(joinedDomain);
                    if (trust.Healthy)
                    {
                        trustValue.Text = "OK";
                        trustValue.ForeColor = Color.DarkGreen;
                        Log("SUCCESS", "Secure channel is healthy." + FormatDcSuffix(trust.TrustedDc));
                    }
                    else
                    {
                        trustValue.Text = "BROKEN / " + NativeMethods.FormatError(trust.StatusCode);
                        trustValue.ForeColor = Color.DarkRed;
                        Log("WARN", "Secure channel verification failed: " + NativeMethods.FormatError(trust.StatusCode));
                    }
                }
                else
                {
                    joinedDomain = String.Empty;
                    membershipValue.Text = "Not joined to a domain (" + join.Status.ToString() + ")";
                    trustValue.Text = "Not applicable";
                    trustValue.ForeColor = SystemColors.ControlText;
                    Log("INFO", "Computer is not currently joined to a domain.");
                    if (initialLoad || String.IsNullOrWhiteSpace(domainBox.Text))
                        DetectDomain(false);
                }
            }
            catch (Exception ex)
            {
                Log("ERROR", ex.Message);
                MessageBox.Show(this, ex.Message, "Status check failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                RefreshStatusCards();
                SetBusy(false);
            }
        }

        private void DetectDomain(bool forceRediscovery)
        {
            SetBusy(true);
            try
            {
                JoinInformation join = NativeMethods.GetJoinInformation();
                if (join.StatusCode == 0 && join.Status == NetJoinStatus.NetSetupDomainName && !String.IsNullOrWhiteSpace(join.Name))
                {
                    DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(join.Name, forceRediscovery);
                    string value = resolved.Success && !String.IsNullOrWhiteSpace(resolved.DnsDomainName) ? resolved.DnsDomainName : join.Name;
                    SetDomainBox(value, resolved.Success ? "Current domain membership / DC discovery" : "Current domain membership (offline)", true);
                    Log("INFO", "Target domain detected from current domain membership." + FormatDcSuffix(resolved.DomainControllerName));
                    return;
                }

                string physicalSuffix = NativeMethods.GetPhysicalDnsDomain();
                if (!String.IsNullOrWhiteSpace(physicalSuffix))
                {
                    DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(physicalSuffix, forceRediscovery);
                    if (resolved.Success)
                    {
                        SetDomainBox(FirstNonEmpty(resolved.DnsDomainName, physicalSuffix), "Physical DNS suffix / DC discovery", true);
                        Log("INFO", "Target domain detected from the computer DNS suffix." + FormatDcSuffix(resolved.DomainControllerName));
                        return;
                    }
                }

                string userDnsDomain = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                if (!String.IsNullOrWhiteSpace(userDnsDomain))
                {
                    DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(userDnsDomain, forceRediscovery);
                    if (resolved.Success)
                    {
                        SetDomainBox(FirstNonEmpty(resolved.DnsDomainName, userDnsDomain), "Current user DNS domain / DC discovery", true);
                        Log("INFO", "Target domain detected from the current user environment." + FormatDcSuffix(resolved.DomainControllerName));
                        return;
                    }
                }

                if (!domainManuallyEdited || String.IsNullOrWhiteSpace(domainBox.Text))
                {
                    SetDomainBox(String.Empty, "Not detected - enter a DNS or NetBIOS domain name", true);
                }
                Log("WARN", "A target domain could not be detected automatically.");
            }
            finally
            {
                RefreshStatusCards();
                SetBusy(false);
            }
        }

        private void SetDomainBox(string value, string source, bool automatic)
        {
            settingDomainBox = true;
            try
            {
                domainBox.Text = value ?? String.Empty;
                domainSourceValue.Text = source ?? String.Empty;
                domainManuallyEdited = !automatic;
            }
            finally
            {
                settingDomainBox = false;
            }
        }

        private void DiagnosticsWorkflow()
        {
            SetBusy(true);
            try
            {
                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(
                    (domainBox.Text ?? String.Empty).Trim(),
                    dcBox == null ? String.Empty : dcBox.Text);
                lastDiagnosticsSnapshot = snapshot;
                Log("INFO", "Diagnostics completed. " + BuildInfo.RuntimeSummary);
                ReportDialog.ShowReport(this, "Diagnostics", DiagnosticsService.ToText(snapshot));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Diagnostics failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Diagnostics failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void ExportDiagnosticsWorkflow()
        {
            SetBusy(true);
            try
            {
                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(
                    (domainBox.Text ?? String.Empty).Trim(),
                    dcBox == null ? String.Empty : dcBox.Text);

                using (SaveFileDialog save = new SaveFileDialog())
                {
                    save.Title = "Export diagnostics";
                    save.Filter = "ZIP archive (*.zip)|*.zip|All files (*.*)|*.*";
                    save.FileName = Path.GetFileName(DiagnosticsService.GetDefaultArchivePath());
                    save.AddExtension = true;
                    save.DefaultExt = "zip";

                    if (save.ShowDialog(this) != DialogResult.OK)
                        return;

                    string archive = DiagnosticsService.ExportPackage(snapshot, save.FileName, fileLogBox != null && fileLogBox.Checked);
                    Log("SUCCESS", "Diagnostics package exported: " + archive);
                    MessageBox.Show(this,
                        "Diagnostics package created successfully:\r\n\r\n" + archive + "\r\n\r\n" +
                        "The application log is included only when file logging is enabled. Review logs before sharing them.",
                        "Diagnostics exported",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                Log("ERROR", "Diagnostics export failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Diagnostics export failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }


        private void AdvancedDiagnosticsWorkflow()
        {
            SetBusy(true);
            try
            {
                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;
                if (String.IsNullOrWhiteSpace(user) || String.IsNullOrEmpty(password))
                {
                    user = String.Empty;
                    password = null;
                }

                AdvancedDiagnosticsResult result = AdvancedDiagnosticsService.Analyze(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text,
                    Environment.MachineName,
                    user,
                    password);

                lastDiagnosticsSnapshot = result.Snapshot;
                ReportDialog.ShowReport(this, "Advanced Diagnostics", AdvancedDiagnosticsService.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Advanced diagnostics failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Advanced diagnostics failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void RecoveryPlanWorkflow()
        {
            SetBusy(true);
            try
            {
                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;
                if (String.IsNullOrWhiteSpace(user) || String.IsNullOrEmpty(password))
                {
                    user = String.Empty;
                    password = null;
                }

                AdvancedDiagnosticsResult result = AdvancedDiagnosticsService.Analyze(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text,
                    Environment.MachineName,
                    user,
                    password);

                ReportDialog.ShowReport(this, "Recovery Plan", RecoveryPlanService.ToText(result.RecoveryPlan));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Recovery plan failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Recovery plan failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void DcMatrixWorkflow()
        {
            SetBusy(true);
            try
            {
                string targetDomain;
                if (!TryGetTargetDomain(out targetDomain))
                    return;

                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(targetDomain, dcBox == null ? String.Empty : dcBox.Text);
                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;
                if (String.IsNullOrWhiteSpace(user) || String.IsNullOrEmpty(password))
                {
                    user = String.Empty;
                    password = null;
                }

                DcMatrixResult matrix = DcMatrixService.Analyze(
                    snapshot.TargetDomain,
                    snapshot.DiscoveredDc,
                    Environment.MachineName,
                    user,
                    password);
                ReportDialog.ShowReport(this, "Domain Controller Matrix", DcMatrixService.ToText(matrix));
            }
            catch (Exception ex)
            {
                Log("ERROR", "DC Matrix failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "DC Matrix failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void SupportBundleWorkflow()
        {
            SetBusy(true);
            try
            {
                using (SaveFileDialog save = new SaveFileDialog())
                {
                    save.Title = "Export advanced support bundle";
                    save.Filter = "ZIP archive (*.zip)|*.zip|All files (*.*)|*.*";
                    save.FileName = "DomainMembershipSupport-" + Environment.MachineName + "-" + DateTime.Now.ToString("yyyyMMdd-HHmmss") + ".zip";
                    save.AddExtension = true;
                    save.DefaultExt = "zip";
                    if (save.ShowDialog(this) != DialogResult.OK)
                        return;

                    string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                    string password = passwordBox == null ? null : passwordBox.Text;
                    if (String.IsNullOrWhiteSpace(user) || String.IsNullOrEmpty(password))
                    {
                        user = String.Empty;
                        password = null;
                    }

                    AdvancedDiagnosticsResult result = AdvancedDiagnosticsService.Analyze(
                        domainBox == null ? String.Empty : domainBox.Text,
                        dcBox == null ? String.Empty : dcBox.Text,
                        Environment.MachineName,
                        user,
                        password);

                    string archive = AdvancedSupportBundleService.Export(
                        result,
                        save.FileName,
                        fileLogBox != null && fileLogBox.Checked);

                    Log("SUCCESS", "Advanced support bundle exported: " + archive);
                    MessageBox.Show(
                        this,
                        "Support bundle created:\r\n\r\n" + archive + "\r\n\r\nReview Windows logs and command output before sharing.",
                        "Support bundle",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                Log("ERROR", "Support bundle failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Support bundle failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void SelfTestWorkflow()
        {
            SetBusy(true);
            try
            {
                SelfTestResult result = SelfTestService.Run(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text);
                ReportDialog.ShowReport(
                    this,
                    "Application Self Test",
                    SelfTestService.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Self Test failed: " + ex.Message);
                MessageBox.Show(
                    this,
                    ex.Message,
                    "Self Test failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void SiteSubnetWorkflow()
        {
            SetBusy(true);
            try
            {
                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;
                if (String.IsNullOrWhiteSpace(user) || String.IsNullOrEmpty(password))
                {
                    user = String.Empty;
                    password = null;
                }

                SiteSubnetDiagnosticsResult result = SiteSubnetDiagnosticsService.Analyze(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text,
                    user,
                    password);

                ReportDialog.ShowReport(this, "AD Site / Subnet Diagnostics", SiteSubnetDiagnosticsService.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Site/Subnet diagnostics failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Site/Subnet diagnostics failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void ProtocolDiagnosticsWorkflow()
        {
            SetBusy(true);
            try
            {
                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;
                if (String.IsNullOrWhiteSpace(user) || String.IsNullOrEmpty(password))
                {
                    user = String.Empty;
                    password = null;
                }

                ProtocolDiagnosticsResult result = ProtocolDiagnosticsService.Analyze(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text,
                    user,
                    password);

                ReportDialog.ShowReport(this, "Protocol-level Diagnostics", ProtocolDiagnosticsService.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Protocol diagnostics failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Protocol diagnostics failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void HardeningWorkflow()
        {
            SetBusy(true);
            try
            {
                AdComputerAccountInfo account = null;
                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;

                if (!String.IsNullOrWhiteSpace(user) && !String.IsNullOrEmpty(password))
                {
                    string targetDomain = domainBox == null ? String.Empty : (domainBox.Text ?? String.Empty).Trim();
                    account = AdDirectoryService.FindComputerAccount(
                        Environment.MachineName,
                        user,
                        password,
                        targetDomain,
                        dcBox == null ? String.Empty : dcBox.Text,
                        null);
                }

                HardeningDiagnosticsResult result = HardeningDiagnosticsService.Analyze(account);
                ReportDialog.ShowReport(this, "LDAP / Kerberos / Netlogon Hardening", HardeningDiagnosticsService.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Hardening diagnostics failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Hardening diagnostics failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void JoinPermissionsWorkflow()
        {
            SetBusy(true);
            try
            {
                string targetDomain = domainBox == null ? String.Empty : (domainBox.Text ?? String.Empty).Trim();
                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;
                AdComputerAccountInfo account = null;

                if (!String.IsNullOrWhiteSpace(user) && !String.IsNullOrEmpty(password))
                {
                    account = AdDirectoryService.FindComputerAccount(
                        Environment.MachineName,
                        user,
                        password,
                        targetDomain,
                        dcBox == null ? String.Empty : dcBox.Text,
                        null);
                }
                else
                {
                    user = String.Empty;
                    password = null;
                }

                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(
                    targetDomain,
                    dcBox == null ? String.Empty : dcBox.Text);

                JoinPermissionsResult result = JoinPermissionsAnalyzer.Analyze(
                    snapshot.TargetDomain,
                    snapshot.DiscoveredDc,
                    Environment.MachineName,
                    user,
                    password,
                    account);

                ReportDialog.ShowReport(this, "Domain Join Permissions Analyzer", JoinPermissionsAnalyzer.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Join Permissions analysis failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Join Permissions analysis failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void HybridEntraWorkflow()
        {
            SetBusy(true);
            try
            {
                HybridEntraDiagnosticsResult result = HybridEntraDiagnosticsService.Analyze();
                ReportDialog.ShowReport(this, "Hybrid Microsoft Entra Diagnostics", HybridEntraDiagnosticsService.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Hybrid Entra diagnostics failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Hybrid Entra diagnostics failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void PolicySourceWorkflow()
        {
            SetBusy(true);
            try
            {
                PolicySourceDiagnosticsResult result = PolicySourceAnalyzer.Analyze();
                ReportDialog.ShowReport(this, "Policy Source Analyzer", PolicySourceAnalyzer.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Policy Source analysis failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Policy Source analysis failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void ReplicationMetadataWorkflow()
        {
            SetBusy(true);
            try
            {
                string targetDomain = domainBox == null ? String.Empty : (domainBox.Text ?? String.Empty).Trim();
                string preferredDc = dcBox == null ? String.Empty : (dcBox.Text ?? String.Empty).Trim();
                DiagnosticsSnapshot snapshot = DiagnosticsService.Capture(targetDomain, preferredDc);

                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;
                string objectDn = String.Empty;

                if (!String.IsNullOrWhiteSpace(user) && !String.IsNullOrEmpty(password))
                {
                    AdComputerAccountInfo account = AdDirectoryService.FindComputerAccount(
                        Environment.MachineName,
                        user,
                        password,
                        snapshot.TargetDomain,
                        !String.IsNullOrWhiteSpace(DomainValidation.NormalizeDirectoryServer(preferredDc))
                            ? DomainValidation.NormalizeDirectoryServer(preferredDc)
                            : snapshot.DiscoveredDc,
                        null);

                    if (account != null && account.LookupSucceeded && account.Exists)
                        objectDn = account.DistinguishedName;
                }

                string configuredDc = DomainValidation.NormalizeDirectoryServer(preferredDc);
                string effectiveDc = !String.IsNullOrWhiteSpace(configuredDc)
                    ? configuredDc
                    : snapshot.DiscoveredDc;

                ReplicationMetadataResult result = ReplicationMetadataService.Analyze(
                    snapshot.TargetDomain,
                    effectiveDc,
                    objectDn);

                ReportDialog.ShowReport(
                    this,
                    "AD Replication Metadata",
                    ReplicationMetadataService.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "Replication metadata analysis failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Replication metadata analysis failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void SpnCollisionsWorkflow()
        {
            SetBusy(true);
            try
            {
                string user = userBox == null ? String.Empty : (userBox.Text ?? String.Empty).Trim();
                string password = passwordBox == null ? null : passwordBox.Text;
                if (String.IsNullOrWhiteSpace(user) || String.IsNullOrEmpty(password))
                {
                    user = String.Empty;
                    password = null;
                }

                SpnCollisionResult result = SpnCollisionAnalyzer.Analyze(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text,
                    Environment.MachineName,
                    user,
                    password);

                ReportDialog.ShowReport(
                    this,
                    "SPN Collision Analyzer",
                    SpnCollisionAnalyzer.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "SPN collision analysis failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "SPN collision analysis failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void SmbKerberosWorkflow()
        {
            SetBusy(true);
            try
            {
                SmbKerberosAuthResult result = SmbKerberosAuthAnalyzer.Analyze(
                    domainBox == null ? String.Empty : domainBox.Text,
                    dcBox == null ? String.Empty : dcBox.Text);

                ReportDialog.ShowReport(
                    this,
                    "SMB / Kerberos Authentication",
                    SmbKerberosAuthAnalyzer.ToText(result));
            }
            catch (Exception ex)
            {
                Log("ERROR", "SMB/Kerberos analysis failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "SMB/Kerberos analysis failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void CyberArkHealthWorkflow()
        {
            CyberArkDiagnosticsResult result = CyberArkDiagnosticsService.Analyze();
            ReportDialog.ShowReport(this, "CyberArk / EPM Health", CyberArkDiagnosticsService.ToText(result));
        }

        private void CreatePreChangeBundle(
            string operation,
            string domain,
            string user,
            string password)
        {
            string bundlePath;
            string bundleError;
            if (SafetyBundleService.TryCreate(
                operation,
                domain,
                dcBox == null ? String.Empty : dcBox.Text,
                Environment.MachineName,
                user,
                password,
                out bundlePath,
                out bundleError))
            {
                Log("INFO", "Pre-change safety bundle created: " + bundlePath);
            }
            else
            {
                Log("WARN", "Pre-change safety bundle could not be created: " + bundleError);
            }
        }

        private void OfflineDomainJoinWorkflow()
        {
            if (!EnsureElevatedForGui("odj-apply"))
                return;

            using (OpenFileDialog open = new OpenFileDialog())
            {
                open.Title = "Select Offline Domain Join provisioning blob";
                open.Filter = "ODJ provisioning files (*.*)|*.*";
                if (open.ShowDialog(this) != DialogResult.OK)
                    return;

                DialogResult confirm = MessageBox.Show(
                    this,
                    "Apply this Offline Domain Join provisioning package to the local Windows installation?\r\n\r\n" +
                    open.FileName + "\r\n\r\nA restart will be required.",
                    "Offline Domain Join",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (confirm != DialogResult.Yes)
                    return;

                string targetDomain = domainBox == null ? String.Empty : domainBox.Text;
                CreatePreChangeBundle("offline-domain-join", targetDomain, null, null);

                using (RecoverySnapshotScope snapshot = new RecoverySnapshotScope(
                    "offline-domain-join",
                    targetDomain,
                    dcBox == null ? String.Empty : dcBox.Text,
                    null,
                    null))
                {
                    string output;
                    int code = OfflineDomainJoinService.ApplyBlob(open.FileName, out output);
                    Log(code == 0 ? "SUCCESS" : "ERROR", "Offline Domain Join returned " + code + ". " + output);

                    if (code != 0)
                    {
                        ReportDialog.ShowReport(this, "Offline Domain Join failed", output);
                        return;
                    }

                    string resumeError;
                    ResumeService.RegisterPostRebootCheck(targetDomain, out resumeError);
                    if (!String.IsNullOrWhiteSpace(resumeError))
                        Log("WARN", "Unable to register post-reboot check: " + resumeError);

                    AskRestart("Offline Domain Join was applied successfully.");
                }
            }
        }

        private void SafeFixesWorkflow()
        {
            if (!EnsureElevatedForGui("safe-fixes"))
                return;

            DialogResult confirm = MessageBox.Show(
                this,
                "Run safe recovery actions now?\r\n\r\n" +
                "- Flush DNS resolver cache\r\n" +
                "- Force Windows Time resynchronization\r\n" +
                "- Restart Netlogon service\r\n" +
                "- Force domain-controller rediscovery\r\n\r\n" +
                "This does NOT delete an AD object, rename the computer, or join/rejoin the domain.",
                "Safe Fixes",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Information,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes)
                return;

            SetBusy(true);
            try
            {
                string domain = domainBox == null ? String.Empty : (domainBox.Text ?? String.Empty).Trim();

                using (RecoverySnapshotScope snapshot = new RecoverySnapshotScope(
                    "safe-fixes",
                    domain,
                    dcBox == null ? String.Empty : dcBox.Text,
                    null,
                    null))
                {
                    SafeRecoveryResult result = SafeRecoveryService.Run(domain);
                    Log(result.Success ? "SUCCESS" : "WARN",
                        result.Success ? "Safe recovery actions completed." : "Safe recovery actions completed with one or more failures.");
                    ReportDialog.ShowReport(this, "Safe Fixes", SafeRecoveryService.ToText(result));
                    RefreshStatus(false);
                }
            }
            catch (Exception ex)
            {
                Log("ERROR", "Safe Fixes failed: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Safe Fixes failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void ShowAbout()
        {
            MessageBox.Show(this,
                "Domain Membership Check & Repair\r\n" +
                "Version " + BuildInfo.Version + "\r\n" +
                "Architecture: " + BuildInfo.TargetArchitecture + "\r\n\r\n" +
                BuildInfo.RuntimeSummary + "\r\n\r\n" +
                "GUI + CLI utility for Windows domain membership, secure-channel diagnostics, Join/Rejoin and AD computer-account recovery.\r\n\r\n" +
                "Privilege: " + (ElevationHelper.IsAdministrator() ? "Administrator (elevated)" : "Standard user") + "\r\n" +
                "Application file logging is disabled by default.\r\n" +
                "License: MIT\r\n" +
                "GitHub: github.com/sgennadi/DomainMembershipCheckRepair",
                "About",
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void CheckAdAccountWorkflow()
        {
            SetBusy(true);
            try
            {
                string targetDomain;
                if (!TryGetTargetDomain(out targetDomain))
                    return;

                string user;
                string password;
                if (!GetCredentials(out user, out password))
                    return;

                targetDomain = ResolveDomainForOperation(targetDomain, user);
                if (String.IsNullOrWhiteSpace(targetDomain))
                    return;

                string computerName = ComputerNameLookupDialog.ShowDialog(this, Environment.MachineName);
                if (computerName == null)
                    return;

                string validationError = ValidateComputerName(computerName);
                if (validationError != null)
                {
                    MessageBox.Show(this, validationError, "Invalid computer name", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    return;
                }

                Log("INFO", "Performing read-only AD computer account check for '" + computerName + "'.");
                SetAdStatus("Checking...", UiStatusKind.Info);
                AdComputerAccountInfo account = FindComputerAccount(computerName, user, password, targetDomain);

                if (!account.LookupSucceeded)
                {
                    SetAdStatus("Lookup failed", UiStatusKind.Error);
                    ReportDialog.ShowReport(this, "AD computer account check",
                        "The Active Directory lookup could not be completed.\r\n\r\n" +
                        "Computer: " + computerName + "\r\n" +
                        "Domain:   " + targetDomain + "\r\n\r\n" +
                        "No changes were made.");
                    return;
                }

                if (!account.Exists)
                {
                    SetAdStatus("Not found", UiStatusKind.Warning);
                    ReportDialog.ShowReport(this, "AD computer account check",
                        "Computer account NOT FOUND.\r\n\r\n" +
                        "Computer: " + computerName + "\r\n" +
                        "Domain:   " + targetDomain + "\r\n\r\n" +
                        "This was a read-only check. No changes were made.");
                    return;
                }

                SetAdStatus(account.Enabled.HasValue && !account.Enabled.Value ? "Found / disabled" : "Found",
                    account.Enabled.HasValue && !account.Enabled.Value ? UiStatusKind.Warning : UiStatusKind.Success);
                ReportDialog.ShowReport(this, "AD computer account check", FormatAdAccountReport(computerName, targetDomain, account));
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void RepairTrustWorkflow()
        {
            if (!EnsureElevatedForGui("repair"))
                return;

            SetBusy(true);
            try
            {
                JoinInformation join = NativeMethods.GetJoinInformation();
                if (join.StatusCode != 0 || join.Status != NetJoinStatus.NetSetupDomainName || String.IsNullOrWhiteSpace(join.Name))
                {
                    MessageBox.Show(this,
                        "This computer is not currently joined to a domain, so there is no secure channel to repair.\r\n\r\nUse Join / Rejoin Domain instead.",
                        "Not a domain member",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information);
                    return;
                }

                joinedDomain = join.Name;

                using (RecoverySnapshotScope snapshot = new RecoverySnapshotScope(
                    "repair-trust",
                    joinedDomain,
                    dcBox == null ? String.Empty : dcBox.Text,
                    null,
                    null))
                {
                int miiValue;
                if (HealthDiagnosticsService.HasMachineIdentityIsolationEnabled(out miiValue) && miiValue == 2)
                {
                    DialogResult miiChoice = MessageBox.Show(
                        this,
                        "Machine Identity Isolation is currently in Enforcement mode.\r\n\r\n" +
                        "On unsupported or affected configurations this can prevent the machine secure channel from working correctly.\r\n\r\n" +
                        "Yes = disable MII locally and restart before attempting trust repair\r\n" +
                        "No = keep MII enabled and continue with trust repair\r\n" +
                        "Cancel = stop",
                        "Machine Identity Isolation detected",
                        MessageBoxButtons.YesNoCancel,
                        MessageBoxIcon.Warning);

                    if (miiChoice == DialogResult.Cancel)
                        return;

                    if (miiChoice == DialogResult.Yes)
                    {
                        CreatePreChangeBundle(
                            "mii-disable",
                            joinedDomain,
                            null,
                            null);

                        string miiDetails;
                        if (!HealthDiagnosticsService.DisableMachineIdentityIsolationLocally(out miiDetails))
                        {
                            Log("ERROR", miiDetails);
                            MessageBox.Show(this, miiDetails, "Unable to change MII", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            return;
                        }

                        Log("SUCCESS", miiDetails);
                        string resumeError;
                        ResumeService.RegisterPostRebootCheck(joinedDomain, out resumeError);
                        if (!String.IsNullOrWhiteSpace(resumeError))
                            Log("WARN", "Unable to register post-reboot recovery check: " + resumeError);

                        MessageBox.Show(
                            this,
                            miiDetails + "\r\n\r\n" +
                            "Restart Windows before trust repair/rejoin. If Group Policy or Intune manages MII, update the central policy as well.",
                            "Machine Identity Isolation disabled locally",
                            MessageBoxButtons.OK,
                            MessageBoxIcon.Information);
                        AskRestart("Machine Identity Isolation was disabled locally.");
                        return;
                    }
                }

                Log("INFO", "Starting native secure-channel repair attempt for the currently joined domain.");

                NativeMethods.NetlogonControl(NativeMethods.NETLOGON_CONTROL_REDISCOVER, 2, joinedDomain);
                TrustCheckResult verifyAfterRediscover = NativeMethods.VerifySecureChannel(joinedDomain);
                if (verifyAfterRediscover.Healthy)
                {
                    Log("SUCCESS", "Secure channel recovered after DC rediscovery.");
                    RefreshStatus(false);
                    return;
                }

                int passwordChangeStatus = NativeMethods.NetlogonControl(NativeMethods.NETLOGON_CONTROL_CHANGE_PASSWORD, 1, joinedDomain);
                Log(passwordChangeStatus == 0 ? "INFO" : "WARN",
                    "Native machine-password refresh returned: " + NativeMethods.FormatError(passwordChangeStatus));

                NativeMethods.NetlogonControl(NativeMethods.NETLOGON_CONTROL_REDISCOVER, 2, joinedDomain);
                TrustCheckResult verifyAfterPassword = NativeMethods.VerifySecureChannel(joinedDomain);
                if (verifyAfterPassword.Healthy)
                {
                    Log("SUCCESS", "Secure channel repaired successfully.");
                    RefreshStatus(false);
                    AskRestart("Secure channel was repaired successfully.");
                    return;
                }

                Log("WARN", "Native trust repair did not restore the secure channel.");

                string targetDomain;
                if (!TryGetTargetDomain(out targetDomain))
                    targetDomain = joinedDomain;

                DialogResult answer = MessageBox.Show(
                    this,
                    "Secure-channel repair did not succeed.\r\n\r\nTry Join/Rejoin to " + targetDomain + " using the CURRENT computer name?\r\n\r\nIf the join is blocked by an existing computer object, the tool can then delete that exact object and retry, use a new computer name, or cancel.",
                    "Repair failed",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (answer == DialogResult.Yes)
                    JoinCurrentNameWorkflowInternal(targetDomain);
                }
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void JoinCurrentNameWorkflow()
        {
            if (!EnsureElevatedForGui("join"))
                return;

            SetBusy(true);
            try
            {
                string targetDomain;
                if (!TryGetTargetDomain(out targetDomain))
                    return;

                JoinCurrentNameWorkflowInternal(targetDomain);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void JoinCurrentNameWorkflowInternal(string targetDomain)
        {
            string pendingName;
            if (HasPendingRename(out pendingName))
            {
                MessageBox.Show(this,
                    "A computer rename is already pending: " + pendingName + "\r\n\r\nRestart Windows before Join/Rejoin so the active computer name and Active Directory account stay consistent.",
                    "Restart required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                Log("WARN", "Join/Rejoin blocked because a computer rename is pending: " + pendingName);
                return;
            }

            string user;
            string password;
            if (!GetCredentials(out user, out password))
                return;

            targetDomain = ResolveDomainForOperation(targetDomain, user);
            if (String.IsNullOrWhiteSpace(targetDomain))
                return;

            string currentName = Environment.MachineName;
            using (RecoverySnapshotScope snapshot = new RecoverySnapshotScope(
                "join-rejoin",
                targetDomain,
                dcBox == null ? String.Empty : dcBox.Text,
                user,
                password))
            {
            Log("INFO", "Attempting Join/Rejoin with the current computer name '" + currentName + "'.");

            int status = NativeMethods.JoinDomain(targetDomain, user, password, false);
            if (status == NativeMethods.NERR_Success)
            {
                Log("SUCCESS", "Join/Rejoin succeeded with the current computer name.");
                AskRestart("Domain Join/Rejoin completed successfully.");
                return;
            }

            Log("ERROR", "Join/Rejoin with current name failed: " + NativeMethods.FormatError(status));

            bool existingAccount = false;
            bool nameConflict = status == NativeMethods.NERR_UserExists || status == NativeMethods.NERR_AccountReuseBlockedByPolicy;

            if (!nameConflict && status == NativeMethods.ERROR_ACCESS_DENIED)
            {
                bool? adExists = ComputerAccountExists(currentName, user, password, targetDomain);
                if (adExists.HasValue && adExists.Value)
                {
                    existingAccount = true;
                    nameConflict = true;
                    Log("WARN", "Access was denied and the same computer account was confirmed to exist in Active Directory.");
                }
            }

            if (status == NativeMethods.NERR_UserExists || status == NativeMethods.NERR_AccountReuseBlockedByPolicy)
                existingAccount = true;

            if (nameConflict)
            {
                string reason;
                if (status == NativeMethods.NERR_AccountReuseBlockedByPolicy)
                    reason = "An account with the same computer name exists in Active Directory and Windows blocked account reuse by security policy.";
                else if (status == NativeMethods.NERR_UserExists)
                    reason = "A computer account with the same name already exists in Active Directory.";
                else if (existingAccount)
                    reason = "A computer account with the same name exists in Active Directory and the supplied account does not have permission to reuse it.";
                else
                    reason = "The current computer name could not be reused in Active Directory.";

                Log("WARN", reason);

                AdComputerAccountInfo account = FindComputerAccount(currentName, user, password, targetDomain);
                bool canDelete = account.LookupSucceeded && account.Exists && !String.IsNullOrWhiteSpace(account.LdapPath);

                AccountConflictChoice choice = AccountConflictDialog.ShowDialog(
                    this,
                    currentName,
                    reason,
                    account,
                    canDelete);

                if (choice == AccountConflictChoice.SafeFixesAndRetry)
                    SafeFixesAndRetryJoin(currentName, user, password, targetDomain);
                else if (choice == AccountConflictChoice.DeleteAndRetry)
                    DeleteExistingAccountAndRetryJoin(currentName, user, password, targetDomain, account);
                else if (choice == AccountConflictChoice.RenameAndJoin)
                    RenameAndJoinWorkflow(currentName, user, password, targetDomain);

                return;
            }

            MessageBox.Show(this,
                "Join/Rejoin failed. The failure does not prove that the computer name already exists.\r\n\r\n" +
                "Error: " + NativeMethods.FormatError(status) + "\r\n\r\n" +
                "Check: C:\\Windows\\Debug\\NetSetup.log",
                "Domain join failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            }
        }

        private void SafeFixesAndRetryJoin(string computerName, string user, string password, string targetDomain)
        {
            using (RecoverySnapshotScope snapshot = new RecoverySnapshotScope(
                "safe-fixes-retry",
                targetDomain,
                dcBox == null ? String.Empty : dcBox.Text,
                user,
                password))
            {
            Log("INFO", "Running non-destructive Safe Fixes before retrying Join/Rejoin with the same computer name.");
            SafeRecoveryResult safe = SafeRecoveryService.Run(targetDomain);
            foreach (string step in safe.Steps)
                Log(step.StartsWith("OK:", StringComparison.OrdinalIgnoreCase) ? "INFO" : "WARN", step);

            NativeMethods.DiscoverDomain(targetDomain, true);
            int status = NativeMethods.JoinDomain(targetDomain, user, password, false);

            if (status == NativeMethods.NERR_Success)
            {
                Log("SUCCESS", "Join/Rejoin succeeded after Safe Fixes using the existing computer name.");
                AskRestart("Safe Fixes completed and Join/Rejoin succeeded with the existing computer name.");
                return;
            }

            Log("ERROR", "Join/Rejoin still failed after Safe Fixes: " + NativeMethods.FormatError(status));
            ReportDialog.ShowReport(
                this,
                "Safe retry did not succeed",
                SafeRecoveryService.ToText(safe) + "\r\n\r\n" +
                "Join/Rejoin error: " + NativeMethods.FormatError(status) + "\r\n\r\n" +
                "No AD computer object was deleted. Use Advanced Diagnostics / Recovery Plan before considering Delete + Recreate.");
            }
        }

        private string ResolveDomainForOperation(string targetDomain, string user)
        {
            string candidate = (targetDomain ?? String.Empty).Trim();
            if (String.IsNullOrWhiteSpace(candidate))
                candidate = ExtractDomainHintFromUser(user);

            if (String.IsNullOrWhiteSpace(candidate))
            {
                MessageBox.Show(this,
                    "Enter a target domain. Use a DNS name such as example.com, or a NetBIOS domain name if DNS discovery is available.",
                    "Target domain required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                domainBox.Focus();
                return null;
            }

            DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(candidate, true);
            if (resolved.Success && !String.IsNullOrWhiteSpace(resolved.DnsDomainName))
            {
                SetDomainBox(resolved.DnsDomainName, "Validated by domain controller discovery", true);
                Log("INFO", "Target domain validated by domain controller discovery." + FormatDcSuffix(resolved.DomainControllerName));
                return resolved.DnsDomainName;
            }

            Log("WARN", "Domain controller discovery did not validate the target domain: " + NativeMethods.FormatError(resolved.StatusCode));
            return candidate;
        }

        private bool TryGetTargetDomain(out string targetDomain)
        {
            targetDomain = (domainBox.Text ?? String.Empty).Trim();
            if (!String.IsNullOrWhiteSpace(targetDomain))
                return true;

            string hint = ExtractDomainHintFromUser(userBox.Text);
            if (!String.IsNullOrWhiteSpace(hint))
            {
                DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(hint, false);
                targetDomain = resolved.Success && !String.IsNullOrWhiteSpace(resolved.DnsDomainName) ? resolved.DnsDomainName : hint;
                SetDomainBox(targetDomain, resolved.Success ? "Derived from entered user / DC discovery" : "Derived from entered user", true);
                return true;
            }

            MessageBox.Show(this,
                "The target domain could not be detected automatically.\r\n\r\nEnter the domain in the Target domain field, for example: example.com",
                "Target domain required",
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            domainBox.Focus();
            return false;
        }

        private static string ExtractDomainHintFromUser(string user)
        {
            return DomainValidation.ExtractDomainHintFromUser(user);
        }

        private void RenameAndJoinWorkflow(string currentName, string user, string password, string targetDomain)
        {
            string pendingName;
            if (HasPendingRename(out pendingName))
            {
                MessageBox.Show(this,
                    "A computer rename is already pending: " + pendingName + "\r\n\r\nRestart Windows before trying another rename.",
                    "Pending rename",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            string suggested = CreateSuggestedName(currentName);

            while (true)
            {
                string newName = NewNameDialog.ShowDialog(this, currentName, suggested);
                if (newName == null)
                    return;

                string validationError = ValidateComputerName(newName);
                if (validationError != null)
                {
                    MessageBox.Show(this, validationError, "Invalid computer name", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                    suggested = newName;
                    continue;
                }

                bool? exists = ComputerAccountExists(newName, user, password, targetDomain);
                if (exists.HasValue && exists.Value)
                {
                    MessageBox.Show(this,
                        "The computer account '" + newName + "$' already exists in Active Directory. Choose another name.",
                        "Name already exists",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                    suggested = CreateSuggestedName(newName);
                    continue;
                }

                CreatePreChangeBundle(
                    "rename-and-join",
                    targetDomain,
                    user,
                    password);

                using (RecoverySnapshotScope snapshot = new RecoverySnapshotScope(
                    "rename-and-join",
                    targetDomain,
                    dcBox == null ? String.Empty : dcBox.Text,
                    user,
                    password))
                {
                Log("INFO", "Setting pending computer name to '" + newName + "'.");
                int renameError;
                if (!NativeMethods.SetPendingComputerName(newName, out renameError))
                {
                    Log("ERROR", "SetComputerNameEx failed: " + NativeMethods.FormatError(renameError));
                    MessageBox.Show(this,
                        "Unable to set the new computer name.\r\n\r\n" + NativeMethods.FormatError(renameError),
                        "Rename failed",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error);
                    return;
                }

                Log("INFO", "Attempting domain join with pending new name '" + newName + "'.");
                int joinStatus = NativeMethods.JoinDomain(targetDomain, user, password, true);

                if (joinStatus == NativeMethods.NERR_Success)
                {
                    Log("SUCCESS", "Rename + domain join succeeded. New name after reboot: " + newName);
                    AskRestart("Rename and domain join completed successfully.\r\n\r\nNew computer name after restart: " + newName);
                    return;
                }

                Log("ERROR", "Rename + domain join failed: " + NativeMethods.FormatError(joinStatus));

                int rollbackError;
                bool rollbackOk = NativeMethods.SetPendingComputerName(currentName, out rollbackError);
                if (rollbackOk)
                    Log("INFO", "Pending computer name was rolled back to '" + currentName + "'.");
                else
                    Log("WARN", "Unable to roll back the pending computer name: " + NativeMethods.FormatError(rollbackError));

                MessageBox.Show(this,
                    "Rename + domain join failed.\r\n\r\nError: " + NativeMethods.FormatError(joinStatus) + "\r\n\r\nCheck C:\\Windows\\Debug\\NetSetup.log",
                    "Domain join failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
                }
            }
        }

        private bool GetCredentials(out string user, out string password)
        {
            user = String.Empty;
            password = passwordBox.Text;

            string validationError;
            if (!TryValidateUserName(userBox.Text, out user, out validationError))
            {
                MessageBox.Show(this,
                    validationError + "\r\n\r\nUse one of these formats:\r\nDOMAIN\\username\r\nusername@example.com",
                    "Domain user format",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                userBox.Focus();
                return false;
            }

            if (String.IsNullOrEmpty(password))
            {
                MessageBox.Show(this,
                    "Enter the password for the domain user.",
                    "Credentials required",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                passwordBox.Focus();
                return false;
            }

            userBox.Text = user;
            return true;
        }

        private static bool TryValidateUserName(string input, out string normalized, out string error)
        {
            return DomainValidation.TryValidateUserName(input, out normalized, out error);
        }

        private bool? ComputerAccountExists(string computerName, string user, string password, string targetDomain)
        {
            AdComputerAccountInfo info = FindComputerAccount(computerName, user, password, targetDomain);
            if (!info.LookupSucceeded)
                return null;
            return info.Exists;
        }

        private AdComputerAccountInfo FindComputerAccount(string computerName, string user, string password, string targetDomain)
        {
            return AdDirectoryService.FindComputerAccount(
                computerName,
                user,
                password,
                targetDomain,
                dcBox == null ? String.Empty : dcBox.Text,
                Log);
        }

        private static string FormatAdAccountReport(string computerName, string targetDomain, AdComputerAccountInfo account)
        {
            StringBuilder report = new StringBuilder();
            report.AppendLine("Active Directory computer account: FOUND");
            report.AppendLine();
            report.AppendLine("Computer:           " + computerName);
            report.AppendLine("Domain:             " + targetDomain);
            report.AppendLine("Distinguished name: " + FirstNonEmpty(account.DistinguishedName, "(not returned)"));
            report.AppendLine("DNS host name:      " + FirstNonEmpty(account.DnsHostName, "(not set)"));
            report.AppendLine("Enabled:            " + (account.Enabled.HasValue ? (account.Enabled.Value ? "Yes" : "No") : "(unknown)"));
            report.AppendLine("Operating system:   " + FirstNonEmpty(account.OperatingSystem, "(not set)"));
            report.AppendLine("Description:        " + FirstNonEmpty(account.Description, "(not set)"));
            report.AppendLine("Object GUID:        " + FirstNonEmpty(account.ObjectGuid, "(not returned)"));
            report.AppendLine("Created:            " + FirstNonEmpty(account.WhenCreated, "(not returned)"));
            report.AppendLine("Changed:            " + FirstNonEmpty(account.WhenChanged, "(not returned)"));
            report.AppendLine("Owner:              " + FirstNonEmpty(account.Owner, "(not returned)"));
            report.AppendLine("pwdLastSet:         " + FirstNonEmpty(account.PwdLastSet, "(not returned)"));
            report.AppendLine("Last logon:         " + FirstNonEmpty(account.LastLogonTimestamp, "(not returned)"));
            report.AppendLine("Canonical name:     " + FirstNonEmpty(account.CanonicalName, "(not returned)"));
            report.AppendLine("SPN count:          " + account.ServicePrincipalNameCount);
            report.AppendLine("Child objects:      " + account.ChildObjectCount);
            report.AppendLine("Encryption types:   " + (account.SupportedEncryptionTypes.HasValue ? account.SupportedEncryptionTypes.Value.ToString() : "(unknown)"));
            if (!String.IsNullOrWhiteSpace(account.ServicePrincipalNames))
                report.AppendLine("SPNs:               " + account.ServicePrincipalNames);
            report.AppendLine();
            report.AppendLine("This was a read-only check. No changes were made.");
            return report.ToString();
        }

        private void DeleteExistingAccountAndRetryJoin(string computerName, string user, string password, string targetDomain, AdComputerAccountInfo account)
        {
            if (account == null || !account.LookupSucceeded || !account.Exists || String.IsNullOrWhiteSpace(account.LdapPath))
            {
                MessageBox.Show(this,
                    "The existing Active Directory computer account could not be located reliably, so it will not be deleted.",
                    "Delete unavailable",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return;
            }

            DeleteSafetyResult deleteSafety = DeleteSafetyAnalyzer.Analyze(
                targetDomain,
                dcBox == null ? String.Empty : dcBox.Text,
                computerName,
                user,
                password,
                account);

            if (!deleteSafety.Allowed)
            {
                ReportDialog.ShowReport(
                    this,
                    "AD Delete BLOCKED",
                    DeleteSafetyAnalyzer.ToText(deleteSafety));
                Log("WARN", "AD computer account deletion blocked by the safety gate.");
                return;
            }

            string dn = String.IsNullOrWhiteSpace(account.DistinguishedName) ? computerName + "$" : account.DistinguishedName;

            DialogResult confirm = MessageBox.Show(this,
                "Delete this computer account from Active Directory?\r\n\r\n" +
                dn + "\r\n\r\n" +
                "Owner: " + FirstNonEmpty(account.Owner, "(unknown)") + "\r\n" +
                "pwdLastSet: " + FirstNonEmpty(account.PwdLastSet, "(unknown)") + "\r\n" +
                "SPNs: " + account.ServicePrincipalNameCount + "\r\n" +
                "Child objects: " + account.ChildObjectCount + "\r\n\r\n" +
                "WARNING: This permanently deletes the AD computer object and data stored on or below that object. Depending on the environment, this may include recovery information such as LAPS data or BitLocker recovery child objects.\r\n\r\n" +
                "After deletion, the tool will retry Join/Rejoin using the SAME computer name.\r\n\r\nContinue?",
                "Confirm AD computer deletion",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes)
                return;

            CreatePreChangeBundle(
                "delete-and-recreate",
                targetDomain,
                user,
                password);

            using (RecoverySnapshotScope snapshot = new RecoverySnapshotScope(
                "delete-and-recreate",
                targetDomain,
                dcBox == null ? String.Empty : dcBox.Text,
                user,
                password))
            {
            string deleteError;
            if (!AdDirectoryService.DeleteComputerAccount(account, computerName, user, password, Log, out deleteError))
            {
                MessageBox.Show(this,
                    "The Active Directory computer account could not be deleted safely.\r\n\r\n" +
                    deleteError + "\r\n\r\n" +
                    "The entered domain account may not have permission to delete computer objects.",
                    "Delete failed",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
                return;
            }

            int[] retryDelays = new int[] { 2, 4, 8, 12 };
            int status = NativeMethods.ERROR_ACCESS_DENIED;

            for (int attempt = 0; attempt < retryDelays.Length; attempt++)
            {
                int delay = retryDelays[attempt];
                Log("INFO", "Waiting " + delay + " second(s) before Join/Rejoin retry " + (attempt + 1) + " of " + retryDelays.Length + " to allow AD replication.");
                System.Threading.Thread.Sleep(delay * 1000);

                NativeMethods.DiscoverDomain(targetDomain, true);
                status = NativeMethods.JoinDomain(targetDomain, user, password, false);

                if (status == NativeMethods.NERR_Success)
                {
                    Log("SUCCESS", "Join/Rejoin succeeded after deleting and recreating the AD computer account.");
                    AskRestart("The old AD computer account was deleted and the computer was joined to the domain again successfully.");
                    return;
                }

                Log("WARN", "Join/Rejoin retry " + (attempt + 1) + " failed: " + NativeMethods.FormatError(status));

                if (status != NativeMethods.NERR_UserExists &&
                    status != NativeMethods.NERR_AccountReuseBlockedByPolicy &&
                    status != NativeMethods.ERROR_ACCESS_DENIED &&
                    status != NativeMethods.ERROR_NO_LOGON_SERVERS &&
                    status != NativeMethods.ERROR_NO_SUCH_DOMAIN)
                    break;
            }

            Log("ERROR", "Join/Rejoin after AD account deletion failed after retry/backoff: " + NativeMethods.FormatError(status));

            if (status == NativeMethods.NERR_UserExists || status == NativeMethods.NERR_AccountReuseBlockedByPolicy || status == NativeMethods.ERROR_ACCESS_DENIED)
            {
                DialogResult rename = MessageBox.Show(this,
                    "The old account was deleted, but Join/Rejoin still failed. This can happen while the deletion is replicating or if another same-name account is still visible to the selected domain controller.\r\n\r\n" +
                    "Error: " + NativeMethods.FormatError(status) + "\r\n\r\n" +
                    "Do you want to try a NEW computer name now?",
                    "Join retry failed",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning);

                if (rename == DialogResult.Yes)
                    RenameAndJoinWorkflow(computerName, user, password, targetDomain);
                return;
            }

            MessageBox.Show(this,
                "The AD account was deleted, but Join/Rejoin failed.\r\n\r\n" +
                "Error: " + NativeMethods.FormatError(status) + "\r\n\r\n" +
                "Check C:\\Windows\\Debug\\NetSetup.log",
                "Domain join failed",
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            }
        }

        private static string EscapeLdapFilterValue(string value)
        {
            return DomainValidation.EscapeLdapFilterValue(value);
        }

        private static string ValidateComputerName(string name)
        {
            return DomainValidation.ValidateComputerName(name);
        }

        private static string CreateSuggestedName(string currentName)
        {
            return DomainValidation.CreateSuggestedName(currentName);
        }

        private static bool HasPendingRename(out string pendingName)
        {
            return DiagnosticsService.HasPendingRename(out pendingName);
        }

        private void AskRestart(string message)
        {
            DialogResult answer = MessageBox.Show(this,
                message + "\r\n\r\nRestart Windows now?",
                "Restart required",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Information);

            if (answer == DialogResult.Yes)
                RestartWindows();
        }

        private void RestartWindows()
        {
            if (!EnsureElevatedForGui("restart"))
                return;

            try
            {
                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "shutdown.exe";
                psi.Arguments = "/r /t 15 /c \"Domain membership repair operation completed. Restarting Windows.\"";
                psi.UseShellExecute = false;
                psi.CreateNoWindow = true;
                Process.Start(psi);
                Log("INFO", "Windows restart scheduled in 15 seconds.");
                MessageBox.Show(this,
                    "Windows will restart in 15 seconds.\r\n\r\nTo cancel: shutdown /a",
                    "Restart scheduled",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Unable to schedule restart: " + ex.Message);
                MessageBox.Show(this, ex.Message, "Restart failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void SetBusy(bool busy)
        {
            UseWaitCursor = busy;
            if (detectButton != null) detectButton.Enabled = !busy;
            if (checkButton != null) checkButton.Enabled = !busy;
            if (repairButton != null) repairButton.Enabled = !busy;
            if (joinButton != null) joinButton.Enabled = !busy;
            if (adCheckButton != null) adCheckButton.Enabled = !busy;
            if (diagnosticsButton != null) diagnosticsButton.Enabled = !busy;
            if (copyDiagnosticsButton != null) copyDiagnosticsButton.Enabled = !busy;
            if (exportButton != null) exportButton.Enabled = !busy;
            if (advancedButton != null) advancedButton.Enabled = !busy;
            if (recoveryPlanButton != null) recoveryPlanButton.Enabled = !busy;
            if (dcMatrixButton != null) dcMatrixButton.Enabled = !busy;
            if (supportBundleButton != null) supportBundleButton.Enabled = !busy;
            if (cyberArkButton != null) cyberArkButton.Enabled = !busy;
            if (offlineJoinButton != null) offlineJoinButton.Enabled = !busy;
            if (safeFixesButton != null) safeFixesButton.Enabled = !busy;
            if (selfTestButton != null) selfTestButton.Enabled = !busy;
            if (siteSubnetButton != null) siteSubnetButton.Enabled = !busy;
            if (protocolsButton != null) protocolsButton.Enabled = !busy;
            if (hardeningButton != null) hardeningButton.Enabled = !busy;
            if (joinPermissionsButton != null) joinPermissionsButton.Enabled = !busy;
            if (hybridEntraButton != null) hybridEntraButton.Enabled = !busy;
            if (policySourceButton != null) policySourceButton.Enabled = !busy;
            if (replicationMetadataButton != null) replicationMetadataButton.Enabled = !busy;
            if (spnCollisionsButton != null) spnCollisionsButton.Enabled = !busy;
            if (smbKerberosButton != null) smbKerberosButton.Enabled = !busy;
            if (restartButton != null) restartButton.Enabled = !busy;
            if (aboutButton != null) aboutButton.Enabled = !busy;
            Application.DoEvents();
        }

        private void Log(string level, string message)
        {
            string line = "[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] [" + level + "] " + message;
            if (logBox != null)
            {
                logBox.AppendText(line + Environment.NewLine);
                logBox.SelectionStart = logBox.TextLength;
                logBox.ScrollToCaret();
            }

            if (fileLogBox == null || !fileLogBox.Checked)
                return;

            try
            {
                string directory = Path.GetDirectoryName(LogFile);
                if (!Directory.Exists(directory))
                    Directory.CreateDirectory(directory);
                File.AppendAllText(LogFile, line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
            }
        }

        private static string FirstNonEmpty(string first, string second)
        {
            return !String.IsNullOrWhiteSpace(first) ? first : (second ?? String.Empty);
        }

        private static string FormatDcSuffix(string dc)
        {
            return String.IsNullOrWhiteSpace(dc) ? String.Empty : " DC: " + dc;
        }
    }
}
