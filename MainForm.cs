using System;
using System.Diagnostics;
using System.DirectoryServices;
using System.Drawing;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class MainForm : Form
    {
        private const string LogFile = @"C:\Windows\Logs\DomainMembershipRepair.log";

        private TextBox domainBox;
        private Label domainSourceValue;
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
        private Button restartButton;
        private TextBox logBox;
        private CheckBox fileLogBox;
        private readonly bool initialFileLogging;

        private string joinedDomain = String.Empty;
        private bool settingDomainBox;
        private bool domainManuallyEdited;

        internal MainForm(bool enableFileLogging)
        {
            initialFileLogging = enableFileLogging;
            Text = "Domain Membership Check & Repair v" + BuildInfo.Version;
            Width = 900;
            Height = 720;
            StartPosition = FormStartPosition.CenterScreen;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = true;
            Font = new Font("Segoe UI", 9F);

            BuildUi();
            RefreshStatus(true);
        }

        private void BuildUi()
        {
            TableLayoutPanel root = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.Padding = new Padding(14);
            root.ColumnCount = 2;
            root.RowCount = 11;
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 170F));
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
            domainPanel.RowCount = 2;
            domainPanel.Margin = new Padding(0);
            domainPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            domainPanel.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 125F));
            domainPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 27F));
            domainPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 20F));

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
            detectButton.Height = 25;
            detectButton.Margin = new Padding(8, 0, 0, 0);
            detectButton.Click += delegate { DetectDomain(true); };
            domainPanel.Controls.Add(detectButton, 1, 0);

            domainSourceValue = new Label();
            domainSourceValue.AutoSize = true;
            domainSourceValue.ForeColor = SystemColors.GrayText;
            domainSourceValue.Text = "Auto-detecting...";
            domainPanel.Controls.Add(domainSourceValue, 0, 1);
            domainPanel.SetColumnSpan(domainSourceValue, 2);

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
            passwordPanel.WrapContents = false;

            passwordBox = new TextBox();
            passwordBox.Width = 390;
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

            FlowLayoutPanel actions = new FlowLayoutPanel();
            actions.Dock = DockStyle.Fill;
            actions.AutoSize = true;
            actions.WrapContents = true;

            checkButton = CreateButton("Check Trust", 120);
            diagnosticsButton = CreateButton("Diagnostics", 120);
            repairButton = CreateButton("Repair Trust", 120);
            joinButton = CreateButton("Join / Rejoin Domain", 170);
            adCheckButton = CreateButton("Check AD Account", 150);
            restartButton = CreateButton("Restart Windows", 140);

            checkButton.Click += delegate { RefreshStatus(false); };
            diagnosticsButton.Click += delegate { DiagnosticsWorkflow(); };
            repairButton.Click += delegate { RepairTrustWorkflow(); };
            joinButton.Click += delegate { JoinCurrentNameWorkflow(); };
            adCheckButton.Click += delegate { CheckAdAccountWorkflow(); };
            restartButton.Click += delegate { RestartWindows(); };

            actions.Controls.Add(checkButton);
            actions.Controls.Add(diagnosticsButton);
            actions.Controls.Add(repairButton);
            actions.Controls.Add(joinButton);
            actions.Controls.Add(adCheckButton);
            actions.Controls.Add(restartButton);

            root.Controls.Add(actions, 0, 7);
            root.SetColumnSpan(actions, 2);

            Label note = new Label();
            note.Text = "The target domain is detected automatically when possible and remains editable. Check AD Account is read-only. If Join/Rejoin is blocked by an existing AD computer object, the tool can delete that exact object and retry the same name, use a new name, or cancel.";
            note.AutoSize = true;
            note.MaximumSize = new Size(790, 0);
            root.Controls.Add(note, 0, 8);
            root.SetColumnSpan(note, 2);

            FlowLayoutPanel fileLogPanel = new FlowLayoutPanel();
            fileLogPanel.Dock = DockStyle.Fill;
            fileLogPanel.FlowDirection = FlowDirection.LeftToRight;
            fileLogPanel.WrapContents = false;
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

            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 38F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 52F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 50F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 38F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 84F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 62F));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 34F));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

            Controls.Add(root);
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
            button.Width = width;
            button.Height = 32;
            return button;
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
                StringBuilder report = new StringBuilder();
                report.AppendLine("Domain Membership Check & Repair diagnostics");
                report.AppendLine("Generated: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
                report.AppendLine();
                report.AppendLine("Computer:          " + Environment.MachineName);
                report.AppendLine("Architecture:      " + BuildInfo.RuntimeSummary);
                report.AppendLine("Physical DNS:      " + FirstNonEmpty(NativeMethods.GetPhysicalDnsDomain(), "(none)"));

                string pendingName;
                report.AppendLine("Pending rename:    " + (HasPendingRename(out pendingName) ? pendingName : "No"));

                JoinInformation join = NativeMethods.GetJoinInformation();
                if (join.StatusCode != NativeMethods.NERR_Success)
                {
                    report.AppendLine("Membership:        Unknown - " + NativeMethods.FormatError(join.StatusCode));
                }
                else if (join.Status == NetJoinStatus.NetSetupDomainName && !String.IsNullOrWhiteSpace(join.Name))
                {
                    report.AppendLine("Membership:        Domain - " + join.Name);
                    TrustCheckResult trust = NativeMethods.VerifySecureChannel(join.Name);
                    report.AppendLine("Secure channel:    " + (trust.Healthy ? "OK" : "BROKEN - " + NativeMethods.FormatError(trust.StatusCode)));
                    report.AppendLine("Trusted DC:        " + FirstNonEmpty(trust.TrustedDc, "(not returned)"));
                }
                else
                {
                    report.AppendLine("Membership:        Not joined (" + join.Status + ")");
                    report.AppendLine("Secure channel:    Not applicable");
                }

                string target = (domainBox.Text ?? String.Empty).Trim();
                if (String.IsNullOrWhiteSpace(target))
                {
                    JoinInformation current = NativeMethods.GetJoinInformation();
                    if (current.StatusCode == 0 && current.Status == NetJoinStatus.NetSetupDomainName)
                        target = current.Name;
                    if (String.IsNullOrWhiteSpace(target))
                        target = NativeMethods.GetPhysicalDnsDomain();
                    if (String.IsNullOrWhiteSpace(target))
                        target = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
                }

                report.AppendLine("Target domain:     " + (String.IsNullOrWhiteSpace(target) ? "(not detected)" : target));
                if (!String.IsNullOrWhiteSpace(target))
                {
                    DomainDiscoveryResult discovery = NativeMethods.DiscoverDomain(target, true);
                    report.AppendLine("DC discovery:      " + (discovery.Success ? "OK" : NativeMethods.FormatError(discovery.StatusCode)));
                    if (discovery.Success)
                    {
                        report.AppendLine("DNS domain:        " + FirstNonEmpty(discovery.DnsDomainName, "(not returned)"));
                        report.AppendLine("Domain controller: " + FirstNonEmpty(discovery.DomainControllerName, "(not returned)"));
                        report.AppendLine("Forest:            " + FirstNonEmpty(discovery.ForestName, "(not returned)"));
                    }
                }

                string netSetupLog = @"C:\Windows\Debug\NetSetup.log";
                if (File.Exists(netSetupLog))
                {
                    FileInfo fi = new FileInfo(netSetupLog);
                    report.AppendLine("NetSetup.log:       Present; modified " + fi.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"));
                }
                else
                {
                    report.AppendLine("NetSetup.log:       Not present");
                }

                Log("INFO", "Diagnostics completed. " + BuildInfo.RuntimeSummary);
                ReportDialog.ShowReport(this, "Diagnostics", report.ToString());
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
                AdComputerAccountInfo account = FindComputerAccount(computerName, user, password, targetDomain);

                if (!account.LookupSucceeded)
                {
                    ReportDialog.ShowReport(this, "AD computer account check",
                        "The Active Directory lookup could not be completed.\r\n\r\n" +
                        "Computer: " + computerName + "\r\n" +
                        "Domain:   " + targetDomain + "\r\n\r\n" +
                        "No changes were made.");
                    return;
                }

                if (!account.Exists)
                {
                    ReportDialog.ShowReport(this, "AD computer account check",
                        "Computer account NOT FOUND.\r\n\r\n" +
                        "Computer: " + computerName + "\r\n" +
                        "Domain:   " + targetDomain + "\r\n\r\n" +
                        "This was a read-only check. No changes were made.");
                    return;
                }

                ReportDialog.ShowReport(this, "AD computer account check", FormatAdAccountReport(computerName, targetDomain, account));
            }
            finally
            {
                SetBusy(false);
            }
        }

        private void RepairTrustWorkflow()
        {
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
            finally
            {
                SetBusy(false);
            }
        }

        private void JoinCurrentNameWorkflow()
        {
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
                    canDelete ? account.DistinguishedName : null,
                    canDelete);

                if (choice == AccountConflictChoice.DeleteAndRetry)
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
            if (String.IsNullOrWhiteSpace(user))
                return String.Empty;

            string value = user.Trim();
            int slash = value.IndexOf('\\');
            int at = value.LastIndexOf('@');

            if (slash > 0)
                return value.Substring(0, slash).Trim();
            if (at > 0 && at < value.Length - 1)
                return value.Substring(at + 1).Trim();

            return String.Empty;
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
            normalized = String.Empty;
            error = null;

            if (String.IsNullOrWhiteSpace(input))
            {
                error = "Enter a domain user.";
                return false;
            }

            string value = input.Trim();
            int slash = value.IndexOf('\\');
            int at = value.IndexOf('@');

            if (slash > 0 && slash < value.Length - 1 && at < 0)
            {
                string domainPart = value.Substring(0, slash).Trim();
                string userPart = value.Substring(slash + 1).Trim();
                if (domainPart.Length == 0 || userPart.Length == 0 || userPart.IndexOf('\\') >= 0)
                {
                    error = "The DOMAIN\\username value is not valid.";
                    return false;
                }

                normalized = domainPart + "\\" + userPart;
                return true;
            }

            if (at > 0 && at < value.Length - 1 && slash < 0 && value.IndexOf('@', at + 1) < 0)
            {
                string userPart = value.Substring(0, at).Trim();
                string domainPart = value.Substring(at + 1).Trim();
                if (userPart.Length == 0 || domainPart.Length == 0)
                {
                    error = "The username@domain value is not valid.";
                    return false;
                }

                normalized = userPart + "@" + domainPart;
                return true;
            }

            error = "Do not enter only a short username.";
            return false;
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
            AdComputerAccountInfo info = new AdComputerAccountInfo();

            try
            {
                string ldapDomain = targetDomain;
                DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(targetDomain, false);
                if (resolved.Success && !String.IsNullOrWhiteSpace(resolved.DnsDomainName))
                    ldapDomain = resolved.DnsDomainName;

                using (DirectoryEntry rootDse = new DirectoryEntry("LDAP://" + ldapDomain + "/RootDSE", user, password, AuthenticationTypes.Secure))
                {
                    object namingContextValue = rootDse.Properties["defaultNamingContext"].Value;
                    if (namingContextValue == null)
                    {
                        Log("WARN", "Active Directory did not return defaultNamingContext.");
                        return info;
                    }

                    string namingContext = namingContextValue.ToString();
                    using (DirectoryEntry root = new DirectoryEntry("LDAP://" + ldapDomain + "/" + namingContext, user, password, AuthenticationTypes.Secure))
                    using (DirectorySearcher searcher = new DirectorySearcher(root))
                    {
                        string samAccountName = EscapeLdapFilterValue(computerName + "$");
                        searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=" + samAccountName + "))";
                        searcher.SearchScope = SearchScope.Subtree;
                        searcher.SizeLimit = 1;
                        searcher.PropertiesToLoad.Add("distinguishedName");
                        searcher.PropertiesToLoad.Add("dNSHostName");
                        searcher.PropertiesToLoad.Add("operatingSystem");
                        searcher.PropertiesToLoad.Add("description");
                        searcher.PropertiesToLoad.Add("objectGUID");
                        searcher.PropertiesToLoad.Add("whenCreated");
                        searcher.PropertiesToLoad.Add("whenChanged");
                        searcher.PropertiesToLoad.Add("userAccountControl");

                        SearchResult result = searcher.FindOne();
                        info.LookupSucceeded = true;

                        if (result == null)
                        {
                            info.Exists = false;
                            Log("INFO", "No AD computer account found for the current requested name.");
                            return info;
                        }

                        info.Exists = true;
                        info.LdapPath = result.Path;
                        info.DistinguishedName = GetSearchPropertyString(result, "distinguishedName", computerName + "$");
                        info.DnsHostName = GetSearchPropertyString(result, "dNSHostName", String.Empty);
                        info.OperatingSystem = GetSearchPropertyString(result, "operatingSystem", String.Empty);
                        info.Description = GetSearchPropertyString(result, "description", String.Empty);
                        info.WhenCreated = GetSearchPropertyString(result, "whenCreated", String.Empty);
                        info.WhenChanged = GetSearchPropertyString(result, "whenChanged", String.Empty);

                        if (result.Properties.Contains("objectGUID") && result.Properties["objectGUID"].Count > 0)
                        {
                            byte[] guidBytes = result.Properties["objectGUID"][0] as byte[];
                            if (guidBytes != null && guidBytes.Length == 16)
                                info.ObjectGuid = new Guid(guidBytes).ToString();
                        }

                        if (result.Properties.Contains("userAccountControl") && result.Properties["userAccountControl"].Count > 0)
                        {
                            int uac;
                            if (Int32.TryParse(Convert.ToString(result.Properties["userAccountControl"][0]), out uac))
                                info.Enabled = (uac & 0x0002) == 0;
                        }

                        Log("INFO", "An AD computer account with the requested name exists.");
                        return info;
                    }
                }
            }
            catch (Exception ex)
            {
                Log("WARN", "Unable to query Active Directory for computer account existence: " + ex.Message);
                return info;
            }
        }

        private static string GetSearchPropertyString(SearchResult result, string propertyName, string fallback)
        {
            if (result != null && result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
            {
                object value = result.Properties[propertyName][0];
                if (value is DateTime)
                    return ((DateTime)value).ToString("yyyy-MM-dd HH:mm:ss");
                return Convert.ToString(value) ?? fallback;
            }
            return fallback;
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

            string dn = String.IsNullOrWhiteSpace(account.DistinguishedName) ? computerName + "$" : account.DistinguishedName;

            DialogResult confirm = MessageBox.Show(this,
                "Delete this computer account from Active Directory?\r\n\r\n" +
                dn + "\r\n\r\n" +
                "WARNING: This permanently deletes the AD computer object and data stored on or below that object. Depending on the environment, this may include recovery information such as LAPS data or BitLocker recovery child objects.\r\n\r\n" +
                "After deletion, the tool will retry Join/Rejoin using the SAME computer name.\r\n\r\nContinue?",
                "Confirm AD computer deletion",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Warning,
                MessageBoxDefaultButton.Button2);

            if (confirm != DialogResult.Yes)
                return;

            try
            {
                using (DirectoryEntry target = new DirectoryEntry(account.LdapPath, user, password, AuthenticationTypes.Secure))
                {
                    target.RefreshCache(new string[] { "sAMAccountName", "objectClass", "objectGUID" });
                    string actualSam = Convert.ToString(target.Properties["sAMAccountName"].Value);
                    bool isComputerObject = false;
                    foreach (object value in target.Properties["objectClass"])
                    {
                        if (String.Equals(Convert.ToString(value), "computer", StringComparison.OrdinalIgnoreCase))
                        {
                            isComputerObject = true;
                            break;
                        }
                    }
                    if (!isComputerObject || !String.Equals(actualSam, computerName + "$", StringComparison.OrdinalIgnoreCase))
                        throw new InvalidOperationException("Safety check failed: the LDAP object no longer matches the requested computer account.");

                    if (!String.IsNullOrWhiteSpace(account.ObjectGuid) && target.Properties["objectGUID"].Value is byte[])
                    {
                        string actualGuid = new Guid((byte[])target.Properties["objectGUID"].Value).ToString();
                        if (!String.Equals(actualGuid, account.ObjectGuid, StringComparison.OrdinalIgnoreCase))
                            throw new InvalidOperationException("Safety check failed: the AD object changed after it was looked up. Run the lookup again.");
                    }
                    Log("WARN", "Deleting the confirmed AD computer account: " + dn);
                    target.DeleteTree();
                }

                Log("SUCCESS", "AD computer account deleted.");
            }
            catch (Exception ex)
            {
                Log("ERROR", "Unable to delete the AD computer account: " + ex.Message);
                MessageBox.Show(this,
                    "The Active Directory computer account could not be deleted.\r\n\r\n" +
                    ex.Message + "\r\n\r\n" +
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

        private static string EscapeLdapFilterValue(string value)
        {
            if (value == null)
                return String.Empty;

            StringBuilder sb = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\5c"); break;
                    case '*': sb.Append("\\2a"); break;
                    case '(': sb.Append("\\28"); break;
                    case ')': sb.Append("\\29"); break;
                    case '\0': sb.Append("\\00"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        private static string ValidateComputerName(string name)
        {
            if (String.IsNullOrWhiteSpace(name))
                return "Computer name cannot be empty.";

            name = name.Trim();
            if (name.Length > 15)
                return "Use 15 characters or fewer for maximum NetBIOS/Active Directory compatibility.";

            if (!Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$|^[A-Za-z0-9]$"))
                return "Use only letters, numbers and hyphens. The name cannot start or end with a hyphen.";

            if (Regex.IsMatch(name, "^[0-9]+$"))
                return "The computer name cannot contain only numbers.";

            return null;
        }

        private static string CreateSuggestedName(string currentName)
        {
            string suffix = "-2";
            string baseName = currentName == null ? "PC" : currentName.Trim();
            int maxBase = 15 - suffix.Length;
            if (baseName.Length > maxBase)
                baseName = baseName.Substring(0, maxBase);
            baseName = baseName.TrimEnd('-');
            return baseName + suffix;
        }

        private static bool HasPendingRename(out string pendingName)
        {
            pendingName = null;
            try
            {
                string active;
                string pending;
                using (RegistryKey activeKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ActiveComputerName"))
                using (RegistryKey pendingKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName"))
                {
                    active = activeKey == null ? null : Convert.ToString(activeKey.GetValue("ComputerName"));
                    pending = pendingKey == null ? null : Convert.ToString(pendingKey.GetValue("ComputerName"));
                }

                if (!String.IsNullOrWhiteSpace(active) && !String.IsNullOrWhiteSpace(pending) &&
                    !String.Equals(active, pending, StringComparison.OrdinalIgnoreCase))
                {
                    pendingName = pending;
                    return true;
                }
            }
            catch
            {
            }
            return false;
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
            if (restartButton != null) restartButton.Enabled = !busy;
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
