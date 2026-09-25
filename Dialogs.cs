using System;
using System.Drawing;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal sealed class AccountConflictDialog : Form
    {
        private AccountConflictChoice choice = AccountConflictChoice.Cancel;

        private AccountConflictDialog(string computerName, string reason, AdComputerAccountInfo account, bool canDelete)
        {
            Text = "Computer account conflict";
            Width = 760;
            Height = 510;
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            ShowInTaskbar = false;
            Font = new Font("Segoe UI", 9F);

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.Dock = DockStyle.Fill;
            layout.Padding = new Padding(14);
            layout.ColumnCount = 1;
            layout.RowCount = 4;
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 54F));

            Label message = new Label();
            message.AutoSize = true;
            message.MaximumSize = new Size(710, 0);
            message.Text = reason + "\r\n\r\nComputer: " + computerName;
            layout.Controls.Add(message, 0, 0);

            TextBox details = new TextBox();
            details.Multiline = true;
            details.ReadOnly = true;
            details.ScrollBars = ScrollBars.Vertical;
            details.WordWrap = false;
            details.Dock = DockStyle.Fill;
            details.Font = new Font("Consolas", 9F);

            if (account != null && account.LookupSucceeded && account.Exists)
            {
                details.Text =
                    "Existing AD object\r\n" +
                    "------------------\r\n" +
                    "DN:            " + First(account.DistinguishedName, "(not returned)") + "\r\n" +
                    "Owner:         " + First(account.Owner, "(not returned)") + "\r\n" +
                    "Enabled:       " + (account.Enabled.HasValue ? (account.Enabled.Value ? "Yes" : "No") : "(unknown)") + "\r\n" +
                    "pwdLastSet:    " + First(account.PwdLastSet, "(not returned)") + "\r\n" +
                    "whenChanged:   " + First(account.WhenChanged, "(not returned)") + "\r\n" +
                    "objectGUID:    " + First(account.ObjectGuid, "(not returned)") + "\r\n" +
                    "SPN count:     " + account.ServicePrincipalNameCount + "\r\n" +
                    "Child objects: " + account.ChildObjectCount + "\r\n" +
                    "Canonical:     " + First(account.CanonicalName, "(not returned)");
            }
            else
            {
                details.Text =
                    "The AD computer object could not be located with the supplied credentials.\r\n" +
                    "Delete is unavailable.";
            }

            layout.Controls.Add(details, 0, 1);

            Label warning = new Label();
            warning.AutoSize = true;
            warning.MaximumSize = new Size(710, 0);
            warning.Margin = new Padding(0, 10, 0, 4);
            warning.Text =
                "Recommended order: Safe Fixes + Retry Same Name -> Use New Name -> Delete + Retry only as a last resort. " +
                "Deletion can also remove child recovery data such as LAPS/BitLocker information.";
            layout.Controls.Add(warning, 0, 2);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.Dock = DockStyle.Fill;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.WrapContents = false;

            Button cancel = new Button();
            cancel.Text = "Cancel";
            cancel.Width = 90;
            cancel.Height = 30;
            cancel.Click += delegate
            {
                choice = AccountConflictChoice.Cancel;
                DialogResult = DialogResult.Cancel;
                Close();
            };

            Button delete = new Button();
            delete.Text = "Delete + Retry";
            delete.Width = 120;
            delete.Height = 30;
            delete.Enabled = canDelete;
            delete.Click += delegate
            {
                choice = AccountConflictChoice.DeleteAndRetry;
                DialogResult = DialogResult.OK;
                Close();
            };

            Button rename = new Button();
            rename.Text = "Use New Name";
            rename.Width = 115;
            rename.Height = 30;
            rename.Click += delegate
            {
                choice = AccountConflictChoice.RenameAndJoin;
                DialogResult = DialogResult.OK;
                Close();
            };

            Button safeRetry = new Button();
            safeRetry.Text = "Safe Fixes + Retry Same Name";
            safeRetry.Width = 205;
            safeRetry.Height = 30;
            safeRetry.Click += delegate
            {
                choice = AccountConflictChoice.SafeFixesAndRetry;
                DialogResult = DialogResult.OK;
                Close();
            };

            buttons.Controls.Add(cancel);
            buttons.Controls.Add(delete);
            buttons.Controls.Add(rename);
            buttons.Controls.Add(safeRetry);
            layout.Controls.Add(buttons, 0, 3);

            AcceptButton = safeRetry;
            CancelButton = cancel;
            Controls.Add(layout);
        }

        internal static AccountConflictChoice ShowDialog(
            IWin32Window owner,
            string computerName,
            string reason,
            AdComputerAccountInfo account,
            bool canDelete)
        {
            using (AccountConflictDialog dialog = new AccountConflictDialog(
                computerName,
                reason,
                account,
                canDelete))
            {
                dialog.ShowDialog(owner);
                return dialog.choice;
            }
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }

    internal sealed class NewNameDialog : Form
    {
        private readonly TextBox nameBox;

        private NewNameDialog(string currentName, string suggested)
        {
            Text = "Enter new computer name";
            Width = 500;
            Height = 210;
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            Font = new Font("Segoe UI", 9F);

            Label info = new Label();
            info.Left = 18;
            info.Top = 18;
            info.Width = 445;
            info.Height = 45;
            info.Text = "Current name: " + currentName + "\r\nEnter a new computer name (maximum 15 characters):";

            nameBox = new TextBox();
            nameBox.Left = 18;
            nameBox.Top = 70;
            nameBox.Width = 445;
            nameBox.Text = suggested;
            nameBox.SelectAll();

            Button ok = new Button();
            ok.Text = "OK";
            ok.Left = 292;
            ok.Top = 110;
            ok.Width = 80;
            ok.DialogResult = DialogResult.OK;

            Button cancel = new Button();
            cancel.Text = "Cancel";
            cancel.Left = 383;
            cancel.Top = 110;
            cancel.Width = 80;
            cancel.DialogResult = DialogResult.Cancel;

            Controls.Add(info);
            Controls.Add(nameBox);
            Controls.Add(ok);
            Controls.Add(cancel);

            AcceptButton = ok;
            CancelButton = cancel;
        }

        internal static string ShowDialog(IWin32Window owner, string currentName, string suggested)
        {
            using (NewNameDialog dialog = new NewNameDialog(currentName, suggested))
            {
                if (dialog.ShowDialog(owner) != DialogResult.OK)
                    return null;
                return dialog.nameBox.Text.Trim();
            }
        }
    }

    internal sealed class ComputerNameLookupDialog : Form
    {
        private readonly TextBox nameBox;

        private ComputerNameLookupDialog(string suggested)
        {
            Text = "Check AD computer account";
            Width = 500;
            Height = 190;
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false;
            MinimizeBox = false;
            Font = new Font("Segoe UI", 9F);

            Label info = new Label();
            info.Left = 18;
            info.Top = 18;
            info.Width = 445;
            info.Height = 40;
            info.Text = "Computer name to look up in Active Directory (read-only):";

            nameBox = new TextBox();
            nameBox.Left = 18;
            nameBox.Top = 58;
            nameBox.Width = 445;
            nameBox.Text = suggested ?? String.Empty;
            nameBox.SelectAll();

            Button ok = new Button();
            ok.Text = "Check";
            ok.Left = 292;
            ok.Top = 100;
            ok.Width = 80;
            ok.DialogResult = DialogResult.OK;

            Button cancel = new Button();
            cancel.Text = "Cancel";
            cancel.Left = 383;
            cancel.Top = 100;
            cancel.Width = 80;
            cancel.DialogResult = DialogResult.Cancel;

            Controls.Add(info);
            Controls.Add(nameBox);
            Controls.Add(ok);
            Controls.Add(cancel);
            AcceptButton = ok;
            CancelButton = cancel;
        }

        internal static string ShowDialog(IWin32Window owner, string suggested)
        {
            using (ComputerNameLookupDialog dialog = new ComputerNameLookupDialog(suggested))
            {
                if (dialog.ShowDialog(owner) != DialogResult.OK)
                    return null;
                return dialog.nameBox.Text.Trim();
            }
        }
    }

    internal sealed class ReportDialog : Form
    {
        private ReportDialog(string title, string report)
        {
            Text = title;
            Width = 760;
            Height = 560;
            StartPosition = FormStartPosition.CenterParent;
            FormBorderStyle = FormBorderStyle.Sizable;
            MinimizeBox = false;
            Font = new Font("Segoe UI", 9F);

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.Dock = DockStyle.Fill;
            layout.Padding = new Padding(12);
            layout.ColumnCount = 1;
            layout.RowCount = 2;
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 44F));

            TextBox box = new TextBox();
            box.Multiline = true;
            box.ReadOnly = true;
            box.ScrollBars = ScrollBars.Both;
            box.WordWrap = false;
            box.Dock = DockStyle.Fill;
            box.Font = new Font("Consolas", 9F);
            box.Text = report ?? String.Empty;
            layout.Controls.Add(box, 0, 0);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.Dock = DockStyle.Fill;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.WrapContents = false;

            Button close = new Button();
            close.Text = "Close";
            close.Width = 90;
            close.Height = 30;
            close.DialogResult = DialogResult.OK;

            Button copy = new Button();
            copy.Text = "Copy";
            copy.Width = 90;
            copy.Height = 30;
            copy.Click += delegate
            {
                try
                {
                    Clipboard.SetText(box.Text ?? String.Empty);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(this, ex.Message, "Copy failed", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };

            buttons.Controls.Add(close);
            buttons.Controls.Add(copy);
            layout.Controls.Add(buttons, 0, 1);

            AcceptButton = close;
            Controls.Add(layout);
        }

        internal static void ShowReport(IWin32Window owner, string title, string report)
        {
            using (ReportDialog dialog = new ReportDialog(title, report))
                dialog.ShowDialog(owner);
        }
    }

}
