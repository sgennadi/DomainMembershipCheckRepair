using System;
using System.Drawing;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal static class DialogUi
    {
        internal static void ApplyDpi(Form form, Size minimumSize)
        {
            form.AutoScaleDimensions = new SizeF(96F, 96F);
            form.AutoScaleMode = AutoScaleMode.Dpi;
            form.MinimumSize = minimumSize;
            form.Font = new Font("Segoe UI", 9F);
            form.StartPosition = FormStartPosition.CenterParent;
            form.ShowInTaskbar = false;
        }

        internal static Button CreateButton(string text, int minimumWidth)
        {
            Button button = new Button();
            button.Text = text;
            button.AutoSize = true;
            button.AutoSizeMode = AutoSizeMode.GrowAndShrink;
            button.MinimumSize = new Size(minimumWidth, 32);
            button.Padding = new Padding(8, 2, 8, 2);
            return button;
        }

        internal static FlowLayoutPanel CreateButtonRow()
        {
            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.Dock = DockStyle.Fill;
            buttons.AutoSize = true;
            buttons.WrapContents = true;
            buttons.FlowDirection = FlowDirection.RightToLeft;
            buttons.Padding = new Padding(0, 6, 0, 0);
            return buttons;
        }
    }

    internal sealed class AccountConflictDialog : Form
    {
        private AccountConflictChoice choice = AccountConflictChoice.Cancel;

        private AccountConflictDialog(
            string computerName,
            string reason,
            AdComputerAccountInfo account,
            bool canDelete)
        {
            Text = "Computer account conflict";
            Width = 820;
            Height = 560;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = false;
            DialogUi.ApplyDpi(this, new Size(620, 430));

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.Dock = DockStyle.Fill;
            layout.Padding = new Padding(14);
            layout.ColumnCount = 1;
            layout.RowCount = 4;
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            Label message = new Label();
            message.AutoSize = true;
            message.Dock = DockStyle.Fill;
            message.Text = reason + "\r\n\r\nComputer: " + computerName;
            layout.Controls.Add(message, 0, 0);

            TextBox details = new TextBox();
            details.Multiline = true;
            details.ReadOnly = true;
            details.ScrollBars = ScrollBars.Both;
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
            warning.Dock = DockStyle.Fill;
            warning.Margin = new Padding(0, 10, 0, 4);
            warning.Text =
                "Recommended order: Safe Fixes + Retry Same Name -> Use New Name -> Delete + Retry only as a last resort. " +
                "The final delete step is also protected by a separate safety gate.";
            layout.Controls.Add(warning, 0, 2);

            FlowLayoutPanel buttons = DialogUi.CreateButtonRow();

            Button cancel = DialogUi.CreateButton("Cancel", 90);
            cancel.Click += delegate
            {
                choice = AccountConflictChoice.Cancel;
                DialogResult = DialogResult.Cancel;
                Close();
            };

            Button delete = DialogUi.CreateButton("Delete + Retry", 125);
            delete.Enabled = canDelete;
            delete.Click += delegate
            {
                choice = AccountConflictChoice.DeleteAndRetry;
                DialogResult = DialogResult.OK;
                Close();
            };

            Button rename = DialogUi.CreateButton("Use New Name", 120);
            rename.Click += delegate
            {
                choice = AccountConflictChoice.RenameAndJoin;
                DialogResult = DialogResult.OK;
                Close();
            };

            Button safeRetry = DialogUi.CreateButton("Safe Fixes + Retry Same Name", 220);
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
            Width = 560;
            Height = 230;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = false;
            MinimizeBox = false;
            DialogUi.ApplyDpi(this, new Size(430, 210));

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.Dock = DockStyle.Fill;
            layout.Padding = new Padding(16);
            layout.ColumnCount = 1;
            layout.RowCount = 3;
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

            Label info = new Label();
            info.AutoSize = true;
            info.Dock = DockStyle.Fill;
            info.Text =
                "Current name: " + currentName +
                "\r\nEnter a new computer name (maximum 15 characters):";
            layout.Controls.Add(info, 0, 0);

            nameBox = new TextBox();
            nameBox.Dock = DockStyle.Top;
            nameBox.Margin = new Padding(0, 10, 0, 6);
            nameBox.Text = suggested;
            layout.Controls.Add(nameBox, 0, 1);

            FlowLayoutPanel buttons = DialogUi.CreateButtonRow();
            Button cancel = DialogUi.CreateButton("Cancel", 90);
            cancel.DialogResult = DialogResult.Cancel;
            Button ok = DialogUi.CreateButton("OK", 90);
            ok.DialogResult = DialogResult.OK;
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons, 0, 2);

            AcceptButton = ok;
            CancelButton = cancel;
            Controls.Add(layout);

            Shown += delegate
            {
                nameBox.Focus();
                nameBox.SelectAll();
            };
        }

        internal static string ShowDialog(
            IWin32Window owner,
            string currentName,
            string suggested)
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
            Width = 560;
            Height = 210;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = false;
            MinimizeBox = false;
            DialogUi.ApplyDpi(this, new Size(430, 195));

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.Dock = DockStyle.Fill;
            layout.Padding = new Padding(16);
            layout.ColumnCount = 1;
            layout.RowCount = 3;
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));

            Label info = new Label();
            info.AutoSize = true;
            info.Dock = DockStyle.Fill;
            info.Text = "Computer name to look up in Active Directory (read-only):";
            layout.Controls.Add(info, 0, 0);

            nameBox = new TextBox();
            nameBox.Dock = DockStyle.Top;
            nameBox.Margin = new Padding(0, 10, 0, 6);
            nameBox.Text = suggested ?? String.Empty;
            layout.Controls.Add(nameBox, 0, 1);

            FlowLayoutPanel buttons = DialogUi.CreateButtonRow();
            Button cancel = DialogUi.CreateButton("Cancel", 90);
            cancel.DialogResult = DialogResult.Cancel;
            Button ok = DialogUi.CreateButton("Check", 90);
            ok.DialogResult = DialogResult.OK;
            buttons.Controls.Add(cancel);
            buttons.Controls.Add(ok);
            layout.Controls.Add(buttons, 0, 2);

            AcceptButton = ok;
            CancelButton = cancel;
            Controls.Add(layout);

            Shown += delegate
            {
                nameBox.Focus();
                nameBox.SelectAll();
            };
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
            Width = 900;
            Height = 650;
            FormBorderStyle = FormBorderStyle.Sizable;
            MaximizeBox = true;
            MinimizeBox = false;
            DialogUi.ApplyDpi(this, new Size(560, 400));

            TableLayoutPanel layout = new TableLayoutPanel();
            layout.Dock = DockStyle.Fill;
            layout.Padding = new Padding(12);
            layout.ColumnCount = 1;
            layout.RowCount = 2;
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

            TextBox box = new TextBox();
            box.Multiline = true;
            box.ReadOnly = true;
            box.ScrollBars = ScrollBars.Both;
            box.WordWrap = false;
            box.Dock = DockStyle.Fill;
            box.Font = new Font("Consolas", 9F);
            box.Text = report ?? String.Empty;
            layout.Controls.Add(box, 0, 0);

            FlowLayoutPanel buttons = DialogUi.CreateButtonRow();
            Button close = DialogUi.CreateButton("Close", 90);
            close.DialogResult = DialogResult.OK;

            Button copy = DialogUi.CreateButton("Copy", 90);
            copy.Click += delegate
            {
                try
                {
                    Clipboard.SetText(box.Text ?? String.Empty);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(
                        this,
                        ex.Message,
                        "Copy failed",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Warning);
                }
            };

            buttons.Controls.Add(close);
            buttons.Controls.Add(copy);
            layout.Controls.Add(buttons, 0, 1);

            AcceptButton = close;
            Controls.Add(layout);
        }

        internal static void ShowReport(
            IWin32Window owner,
            string title,
            string report)
        {
            using (ReportDialog dialog = new ReportDialog(title, report))
                dialog.ShowDialog(owner);
        }
    }
}
