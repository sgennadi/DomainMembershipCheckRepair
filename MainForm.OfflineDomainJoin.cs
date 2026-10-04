using System;
using System.IO;
using System.Security.Principal;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal sealed partial class MainForm
    {
        private OdjGuiWorkflow odjGuiWorkflow;

        private void RunOdjGuiWorkflow(bool applyOnly)
        {
            if (odjGuiWorkflow == null)
            {
                odjGuiWorkflow = new OdjGuiWorkflow(
                    new WinFormsOdjDialogs(this),
                    ExecuteConfirmedOdjApply,
                    ExecuteConfirmedOdjProvision);
            }

            try
            {
                odjGuiWorkflow.Run(applyOnly);
            }
            catch (Exception ex)
            {
                Log("ERROR", "Offline Domain Join workflow interrupted: " + ex.Message);
                MessageBox.Show(
                    this,
                    "The Offline Domain Join workflow was interrupted.\r\n\r\n" +
                    ex.Message + "\r\n\r\n" +
                    "Review the operation output and local/domain state before retrying. " +
                    "No automatic retry was performed.",
                    "Offline Domain Join interrupted",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Error);
            }
        }

        private void ExecuteConfirmedOdjApply(string blobPath)
        {
            string targetDomain = domainBox == null ? String.Empty : domainBox.Text;
            SetBusy(true);
            try
            {
                CreatePreChangeBundle("offline-domain-join", targetDomain, null, null);

                RecoverySnapshotScope snapshot;
                if (!TryCreateRecoverySnapshotForGui(
                    "offline-domain-join", targetDomain, null, null, out snapshot))
                {
                    return;
                }

                using (snapshot)
                {
                    string output;
                    int code = OfflineDomainJoinService.ApplyBlob(blobPath, out output);
                    Log(code == 0 ? "SUCCESS" : "ERROR",
                        "Offline Domain Join returned " + code + ". " + output);

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
            finally
            {
                SetBusy(false);
            }
        }

        private void ExecuteConfirmedOdjProvision(OdjProvisionRequest request)
        {
            SetBusy(true);
            try
            {
                string output;
                int code = OfflineDomainJoinService.ProvisionBlob(
                    request.Domain,
                    request.ComputerName,
                    request.OutputPath,
                    request.Reuse,
                    out output);

                Log(code == 0 ? "SUCCESS" : "ERROR",
                    "Offline Domain Join provisioning returned " + code + ". " + output);

                if (code != 0)
                {
                    ReportDialog.ShowReport(
                        this, "Offline Domain Join provisioning failed", output);
                    return;
                }

                MessageBox.Show(
                    this,
                    "Protected Offline Domain Join provisioning blob created successfully.\r\n\r\n" +
                    request.OutputPath + "\r\n\r\n" +
                    "Protect this file during transfer and delete it when it is no longer needed.",
                    "Offline Domain Join - Provision",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
            }
            finally
            {
                SetBusy(false);
            }
        }

        private sealed class WinFormsOdjDialogs : IOdjGuiDialogs
        {
            private readonly MainForm owner;

            internal WinFormsOdjDialogs(MainForm owner)
            {
                this.owner = owner;
            }

            public DialogResult ChooseMode()
            {
                return MessageBox.Show(
                    owner,
                    "Choose the Offline Domain Join operation.\r\n\r\n" +
                    "Yes = Apply an existing provisioning blob to this computer\r\n" +
                    "No = Provision a new protected blob for a computer account\r\n" +
                    "Cancel = Do nothing",
                    "Offline Domain Join",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Information,
                    OdjGuiWorkflow.ModeDefault);
            }

            public bool EnsureApplyElevation()
            {
                return owner.EnsureElevatedForGui("odj-apply");
            }

            public string ChooseApplyBlob()
            {
                using (OpenFileDialog open = new OpenFileDialog())
                {
                    open.Title = "Select Offline Domain Join provisioning blob";
                    open.Filter = "ODJ provisioning files (*.*)|*.*";
                    open.CheckFileExists = true;
                    open.CheckPathExists = true;
                    return open.ShowDialog(owner) == DialogResult.OK ? open.FileName : null;
                }
            }

            public DialogResult ConfirmApply(string blobPath)
            {
                return MessageBox.Show(
                    owner,
                    "Apply this Offline Domain Join provisioning package to the local Windows installation?\r\n\r\n" +
                    blobPath + "\r\n\r\nA restart will be required.",
                    "Offline Domain Join - Apply",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    OdjGuiWorkflow.ApplyDefault);
            }

            public string GetTargetDomain()
            {
                string domain;
                return owner.TryGetTargetDomain(out domain) ? domain : null;
            }

            public string ChooseComputerName()
            {
                return ComputerNameLookupDialog.ShowDialog(owner, Environment.MachineName);
            }

            public DialogResult ChooseReuse()
            {
                return MessageBox.Show(
                    owner,
                    "Should djoin.exe be allowed to reuse an existing Active Directory computer account with this name?\r\n\r\n" +
                    "Yes = include /reuse\r\n" +
                    "No = provision without /reuse\r\n" +
                    "Cancel = stop",
                    "Offline Domain Join - Provision",
                    MessageBoxButtons.YesNoCancel,
                    MessageBoxIcon.Question,
                    OdjGuiWorkflow.ReuseDefault);
            }

            public string ChooseOutputFile(string computerName)
            {
                using (SaveFileDialog save = new SaveFileDialog())
                {
                    save.Title = "Save protected Offline Domain Join provisioning blob";
                    save.Filter = "ODJ provisioning files (*.txt)|*.txt|All files (*.*)|*.*";
                    save.FileName = computerName + "-odj.txt";
                    save.DefaultExt = "txt";
                    save.AddExtension = true;
                    save.CheckPathExists = true;
                    // The service refuses every existing target, regardless of
                    // the dialog's overwrite setting or operator confirmation.
                    save.OverwritePrompt = false;
                    return save.ShowDialog(owner) == DialogResult.OK ? save.FileName : null;
                }
            }

            public string GetWindowsIdentity()
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                    return identity == null ? null : identity.Name;
            }

            public DialogResult ConfirmProvision(OdjProvisionRequest request)
            {
                return MessageBox.Show(
                    owner,
                    OdjGuiWorkflow.BuildProvisionConfirmation(request),
                    "Confirm Offline Domain Join provisioning",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning,
                    OdjGuiWorkflow.ProvisionDefault);
            }

            public void ShowValidationError(string message)
            {
                MessageBox.Show(
                    owner,
                    message,
                    "Offline Domain Join - invalid input",
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
            }
        }
    }
}
