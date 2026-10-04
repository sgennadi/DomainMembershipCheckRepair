using System;
using System.IO;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    // Immutable, non-secret values displayed to the operator before provisioning.
    internal sealed class OdjProvisionRequest
    {
        internal readonly string Domain;
        internal readonly string ComputerName;
        internal readonly string OutputPath;
        internal readonly bool Reuse;
        internal readonly string WindowsIdentity;

        internal OdjProvisionRequest(string domain, string computerName, string outputPath,
            bool reuse, string windowsIdentity)
        {
            Domain = domain;
            ComputerName = computerName;
            OutputPath = outputPath;
            Reuse = reuse;
            WindowsIdentity = windowsIdentity;
        }
    }

    internal interface IOdjGuiDialogs
    {
        DialogResult ChooseMode();
        bool EnsureApplyElevation();
        string ChooseApplyBlob();
        DialogResult ConfirmApply(string blobPath);
        string GetTargetDomain();
        string ChooseComputerName();
        DialogResult ChooseReuse();
        string ChooseOutputFile(string computerName);
        string GetWindowsIdentity();
        DialogResult ConfirmProvision(OdjProvisionRequest request);
        void ShowValidationError(string message);
    }

    // The production GUI and regression tests use the same orchestration.
    // Tests substitute dialogs and terminal actions, never a real djoin command.
    internal sealed class OdjGuiWorkflow
    {
        internal const MessageBoxDefaultButton ModeDefault = MessageBoxDefaultButton.Button3;
        internal const MessageBoxDefaultButton ApplyDefault = MessageBoxDefaultButton.Button2;
        internal const MessageBoxDefaultButton ReuseDefault = MessageBoxDefaultButton.Button2;
        internal const MessageBoxDefaultButton ProvisionDefault = MessageBoxDefaultButton.Button2;

        private readonly IOdjGuiDialogs dialogs;
        private readonly Action<string> apply;
        private readonly Action<OdjProvisionRequest> provision;
        private bool running;

        internal OdjGuiWorkflow(IOdjGuiDialogs dialogs, Action<string> apply,
            Action<OdjProvisionRequest> provision)
        {
            if (dialogs == null) throw new ArgumentNullException("dialogs");
            if (apply == null) throw new ArgumentNullException("apply");
            if (provision == null) throw new ArgumentNullException("provision");
            this.dialogs = dialogs;
            this.apply = apply;
            this.provision = provision;
        }

        internal void Run(bool applyOnly)
        {
            // WinForms modal message loops can re-enter event handlers.
            if (running)
                return;

            running = true;
            try
            {
                if (applyOnly)
                {
                    RunApply();
                    return;
                }

                DialogResult choice = dialogs.ChooseMode();
                if (choice == DialogResult.Yes)
                    RunApply();
                else if (choice == DialogResult.No)
                    RunProvision();
                // Cancel, a closed chooser, and every unexpected result do nothing.
            }
            finally
            {
                running = false;
            }
        }

        private void RunApply()
        {
            if (!dialogs.EnsureApplyElevation())
                return;

            string path = dialogs.ChooseApplyBlob();
            if (String.IsNullOrWhiteSpace(path))
                return;

            if (dialogs.ConfirmApply(path) != DialogResult.Yes)
                return;

            apply(path);
        }

        private void RunProvision()
        {
            string domain = dialogs.GetTargetDomain();
            if (domain == null)
                return;
            domain = domain.Trim();
            string error = DomainValidation.ValidateDomainArgument(domain);
            if (error != null)
            {
                dialogs.ShowValidationError(error);
                return;
            }

            string computerName = dialogs.ChooseComputerName();
            if (computerName == null)
                return;
            computerName = computerName.Trim();
            error = DomainValidation.ValidateComputerName(computerName);
            if (error != null)
            {
                dialogs.ShowValidationError(error);
                return;
            }

            DialogResult reuse = dialogs.ChooseReuse();
            if (reuse != DialogResult.Yes && reuse != DialogResult.No)
                return;

            string path = dialogs.ChooseOutputFile(computerName);
            if (String.IsNullOrWhiteSpace(path))
                return;
            try
            {
                path = Path.GetFullPath(path);
            }
            catch (Exception ex)
            {
                dialogs.ShowValidationError("Invalid output path: " + ex.Message);
                return;
            }

            string identity = dialogs.GetWindowsIdentity();
            if (String.IsNullOrWhiteSpace(identity))
            {
                dialogs.ShowValidationError("The current Windows identity could not be determined. Provisioning was not started.");
                return;
            }

            OdjProvisionRequest request = new OdjProvisionRequest(
                domain, computerName, path, reuse == DialogResult.Yes, identity);
            if (dialogs.ConfirmProvision(request) != DialogResult.Yes)
                return;

            // Do not silently use a different identity than the one displayed.
            if (!String.Equals(identity, dialogs.GetWindowsIdentity(), StringComparison.OrdinalIgnoreCase))
            {
                dialogs.ShowValidationError("The Windows identity changed or could not be rechecked. Provisioning was not started; review the Windows session before trying again.");
                return;
            }

            // The existing service still performs its complete output preflight
            // and protected final commit. Confirmation cannot bypass that policy.
            provision(request);
        }

        internal static string BuildProvisionConfirmation(OdjProvisionRequest request)
        {
            if (request == null) throw new ArgumentNullException("request");
            return "Provision an Offline Domain Join package?\r\n\r\n" +
                "Windows account: " + request.WindowsIdentity + "\r\n" +
                "Domain: " + request.Domain + "\r\n" +
                "Computer: " + request.ComputerName + "\r\n" +
                "Output: " + request.OutputPath + "\r\n" +
                "Reuse existing AD account: " + (request.Reuse ? "YES (/reuse)" : "NO") + "\r\n\r\n" +
                "This operation can create or reuse an Active Directory computer account.\r\n\r\n" +
                "The Domain user and Password fields in the main window are NOT used for this operation. " +
                "djoin.exe runs under the current Windows process identity.\r\n\r\n" +
                "No automatic retry, account deletion or rollback will be performed.\r\n\r\nContinue?";
        }
    }
}
