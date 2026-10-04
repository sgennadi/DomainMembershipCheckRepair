using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal static class OdjGuiWorkflowTests
    {
        private static int cases;
        private static int failures;

        private static void Main(string[] args)
        {
            if (args.Length != 2 || args[0] != "--root")
            {
                Console.Error.WriteLine("Usage: DomainMembershipCheckRepair.OdjGui.Tests.exe --root REPOSITORY");
                Environment.ExitCode = 3;
                return;
            }

            string root = Path.GetFullPath(args[1]);
            foreach (DialogResult value in new DialogResult[] {
                DialogResult.Cancel, DialogResult.None, DialogResult.Abort, DialogResult.OK, DialogResult.Retry })
            {
                DialogResult choice = value;
                Run("mode " + choice + " has no side effects", delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.Mode = choice;
                    f.Workflow.Run(false);
                    AssertNoExecution(f);
                    Equal("mode", String.Join(",", f.Dialogs.Events), "only the mode chooser ran");
                });
            }

            Run("Apply elevation refusal stops before file chooser", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.Mode = DialogResult.Yes;
                f.Dialogs.Elevated = false;
                f.Workflow.Run(false);
                AssertNoExecution(f);
                Equal("mode,elevation", String.Join(",", f.Dialogs.Events), "elevation boundary");
            });

            Run("resumed Apply skips mode chooser but retains elevation gate", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.Mode = DialogResult.No;
                f.Dialogs.Elevated = false;
                f.Workflow.Run(true);
                AssertNoExecution(f);
                Equal("elevation", String.Join(",", f.Dialogs.Events), "resume does not select Provision");
            });

            foreach (string value in new string[] { null, String.Empty, "   " })
            {
                string path = value;
                Run("cancelled or empty Apply chooser stops before confirmation", delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.Blob = path;
                    f.Workflow.Run(true);
                    AssertNoExecution(f);
                    Equal("elevation,blob", String.Join(",", f.Dialogs.Events), "cancelled blob chooser");
                });
            }

            foreach (DialogResult value in new DialogResult[] {
                DialogResult.No, DialogResult.Cancel, DialogResult.None, DialogResult.OK })
            {
                DialogResult choice = value;
                Run("Apply confirmation " + choice + " cannot execute", delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.ApplyConfirmation = choice;
                    f.Workflow.Run(true);
                    AssertNoExecution(f);
                    Equal("elevation,blob,confirm-apply", String.Join(",", f.Dialogs.Events), "confirmation boundary");
                });
            }

            Run("ordinary Apply executes exactly once after confirmation", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.Mode = DialogResult.Yes;
                f.Workflow.Run(false);
                Equal(1, f.ApplyCalls, "Apply count");
                Equal(0, f.ProvisionCalls, "Provision count");
                Equal(f.Dialogs.Blob, f.AppliedPath, "selected blob path");
                Equal("mode,elevation,blob,confirm-apply,apply", String.Join(",", f.Dialogs.Events), "Apply ordering");
            });

            Run("resumed Apply executes without reopening mode chooser", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.Mode = DialogResult.No;
                f.Workflow.Run(true);
                Equal(1, f.ApplyCalls, "Apply count");
                Equal(0, f.ProvisionCalls, "Provision count");
                Equal("elevation,blob,confirm-apply,apply", String.Join(",", f.Dialogs.Events), "resume ordering");
            });

            Run("cancelled domain input stops Provision", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.Domain = null;
                f.Workflow.Run(false);
                AssertNoExecution(f);
                Equal("mode,domain", String.Join(",", f.Dialogs.Events), "cancelled domain");
            });

            foreach (string value in new string[] { String.Empty, "example.com /force", "bad..example" })
            {
                string domain = value;
                Run("invalid domain stops before computer chooser", delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.Domain = domain;
                    f.Workflow.Run(false);
                    AssertNoExecution(f);
                    Equal(1, f.Dialogs.Errors.Count, "domain validation error");
                    Equal("mode,domain,error", String.Join(",", f.Dialogs.Events), "domain boundary");
                });
            }

            Run("cancelled computer chooser stops Provision", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.Computer = null;
                f.Workflow.Run(false);
                AssertNoExecution(f);
                Equal("mode,domain,computer", String.Join(",", f.Dialogs.Events), "cancelled computer chooser");
            });

            foreach (string value in new string[] { String.Empty, "BAD_NAME", "12345", "COMPUTER-NAME-TOO-LONG" })
            {
                string name = value;
                Run("invalid computer name cannot reach reuse chooser", delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.Computer = name;
                    f.Workflow.Run(false);
                    AssertNoExecution(f);
                    Equal(1, f.Dialogs.Errors.Count, "name validation error");
                    Equal("mode,domain,computer,error", String.Join(",", f.Dialogs.Events), "computer boundary");
                });
            }

            foreach (DialogResult value in new DialogResult[] { DialogResult.Cancel, DialogResult.None, DialogResult.OK })
            {
                DialogResult choice = value;
                Run("reuse chooser " + choice + " stops before output selection", delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.Reuse = choice;
                    f.Workflow.Run(false);
                    AssertNoExecution(f);
                    Equal("mode,domain,computer,reuse", String.Join(",", f.Dialogs.Events), "reuse boundary");
                });
            }

            foreach (string value in new string[] { null, String.Empty, "   " })
            {
                string path = value;
                Run("cancelled or empty output chooser does not request identity", delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.Output = path;
                    f.Workflow.Run(false);
                    AssertNoExecution(f);
                    Equal("mode,domain,computer,reuse,output", String.Join(",", f.Dialogs.Events), "output boundary");
                });
            }

            Run("malformed output path cannot execute", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.Output = "bad\0output";
                f.Workflow.Run(false);
                AssertNoExecution(f);
                Equal(1, f.Dialogs.Errors.Count, "path validation error");
            });

            Run("unavailable Windows identity blocks confirmation", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.Identity = null;
                f.Workflow.Run(false);
                AssertNoExecution(f);
                Equal(1, f.Dialogs.Errors.Count, "identity validation error");
                True(!f.Dialogs.Events.Contains("confirm-provision"), "confirmation not shown");
            });

            foreach (DialogResult value in new DialogResult[] {
                DialogResult.No, DialogResult.Cancel, DialogResult.None, DialogResult.OK })
            {
                DialogResult choice = value;
                Run("Provision confirmation " + choice + " cannot execute", delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.ProvisionConfirmation = choice;
                    f.Workflow.Run(false);
                    AssertNoExecution(f);
                    Equal("mode,domain,computer,reuse,output,identity,confirm-provision",
                        String.Join(",", f.Dialogs.Events), "Provision confirmation boundary");
                });
            }

            foreach (bool reuse in new bool[] { false, true })
            {
                bool useExisting = reuse;
                Run("confirmed Provision preserves request with reuse=" + useExisting, delegate
                {
                    Fixture f = new Fixture();
                    f.Dialogs.Domain = " example.com ";
                    f.Dialogs.Computer = " PC-01 ";
                    f.Dialogs.Reuse = useExisting ? DialogResult.Yes : DialogResult.No;
                    f.Workflow.Run(false);
                    Equal(0, f.ApplyCalls, "Apply count");
                    Equal(1, f.ProvisionCalls, "Provision count");
                    Equal("example.com", f.Provisioned.Domain, "trimmed domain");
                    Equal("PC-01", f.Provisioned.ComputerName, "trimmed computer");
                    Equal(Path.GetFullPath(f.Dialogs.Output), f.Provisioned.OutputPath, "absolute output");
                    Equal(f.Dialogs.Identity, f.Provisioned.WindowsIdentity, "confirmed identity");
                    True(f.Provisioned.Reuse == useExisting, "reuse preserved");
                    True(Object.ReferenceEquals(f.Dialogs.Confirmed, f.Provisioned), "exact confirmed request delivered");
                    Equal("mode,domain,computer,reuse,output,identity,confirm-provision,identity,provision",
                        String.Join(",", f.Dialogs.Events), "Provision ordering and no elevation");
                });
            }

            Run("changed Windows identity after confirmation blocks Provision", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.OnProvisionConfirmation = delegate { f.Dialogs.Identity = @"EXAMPLE\other"; };
                f.Workflow.Run(false);
                AssertNoExecution(f);
                Equal(1, f.Dialogs.Errors.Count, "identity change error");
            });

            Run("failed identity recheck blocks Provision", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.OnProvisionConfirmation = delegate { f.Dialogs.Identity = null; };
                f.Workflow.Run(false);
                AssertNoExecution(f);
                Equal(1, f.Dialogs.Errors.Count, "identity unavailable after confirmation");
            });

            Run("case-only identity difference does not change account", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.OnProvisionConfirmation = delegate { f.Dialogs.Identity = f.Dialogs.Identity.ToLowerInvariant(); };
                f.Workflow.Run(false);
                Equal(1, f.ProvisionCalls, "case-insensitive account comparison");
            });

            Run("confirmation includes identity targets and ignored-credential warning", delegate
            {
                OdjProvisionRequest request = new OdjProvisionRequest(
                    "example.com", "PC-01", @"C:\odj-tests\output.txt", true, @"EXAMPLE\operator");
                string text = OdjGuiWorkflow.BuildProvisionConfirmation(request);
                foreach (string required in new string[] {
                    request.Domain, request.ComputerName, request.OutputPath, request.WindowsIdentity,
                    "YES (/reuse)", "Active Directory", "Domain user and Password", "NOT used", "No automatic retry" })
                {
                    True(text.Contains(required), "confirmation contains " + required);
                }

                foreach (FieldInfo field in typeof(OdjProvisionRequest).GetFields(BindingFlags.Instance | BindingFlags.NonPublic))
                {
                    True(field.IsInitOnly, "confirmed request is immutable");
                    True(field.Name.IndexOf("password", StringComparison.OrdinalIgnoreCase) < 0,
                        "request does not carry a password");
                }
            });

            Run("safety defaults are Cancel or No", delegate
            {
                True(OdjGuiWorkflow.ModeDefault == MessageBoxDefaultButton.Button3, "mode defaults Cancel");
                True(OdjGuiWorkflow.ApplyDefault == MessageBoxDefaultButton.Button2, "Apply defaults No");
                True(OdjGuiWorkflow.ReuseDefault == MessageBoxDefaultButton.Button2, "reuse defaults No");
                True(OdjGuiWorkflow.ProvisionDefault == MessageBoxDefaultButton.Button2, "Provision defaults No");
            });

            Run("modal chooser reentry cannot duplicate execution", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.OnMode = delegate { f.Workflow.Run(true); };
                f.Workflow.Run(false);
                Equal(0, f.ApplyCalls, "reentrant Apply blocked");
                Equal(1, f.ProvisionCalls, "outer Provision runs once");
            });

            Run("confirmation reentry cannot duplicate execution", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.OnProvisionConfirmation = delegate { f.Workflow.Run(false); };
                f.Workflow.Run(false);
                Equal(0, f.ApplyCalls, "no Apply");
                Equal(1, f.ProvisionCalls, "one Provision despite nested loop");
            });

            Run("dialog exception releases guard without automatic retry", delegate
            {
                Fixture f = new Fixture();
                f.Dialogs.OnMode = delegate { throw new IOException("simulated dialog failure"); };
                bool thrown = false;
                try { f.Workflow.Run(false); } catch (IOException) { thrown = true; }
                True(thrown, "dialog failure is surfaced");
                AssertNoExecution(f);
                f.Dialogs.OnMode = null;
                f.Workflow.Run(false);
                Equal(1, f.ProvisionCalls, "subsequent explicit invocation is possible");
            });

            Run("terminal action failure is not automatically retried", delegate
            {
                Fixture f = new Fixture();
                f.ThrowProvision = true;
                bool thrown = false;
                try { f.Workflow.Run(false); } catch (IOException) { thrown = true; }
                True(thrown, "terminal failure surfaced");
                Equal(1, f.ProvisionCalls, "no automatic retry");
                f.ThrowProvision = false;
                f.Workflow.Run(false);
                Equal(2, f.ProvisionCalls, "only explicit invocation runs again");
            });

            Run("production MainForm wiring retains distinct chooser and Apply resume", delegate
            {
                string source = File.ReadAllText(Path.Combine(root, "MainForm.cs"));
                Match resume = Regex.Match(source, "case \\\"odj-apply\\\":(?<body>.*?)break;", RegexOptions.Singleline);
                True(resume.Success, "odj-apply resume case exists");
                Equal("ApplyOfflineDomainJoinWorkflow();", resume.Groups["body"].Value.Trim(), "resume dispatches directly to Apply");
                True(source.Contains("offlineJoinButton.Click += delegate { OfflineDomainJoinWorkflow(); };"),
                    "ordinary button retains mode chooser");
                True(Regex.IsMatch(source, @"private void OfflineDomainJoinWorkflow\(\)\s*\{\s*RunOdjGuiWorkflow\(false\);\s*\}"),
                    "ordinary wrapper selects chooser route");
                True(Regex.IsMatch(source, @"private void ApplyOfflineDomainJoinWorkflow\(\)\s*\{\s*RunOdjGuiWorkflow\(true\);\s*\}"),
                    "Apply wrapper selects apply-only route");
                True(!source.Contains("OfflineDomainJoinService.ApplyBlob("), "no legacy direct Apply path");
                True(!source.Contains("OfflineDomainJoinService.ProvisionBlob("), "no legacy direct Provision path");
            });

            Run("production adapter uses tested controller defaults and service gates", delegate
            {
                string source = File.ReadAllText(Path.Combine(root, "MainForm.OfflineDomainJoin.cs"));
                foreach (string required in new string[] {
                    "new OdjGuiWorkflow(", "new WinFormsOdjDialogs(this)", "ExecuteConfirmedOdjApply,",
                    "ExecuteConfirmedOdjProvision)", "odjGuiWorkflow.Run(applyOnly)",
                    "OdjGuiWorkflow.ModeDefault", "OdjGuiWorkflow.ApplyDefault", "OdjGuiWorkflow.ReuseDefault",
                    "OdjGuiWorkflow.ProvisionDefault", "OdjGuiWorkflow.BuildProvisionConfirmation(request)",
                    "owner.EnsureElevatedForGui(\"odj-apply\")", "TryCreateRecoverySnapshotForGui(",
                    "OfflineDomainJoinService.ApplyBlob(", "OfflineDomainJoinService.ProvisionBlob(" })
                {
                    True(source.Contains(required), "production adapter contains " + required);
                }
                True(!source.Contains("owner.GetCredentials("), "Provision does not read domain credentials");
                True(!source.Contains("passwordBox.Text"), "adapter never reads password box");
                Equal(2, Regex.Matches(source, @"finally\s*\{\s*SetBusy\(false\);").Count,
                    "both terminal workflows release busy state");
            });

            Console.WriteLine("ODJ GUI regression cases: " + cases + "; failures: " + failures + ".");
            Console.WriteLine("Dialog results and terminal operations were simulated; no djoin, UAC request, restart or AD mutation was executed.");
            Console.WriteLine("MainForm routing/adapter checks above are source-contract checks, not real UAC or dialog automation.");
            Environment.ExitCode = failures == 0 ? 0 : 1;
        }

        private static void Run(string name, Action test)
        {
            cases++;
            try
            {
                test();
                Console.WriteLine("PASS: " + name);
            }
            catch (Exception ex)
            {
                failures++;
                Console.Error.WriteLine("FAIL: " + name + ": " + ex.GetType().Name + ": " + ex.Message);
            }
        }

        private static void True(bool value, string message)
        {
            if (!value) throw new InvalidOperationException(message);
        }

        private static void Equal<T>(T expected, T actual, string message)
        {
            if (!EqualityComparer<T>.Default.Equals(expected, actual))
                throw new InvalidOperationException(message + ": expected " + expected + ", actual " + actual);
        }

        private static void AssertNoExecution(Fixture fixture)
        {
            Equal(0, fixture.ApplyCalls, "Apply not executed");
            Equal(0, fixture.ProvisionCalls, "Provision not executed");
        }

        private sealed class Fixture
        {
            internal readonly FakeDialogs Dialogs = new FakeDialogs();
            internal readonly OdjGuiWorkflow Workflow;
            internal int ApplyCalls;
            internal int ProvisionCalls;
            internal string AppliedPath;
            internal OdjProvisionRequest Provisioned;
            internal bool ThrowProvision;

            internal Fixture()
            {
                Workflow = new OdjGuiWorkflow(Dialogs,
                    delegate(string path)
                    {
                        ApplyCalls++;
                        AppliedPath = path;
                        Dialogs.Events.Add("apply");
                    },
                    delegate(OdjProvisionRequest request)
                    {
                        ProvisionCalls++;
                        Provisioned = request;
                        Dialogs.Events.Add("provision");
                        if (ThrowProvision) throw new IOException("simulated terminal failure");
                    });
            }
        }

        private sealed class FakeDialogs : IOdjGuiDialogs
        {
            internal DialogResult Mode = DialogResult.No;
            internal bool Elevated = true;
            internal string Blob = @"C:\odj-tests\input.txt";
            internal DialogResult ApplyConfirmation = DialogResult.Yes;
            internal string Domain = "example.com";
            internal string Computer = "PC-01";
            internal DialogResult Reuse = DialogResult.No;
            internal string Output = @"C:\odj-tests\output.txt";
            internal string Identity = @"EXAMPLE\operator";
            internal DialogResult ProvisionConfirmation = DialogResult.Yes;
            internal OdjProvisionRequest Confirmed;
            internal Action OnMode;
            internal Action OnProvisionConfirmation;
            internal readonly List<string> Events = new List<string>();
            internal readonly List<string> Errors = new List<string>();

            public DialogResult ChooseMode()
            {
                Events.Add("mode");
                if (OnMode != null) OnMode();
                return Mode;
            }
            public bool EnsureApplyElevation() { Events.Add("elevation"); return Elevated; }
            public string ChooseApplyBlob() { Events.Add("blob"); return Blob; }
            public DialogResult ConfirmApply(string path) { Events.Add("confirm-apply"); return ApplyConfirmation; }
            public string GetTargetDomain() { Events.Add("domain"); return Domain; }
            public string ChooseComputerName() { Events.Add("computer"); return Computer; }
            public DialogResult ChooseReuse() { Events.Add("reuse"); return Reuse; }
            public string ChooseOutputFile(string computerName) { Events.Add("output"); return Output; }
            public string GetWindowsIdentity() { Events.Add("identity"); return Identity; }
            public DialogResult ConfirmProvision(OdjProvisionRequest request)
            {
                Events.Add("confirm-provision");
                Confirmed = request;
                if (OnProvisionConfirmation != null) OnProvisionConfirmation();
                return ProvisionConfirmation;
            }
            public void ShowValidationError(string message) { Events.Add("error"); Errors.Add(message); }
        }
    }
}
