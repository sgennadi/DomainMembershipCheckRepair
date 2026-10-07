using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal sealed partial class MainForm
    {
        private sealed class UiSmokeScenario
        {
            internal readonly string Name;
            internal readonly Size WorkingArea;
            internal readonly float Scale;

            internal UiSmokeScenario(
                string name,
                Size workingArea,
                float scale)
            {
                Name = name;
                WorkingArea = workingArea;
                Scale = scale;
            }
        }

        internal static int RunUiSmokeTests(bool json)
        {
            UiSmokeScenario[] scenarios = new UiSmokeScenario[]
            {
                new UiSmokeScenario("1366x768-100", new Size(1366, 768), 1.00F),
                new UiSmokeScenario("1366x768-125", new Size(1366, 768), 1.25F),
                new UiSmokeScenario("1920x1080-150", new Size(1920, 1080), 1.50F),
                new UiSmokeScenario("1920x1080-175", new Size(1920, 1080), 1.75F),
                new UiSmokeScenario("2560x1440-200", new Size(2560, 1440), 2.00F),
                new UiSmokeScenario("3840x2160-200", new Size(3840, 2160), 2.00F),
                new UiSmokeScenario("3840x2160-250", new Size(3840, 2160), 2.50F)
            };

            List<string> failures = new List<string>();
            List<string> passed = new List<string>();

            foreach (UiSmokeScenario scenario in scenarios)
            {
                try
                {
                    using (MainForm form = new MainForm(
                        false,
                        new string[0],
                        true))
                    {
                        PrepareFormForScenario(
                            form,
                            scenario,
                            UiStyle.MainWindowSize,
                            UiStyle.MainWindowMinimumSize);

                        ValidateMainForm(
                            form,
                            scenario.Name,
                            failures);

                        ValidateCustomDialogs(
                            scenario,
                            failures);

                        if (!HasScenarioFailure(
                            scenario.Name,
                            failures))
                        {
                            passed.Add(scenario.Name);
                        }
                    }
                }
                catch (Exception ex)
                {
                    failures.Add(
                        scenario.Name + ": exception: " +
                        ex.GetType().Name + ": " +
                        ex.Message);
                }
            }

            ValidateScaleRoundTrip(failures);

            if (json)
            {
                StringBuilder sb = new StringBuilder();
                sb.Append("{");
                sb.Append("\"action\":\"ui-smoke\",");
                sb.Append("\"architecture\":\"")
                    .Append(DiagnosticsService.JsonEscape(BuildInfo.TargetArchitecture))
                    .Append("\",");
                sb.Append("\"passed\":")
                    .Append(failures.Count == 0 ? "true" : "false")
                    .Append(",");
                sb.Append("\"scenariosPassed\":")
                    .Append(passed.Count)
                    .Append(",");
                sb.Append("\"scenarioCount\":")
                    .Append(scenarios.Length)
                    .Append(",");
                sb.Append("\"failures\":[");

                for (int i = 0; i < failures.Count; i++)
                {
                    if (i > 0)
                        sb.Append(",");
                    sb.Append("\"")
                        .Append(DiagnosticsService.JsonEscape(failures[i]))
                        .Append("\"");
                }

                sb.Append("]}");
                Console.WriteLine(sb.ToString());
            }
            else
            {
                Console.WriteLine("GUI / DPI smoke test");
                Console.WriteLine("====================");
                Console.WriteLine("Architecture: " + BuildInfo.TargetArchitecture);
                Console.WriteLine("Scenarios: " + scenarios.Length);
                Console.WriteLine("Passed: " + passed.Count);
                Console.WriteLine("Failed: " + failures.Count);

                foreach (string scenario in passed)
                    Console.WriteLine("PASS: " + scenario);

                foreach (string failure in failures)
                    Console.WriteLine("FAIL: " + failure);
            }

            return failures.Count == 0 ? 0 : 1;
        }

        private static void PrepareFormForScenario(
            Form form,
            UiSmokeScenario scenario,
            Size requestedLogicalSize,
            Size minimumLogicalSize)
        {
            form.CreateControl();

            if (scenario.Scale != 1.0F)
                form.Scale(new SizeF(scenario.Scale, scenario.Scale));

            Size requested = ScaleSize(
                requestedLogicalSize,
                scenario.Scale);
            Size minimum = ScaleSize(
                minimumLogicalSize,
                scenario.Scale);

            form.Size = UiLayoutHelper.CalculateFittedSize(
                requested,
                scenario.WorkingArea,
                20,
                minimum);

            form.PerformLayout();
            PerformLayoutRecursively(form);
        }

        private static Size ScaleSize(
            Size logical,
            float scale)
        {
            return new Size(
                Math.Max(1, (int)Math.Round(logical.Width * scale)),
                Math.Max(1, (int)Math.Round(logical.Height * scale)));
        }

        private static void PerformLayoutRecursively(Control root)
        {
            if (root == null)
                return;

            root.PerformLayout();
            foreach (Control child in root.Controls)
                PerformLayoutRecursively(child);
        }

        private static void ValidateMainForm(
            MainForm form,
            string scenario,
            List<string> failures)
        {
            if (form.scrollHost == null)
                failures.Add(scenario + ": scroll host was not created.");
            else
            {
                form.scrollHost.PerformLayout();

                if (!form.scrollHost.AutoScroll)
                    failures.Add(scenario + ": scroll host AutoScroll is disabled.");

                if (form.scrollHost.Controls.Count == 0)
                    failures.Add(scenario + ": root UI content is missing.");

                if (form.scrollHost.ClientSize.Width <= 0 ||
                    form.scrollHost.ClientSize.Height <= 0)
                {
                    failures.Add(scenario + ": scroll host has an invalid client size.");
                }
            }

            ValidateRequiredControls(
                form,
                scenario,
                failures);

            ValidateControlTree(
                form,
                scenario + "/MainForm",
                failures);
        }

        private static void ValidateCustomDialogs(
            UiSmokeScenario scenario,
            List<string> failures)
        {
            Form[] dialogs = new Form[]
            {
                new AccountConflictDialog(
                    "WORKSTATION-15",
                    "The existing Active Directory computer account requires operator review before the next recovery action.",
                    null,
                    false),
                new NewNameDialog(
                    "WORKSTATION-15",
                    "WORKSTATION-14"),
                new ComputerNameLookupDialog(
                    "WORKSTATION-15"),
                new ReportDialog(
                    "Advanced Diagnostics Report",
                    "Diagnostic report\r\n" +
                    "Domain controller: dc-long-name.example.internal\r\n" +
                    "A deliberately long report line remains horizontally scrollable rather than resizing the surrounding dialog.")
            };

            try
            {
                foreach (Form dialog in dialogs)
                {
                    PrepareFormForScenario(
                        dialog,
                        scenario,
                        dialog.Size,
                        new Size(320, 180));

                    ValidateControlTree(
                        dialog,
                        scenario + "/" + dialog.GetType().Name,
                        failures);
                }
            }
            finally
            {
                foreach (Form dialog in dialogs)
                    dialog.Dispose();
            }
        }

        private static void ValidateScaleRoundTrip(
            List<string> failures)
        {
            const string scenario = "dpi-cycle-100-200-150";

            try
            {
                using (MainForm form = new MainForm(
                    false,
                    new string[0],
                    true))
                {
                    form.CreateControl();
                    form.PerformLayout();

                    form.Scale(new SizeF(2.0F, 2.0F));
                    form.Size = UiLayoutHelper.CalculateFittedSize(
                        ScaleSize(UiStyle.MainWindowSize, 2.0F),
                        new Size(3840, 2160),
                        20,
                        ScaleSize(UiStyle.MainWindowMinimumSize, 2.0F));
                    PerformLayoutRecursively(form);
                    ValidateControlTree(
                        form,
                        scenario + "/200",
                        failures);

                    form.Scale(new SizeF(0.75F, 0.75F));
                    form.Size = UiLayoutHelper.CalculateFittedSize(
                        ScaleSize(UiStyle.MainWindowSize, 1.5F),
                        new Size(1920, 1080),
                        20,
                        ScaleSize(UiStyle.MainWindowMinimumSize, 1.5F));
                    PerformLayoutRecursively(form);
                    ValidateControlTree(
                        form,
                        scenario + "/150",
                        failures);
                }
            }
            catch (Exception ex)
            {
                failures.Add(
                    scenario + ": exception: " +
                    ex.GetType().Name + ": " +
                    ex.Message);
            }
        }

        private static void ValidateRequiredControls(
            MainForm form,
            string scenario,
            List<string> failures)
        {
            if (form.domainBox == null) failures.Add(scenario + ": domain box is missing.");
            if (form.dcBox == null) failures.Add(scenario + ": preferred DC box is missing.");
            if (form.userBox == null) failures.Add(scenario + ": user box is missing.");
            if (form.passwordBox == null) failures.Add(scenario + ": password box is missing.");
            if (form.checkButton == null) failures.Add(scenario + ": Check button is missing.");
            if (form.repairButton == null) failures.Add(scenario + ": Repair button is missing.");
            if (form.joinButton == null) failures.Add(scenario + ": Join button is missing.");
            if (form.advancedButton == null) failures.Add(scenario + ": Advanced button is missing.");
            if (form.supportBundleButton == null) failures.Add(scenario + ": Support Bundle button is missing.");
            if (form.rollbackLocalButton == null) failures.Add(scenario + ": Rollback Local button is missing.");
            if (form.cancelDiagnosticsButton == null) failures.Add(scenario + ": Cancel Diagnostics button is missing.");
            if (form.diagnosticsProgressLabel == null) failures.Add(scenario + ": diagnostic progress label is missing.");
        }

        private static void ValidateControlTree(
            Control root,
            string scenario,
            List<string> failures)
        {
            if (root == null)
                return;

            if (root.Width < 0 || root.Height < 0)
            {
                failures.Add(
                    scenario + ": negative control size detected for " +
                    DescribeControl(root) + ".");
            }

            if (root.Width == 0 || root.Height == 0)
            {
                Button button = root as Button;
                CheckBox checkBox = root as CheckBox;
                Label label = root as Label;
                if (button != null || checkBox != null ||
                    (label != null && !String.IsNullOrWhiteSpace(label.Text)))
                {
                    failures.Add(
                        scenario + ": visible text control has zero size: " +
                        DescribeControl(root) + ".");
                }
            }

            ValidateTextFit(
                root,
                scenario,
                failures);

            TabControl tabs = root as TabControl;
            if (tabs != null)
            {
                try
                {
                    tabs.CreateControl();
                    for (int i = 0; i < tabs.TabPages.Count; i++)
                    {
                        Rectangle tab = tabs.GetTabRect(i);
                        string text = tabs.TabPages[i].Text ?? String.Empty;
                        Size measured = TextRenderer.MeasureText(
                            text,
                            tabs.Font,
                            Size.Empty,
                            TextFormatFlags.SingleLine |
                            TextFormatFlags.NoPadding);

                        if (tab.Width > 0 &&
                            measured.Width + 14 > tab.Width)
                        {
                            failures.Add(
                                scenario + ": tab text may be clipped: '" +
                                text + "' measured " + measured.Width +
                                "px but tab width is " + tab.Width + "px.");
                        }
                    }
                }
                catch (InvalidOperationException ex)
                {
                    failures.Add(
                        scenario + ": unable to validate tab headers: " +
                        ex.Message);
                }
            }

            foreach (Control child in root.Controls)
                ValidateControlTree(child, scenario, failures);
        }

        private static void ValidateTextFit(
            Control control,
            string scenario,
            List<string> failures)
        {
            if (control == null ||
                String.IsNullOrWhiteSpace(control.Text))
            {
                return;
            }

            bool shouldFitPreferred =
                (control is Label && ((Label)control).AutoSize) ||
                (control is Button && ((Button)control).AutoSize) ||
                (control is CheckBox && ((CheckBox)control).AutoSize) ||
                (control is RadioButton && ((RadioButton)control).AutoSize) ||
                (control is LinkLabel && ((LinkLabel)control).AutoSize);

            if (shouldFitPreferred)
            {
                Size preferred = control.GetPreferredSize(Size.Empty);
                const int tolerance = 2;

                if (control.Width + tolerance < preferred.Width ||
                    control.Height + tolerance < preferred.Height)
                {
                    failures.Add(
                        scenario + ": text clipping detected for " +
                        DescribeControl(control) +
                        "; actual=" + control.Width + "x" + control.Height +
                        ", preferred=" + preferred.Width + "x" + preferred.Height + ".");
                }
            }

            GroupBox group = control as GroupBox;
            if (group != null)
            {
                Size measured = TextRenderer.MeasureText(
                    group.Text,
                    group.Font,
                    Size.Empty,
                    TextFormatFlags.SingleLine |
                    TextFormatFlags.NoPadding);

                if (group.ClientSize.Width > 0 &&
                    measured.Width + 24 > group.ClientSize.Width)
                {
                    failures.Add(
                        scenario + ": group title may be clipped: '" +
                        group.Text + "'.");
                }
            }
        }

        private static string DescribeControl(Control control)
        {
            string text = control.Text ?? String.Empty;
            if (text.Length > 60)
                text = text.Substring(0, 57) + "...";

            return control.GetType().Name +
                (String.IsNullOrWhiteSpace(text)
                    ? String.Empty
                    : " '" + text.Replace("\r", " ").Replace("\n", " ") + "'");
        }

        private static bool HasScenarioFailure(
            string scenario,
            List<string> failures)
        {
            string prefix = scenario + ":";
            string nestedPrefix = scenario + "/";
            foreach (string failure in failures)
            {
                if (failure.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase) ||
                    failure.StartsWith(
                    nestedPrefix,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
