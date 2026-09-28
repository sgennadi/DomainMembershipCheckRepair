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
                        form.CreateControl();

                        if (scenario.Scale != 1.0F)
                            form.Scale(new SizeF(scenario.Scale, scenario.Scale));

                        Size logicalMinimum = new Size(
                            Math.Max(1, (int)Math.Round(640 * scenario.Scale)),
                            Math.Max(1, (int)Math.Round(480 * scenario.Scale)));

                        Size requested = new Size(
                            Math.Max(1, (int)Math.Round(980 * scenario.Scale)),
                            Math.Max(1, (int)Math.Round(820 * scenario.Scale)));

                        form.Size = UiLayoutHelper.CalculateFittedSize(
                            requested,
                            scenario.WorkingArea,
                            20,
                            logicalMinimum);

                        form.PerformLayout();

                        if (form.scrollHost == null)
                            failures.Add(scenario.Name + ": scroll host was not created.");
                        else
                        {
                            form.scrollHost.PerformLayout();

                            if (!form.scrollHost.AutoScroll)
                                failures.Add(scenario.Name + ": scroll host AutoScroll is disabled.");

                            if (form.scrollHost.Controls.Count == 0)
                                failures.Add(scenario.Name + ": root UI content is missing.");

                            if (form.scrollHost.ClientSize.Width <= 0 ||
                                form.scrollHost.ClientSize.Height <= 0)
                            {
                                failures.Add(scenario.Name + ": scroll host has an invalid client size.");
                            }
                        }

                        ValidateRequiredControls(
                            form,
                            scenario.Name,
                            failures);

                        ValidateControlTree(
                            form,
                            scenario.Name,
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
                failures.Add(scenario + ": negative control size detected for " + root.GetType().Name + ".");

            Button button = root as Button;
            if (button != null &&
                (button.Width <= 0 || button.Height <= 0))
            {
                failures.Add(
                    scenario + ": button has invalid size: " +
                    button.Text);
            }

            foreach (Control child in root.Controls)
                ValidateControlTree(child, scenario, failures);
        }

        private static bool HasScenarioFailure(
            string scenario,
            List<string> failures)
        {
            string prefix = scenario + ":";
            foreach (string failure in failures)
            {
                if (failure.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }
    }
}
