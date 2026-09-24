using System;
using System.Windows.Forms;

namespace DomainMembershipCheckRepair
{
    internal static class Program
    {
        [STAThread]
        private static int Main(string[] args)
        {
            bool enableFileLogging = false;
            bool cliMode = false;
            bool helpRequested = false;

            if (args != null)
            {
                foreach (string raw in args)
                {
                    string arg = (raw ?? String.Empty).Trim();
                    if (arg.Equals("--log", StringComparison.OrdinalIgnoreCase) ||
                        arg.Equals("/log", StringComparison.OrdinalIgnoreCase))
                    {
                        enableFileLogging = true;
                    }
                    else if (arg.Equals("--no-log", StringComparison.OrdinalIgnoreCase) ||
                             arg.Equals("/no-log", StringComparison.OrdinalIgnoreCase))
                    {
                        enableFileLogging = false;
                    }
                    else if (arg.Equals("--cli", StringComparison.OrdinalIgnoreCase) ||
                             arg.Equals("/cli", StringComparison.OrdinalIgnoreCase))
                    {
                        cliMode = true;
                    }
                    else if (arg.Equals("--help", StringComparison.OrdinalIgnoreCase) ||
                             arg.Equals("-h", StringComparison.OrdinalIgnoreCase) ||
                             arg.Equals("/?", StringComparison.OrdinalIgnoreCase))
                    {
                        helpRequested = true;
                    }
                }
            }

            if (cliMode || helpRequested)
                return CliRunner.Run(args, enableFileLogging);

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm(enableFileLogging, args));
            return 0;
        }
    }
}
