using System;
using System.Drawing;
using System.IO;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class IconTool
    {
        internal static int Run(CommandLine options)
        {
            string outputPath = Path.GetFullPath(options.Require("output"));
            string directory = Path.GetDirectoryName(outputPath);
            if (!String.IsNullOrWhiteSpace(directory))
                Directory.CreateDirectory(directory);

            using (FileStream stream = new FileStream(
                outputPath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None))
            {
                SystemIcons.Shield.Save(stream);
            }

            if (!File.Exists(outputPath))
                throw new IOException("Application icon was not created.");

            Console.WriteLine("Application icon generated.");
            return 0;
        }
    }
}
