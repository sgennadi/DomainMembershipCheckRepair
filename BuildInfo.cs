using System;

namespace DomainMembershipCheckRepair
{
    internal static class BuildInfo
    {
        internal const string Version = "1.1.0";

        internal static string TargetArchitecture
        {
            get
            {
#if ARCH_ARM64
                return "ARM64";
#elif ARCH_X64
                return "x64";
#elif ARCH_X86
                return "x86";
#else
                return "AnyCPU";
#endif
            }
        }

        internal static string RuntimeSummary
        {
            get
            {
                string process = Environment.Is64BitProcess ? "64-bit" : "32-bit";
                string os = Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit";
                string envArch = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE") ?? String.Empty;
                if (String.IsNullOrWhiteSpace(envArch))
                    envArch = "unknown";
                return "Build " + TargetArchitecture + "; process " + process + "; OS " + os + " (" + envArch + "); CLR " + Environment.Version;
            }
        }
    }
}
