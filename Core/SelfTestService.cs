using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Management;
using System.Text;
using Microsoft.Win32;

namespace DomainMembershipCheckRepair
{
    internal sealed class SelfTestItem
    {
        internal string Name = String.Empty;
        internal string Status = String.Empty;
        internal string Details = String.Empty;
    }

    internal sealed class SelfTestResult
    {
        internal readonly List<SelfTestItem> Items = new List<SelfTestItem>();
        internal bool HasFailure;
    }

    internal static class SelfTestService
    {
        internal static SelfTestResult Run(string domain, string preferredDc)
        {
            SelfTestResult r = new SelfTestResult();

            Add(r, ".NET runtime", "PASS", Environment.Version.ToString());
            Add(r, "Process architecture", "PASS", BuildInfo.TargetArchitecture + " / " +
                (Environment.Is64BitProcess ? "64-bit process" : "32-bit process"));

            TestSystemBinary(r, "nltest.exe");
            TestSystemBinary(r, "w32tm.exe");
            TestSystemBinary(r, "klist.exe");
            TestSystemBinary(r, "djoin.exe");
            TestSystemBinary(r, "nslookup.exe");
            TestSystemBinary(r, "sc.exe");
            TestSystemBinary(r, "net.exe");
            TestOptionalSystemBinary(r, "repadmin.exe", "Optional RSAT AD DS replication diagnostics");
            TestDnToDnsConversion(r);
            TestTemporaryWrite(r);
            TestRegistryRead(r);
            TestWmi(r);
            TestEventLogApi(r);
            TestDpiConfig(r);

            string targetDomain = (domain ?? String.Empty).Trim();
            if (!String.IsNullOrWhiteSpace(targetDomain))
            {
                DomainDiscoveryResult discovery = NativeMethods.DiscoverDomain(targetDomain, false);
                Add(
                    r,
                    "DC Locator API",
                    discovery.Success ? "PASS" : "WARN",
                    discovery.Success
                        ? First(discovery.DomainControllerName, "DC discovered")
                        : NativeMethods.FormatError(discovery.StatusCode));
            }
            else
            {
                Add(r, "DC Locator API", "SKIP", "No target domain was supplied.");
            }

            string dc = DomainValidation.NormalizeDirectoryServer(preferredDc);
            if (!String.IsNullOrWhiteSpace(dc))
            {
                try
                {
                    using (System.DirectoryServices.DirectoryEntry root =
                        new System.DirectoryServices.DirectoryEntry("LDAP://" + dc + "/RootDSE"))
                    {
                        string nc = Convert.ToString(root.Properties["defaultNamingContext"].Value);
                        Add(
                            r,
                            "LDAP RootDSE API",
                            String.IsNullOrWhiteSpace(nc) ? "WARN" : "PASS",
                            String.IsNullOrWhiteSpace(nc) ? "No naming context returned." : nc);
                    }
                }
                catch (Exception ex)
                {
                    Add(r, "LDAP RootDSE API", "WARN", ex.Message);
                }
            }
            else
            {
                Add(r, "LDAP RootDSE API", "SKIP", "No preferred DC was supplied.");
            }

            foreach (SelfTestItem item in r.Items)
            {
                if (item.Status == "FAIL")
                {
                    r.HasFailure = true;
                    break;
                }
            }

            return r;
        }

        internal static string ToText(SelfTestResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("DomainMembershipCheckRepair self-test");
            sb.AppendLine("====================================");
            foreach (SelfTestItem item in r.Items)
                sb.AppendLine(item.Status.PadRight(5) + " | " + item.Name + " | " + item.Details);
            sb.AppendLine();
            sb.AppendLine("Overall: " + (r.HasFailure ? "FAIL" : "PASS/WARN"));
            return sb.ToString();
        }

        private static void TestSystemBinary(SelfTestResult r, string name)
        {
            string path = Path.Combine(Environment.SystemDirectory, name);
            Add(
                r,
                "Windows tool " + name,
                File.Exists(path) ? "PASS" : "FAIL",
                File.Exists(path) ? path : "Not found in System32.");
        }

        private static void TestOptionalSystemBinary(
            SelfTestResult r,
            string name,
            string purpose)
        {
            string path = Path.Combine(Environment.SystemDirectory, name);
            Add(
                r,
                "Windows tool " + name,
                File.Exists(path) ? "PASS" : "WARN",
                File.Exists(path)
                    ? path
                    : "Not found in System32. " + purpose + " will be unavailable.");
        }

        private static void TestDnToDnsConversion(SelfTestResult r)
        {
            const string source = "DC=yosh,DC=ac,DC=il";
            const string expected = "yosh.ac.il";
            string actual = DomainValidation.DnToDns(source);

            Add(
                r,
                "AD DN to DNS conversion",
                String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase) ? "PASS" : "FAIL",
                source + " -> " + actual);
        }

        private static void TestTemporaryWrite(SelfTestResult r)
        {
            string path = Path.Combine(
                Path.GetTempPath(),
                "DomainMembershipCheckRepair-selftest-" + Guid.NewGuid().ToString("N") + ".tmp");

            try
            {
                File.WriteAllText(path, "test", Encoding.ASCII);
                File.Delete(path);
                Add(r, "Temporary file write", "PASS", Path.GetTempPath());
            }
            catch (Exception ex)
            {
                Add(r, "Temporary file write", "FAIL", ex.Message);
            }
        }

        private static void TestRegistryRead(SelfTestResult r)
        {
            try
            {
                using (RegistryKey key = Registry.LocalMachine.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
                {
                    string build = key == null
                        ? String.Empty
                        : Convert.ToString(key.GetValue("CurrentBuildNumber")) ?? String.Empty;

                    Add(
                        r,
                        "HKLM registry read",
                        key == null ? "FAIL" : "PASS",
                        key == null ? "CurrentVersion key unavailable." : "Build " + build);
                }
            }
            catch (Exception ex)
            {
                Add(r, "HKLM registry read", "FAIL", ex.Message);
            }
        }

        private static void TestWmi(SelfTestResult r)
        {
            try
            {
                using (ManagementObjectSearcher searcher =
                    new ManagementObjectSearcher("SELECT Caption FROM Win32_OperatingSystem"))
                using (ManagementObjectCollection items = searcher.Get())
                {
                    string caption = String.Empty;
                    foreach (ManagementObject item in items)
                    {
                        caption = Convert.ToString(item["Caption"]) ?? String.Empty;
                        break;
                    }

                    Add(
                        r,
                        "WMI/CIM provider",
                        String.IsNullOrWhiteSpace(caption) ? "WARN" : "PASS",
                        First(caption, "Query succeeded but Caption was empty."));
                }
            }
            catch (Exception ex)
            {
                Add(r, "WMI/CIM provider", "WARN", ex.Message);
            }
        }

        private static void TestEventLogApi(SelfTestResult r)
        {
            try
            {
                EventLogQuery query = new EventLogQuery(
                    "System",
                    PathType.LogName,
                    "*[System[(Level=1 or Level=2 or Level=3)]]");
                query.ReverseDirection = true;

                using (EventLogReader reader = new EventLogReader(query))
                using (EventRecord record = reader.ReadEvent())
                {
                    Add(
                        r,
                        "Windows Event Log API",
                        "PASS",
                        record == null ? "API available; no matching event required." : "System log readable.");
                }
            }
            catch (Exception ex)
            {
                Add(r, "Windows Event Log API", "WARN", ex.Message);
            }
        }

        private static void TestDpiConfig(SelfTestResult r)
        {
            try
            {
                string configPath = System.Windows.Forms.Application.ExecutablePath + ".config";
                if (!File.Exists(configPath))
                {
                    Add(r, "Per-Monitor DPI config", "WARN", "Application .config file was not found.");
                    return;
                }

                string text = File.ReadAllText(configPath);
                bool perMonitor = text.IndexOf("PerMonitorV2", StringComparison.OrdinalIgnoreCase) >= 0;
                bool autoResize = text.IndexOf("EnableWindowsFormsHighDpiAutoResizing", StringComparison.OrdinalIgnoreCase) >= 0;

                Add(
                    r,
                    "Per-Monitor DPI config",
                    perMonitor && autoResize ? "PASS" : "WARN",
                    "PerMonitorV2=" + perMonitor + ", HighDpiAutoResizing=" + autoResize);
            }
            catch (Exception ex)
            {
                Add(r, "Per-Monitor DPI config", "WARN", ex.Message);
            }
        }

        private static void Add(
            SelfTestResult r,
            string name,
            string status,
            string details)
        {
            SelfTestItem item = new SelfTestItem();
            item.Name = name;
            item.Status = status;
            item.Details = details ?? String.Empty;
            r.Items.Add(item);
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
