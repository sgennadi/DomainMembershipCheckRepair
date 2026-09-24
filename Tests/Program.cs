using System;
using System.Collections.Generic;

namespace DomainMembershipCheckRepair
{
    internal static class TestProgram
    {
        private static int failures;

        private static void Main()
        {
            TestComputerNames();
            TestUserNames();
            TestDomainHints();
            TestLdapEscaping();
            TestSuggestedNames();
            TestDirectoryServerNormalization();
            TestElevationActions();
            TestGuiResumeOptions();
            TestNetSetupErrorMapping();

            if (failures == 0)
            {
                Console.WriteLine("All DomainMembershipCheckRepair tests passed.");
                Environment.ExitCode = 0;
                return;
            }

            Console.Error.WriteLine(failures + " test(s) failed.");
            Environment.ExitCode = 1;
        }

        private static void TestComputerNames()
        {
            AssertNull(DomainValidation.ValidateComputerName("PC-01"), "PC-01 valid");
            AssertNull(DomainValidation.ValidateComputerName("A"), "single character valid");
            AssertNotNull(DomainValidation.ValidateComputerName("-PC"), "leading hyphen invalid");
            AssertNotNull(DomainValidation.ValidateComputerName("PC-"), "trailing hyphen invalid");
            AssertNotNull(DomainValidation.ValidateComputerName("PC_NAME"), "underscore invalid");
            AssertNotNull(DomainValidation.ValidateComputerName("12345"), "numeric-only invalid");
            AssertNotNull(DomainValidation.ValidateComputerName("ABCDEFGHIJKLMNOP"), "16 chars invalid");
        }

        private static void TestUserNames()
        {
            string normalized;
            string error;
            AssertTrue(DomainValidation.TryValidateUserName(@"EXAMPLE\admin", out normalized, out error), "DOMAIN user accepted");
            AssertEqual(@"EXAMPLE\admin", normalized, "DOMAIN user normalized");
            AssertTrue(DomainValidation.TryValidateUserName("admin@example.com", out normalized, out error), "UPN accepted");
            AssertEqual("admin@example.com", normalized, "UPN normalized");
            AssertFalse(DomainValidation.TryValidateUserName("admin", out normalized, out error), "short user rejected");
            AssertFalse(DomainValidation.TryValidateUserName("a@b@c", out normalized, out error), "multiple @ rejected");
        }

        private static void TestDomainHints()
        {
            AssertEqual("EXAMPLE", DomainValidation.ExtractDomainHintFromUser(@"EXAMPLE\admin"), "NetBIOS domain hint");
            AssertEqual("example.com", DomainValidation.ExtractDomainHintFromUser("admin@example.com"), "UPN domain hint");
            AssertEqual(String.Empty, DomainValidation.ExtractDomainHintFromUser("admin"), "short user has no hint");
        }

        private static void TestLdapEscaping()
        {
            AssertEqual(@"pc\2a\28x\29\5c\00", DomainValidation.EscapeLdapFilterValue("pc*(x)\\\0"), "LDAP escaping");
        }

        private static void TestSuggestedNames()
        {
            string value = DomainValidation.CreateSuggestedName("WORKSTATION12345");
            AssertTrue(value.Length <= 15, "suggested name <= 15");
            AssertTrue(value.EndsWith("-2", StringComparison.Ordinal), "suggested name suffix");
        }

        private static void TestDirectoryServerNormalization()
        {
            AssertEqual("dc01.example.com", DomainValidation.NormalizeDirectoryServer(@"\\dc01.example.com"), "UNC-style DC normalization");
            AssertEqual("dc01.example.com", DomainValidation.NormalizeDirectoryServer("LDAP://dc01.example.com/"), "LDAP URL normalization");
        }


        private static void TestElevationActions()
        {
            AssertTrue(ElevationHelper.RequiresElevation("repair"), "repair requires elevation");
            AssertTrue(ElevationHelper.RequiresElevation("join"), "join requires elevation");
            AssertTrue(ElevationHelper.RequiresElevation("rename"), "rename requires elevation");
            AssertTrue(ElevationHelper.RequiresElevation("restart"), "restart requires elevation");
            AssertTrue(ElevationHelper.RequiresElevation("mii-disable"), "mii-disable requires elevation");
            AssertTrue(ElevationHelper.RequiresElevation("odj-apply"), "odj-apply requires elevation");
            AssertTrue(ElevationHelper.RequiresElevation("safe-fixes"), "safe-fixes requires elevation");

            AssertFalse(ElevationHelper.RequiresElevation("status"), "status does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("check"), "check does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("detect"), "detect does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("ad-check"), "ad-check does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("diagnose"), "diagnose does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("export-diagnostics"), "export diagnostics does not require elevation");
        }

        private static void TestGuiResumeOptions()
        {
            string[] args = new string[]
            {
                "--resume-action", "join",
                "--elevation-attempted",
                "--domain", "example.com",
                "--user", @"EXAMPLE\admin",
                "--dc", @"\\dc01.example.com",
                "--no-log"
            };

            GuiResumeOptions options = ElevationHelper.ParseGuiResumeOptions(args);
            AssertEqual("join", options.Action, "GUI resume action");
            AssertEqual("example.com", options.Domain, "GUI resume domain");
            AssertEqual(@"EXAMPLE\admin", options.User, "GUI resume user");
            AssertEqual("dc01.example.com", options.PreferredDc, "GUI resume preferred DC");
            AssertTrue(options.ElevationAttempted, "GUI resume elevation marker");

            GuiResumeOptions invalid = ElevationHelper.ParseGuiResumeOptions(
                new string[] { "--resume-action", "diagnose", "--elevation-attempted" });
            AssertEqual(String.Empty, invalid.Action, "read-only GUI resume action rejected");
            AssertTrue(invalid.ElevationAttempted, "invalid resume still records elevation marker");

            GuiResumeOptions postReboot = ElevationHelper.ParseGuiResumeOptions(
                new string[] { "--resume-action", "post-reboot-check", "--domain", "example.com" });
            AssertEqual("post-reboot-check", postReboot.Action, "post reboot resume action");
            AssertEqual("example.com", postReboot.Domain, "post reboot domain");
        }

        private static void TestNetSetupErrorMapping()
        {
            string reuse = NetSetupLogAnalyzer.ExplainCode("0xAAC");
            AssertTrue(reuse.IndexOf("reuse", StringComparison.OrdinalIgnoreCase) >= 0, "0xAAC account reuse mapping");

            string rpc = NetSetupLogAnalyzer.ExplainCode("0x6ba");
            AssertTrue(rpc.IndexOf("RPC", StringComparison.OrdinalIgnoreCase) >= 0, "0x6BA RPC mapping");

            AssertEqual(String.Empty, NetSetupLogAnalyzer.ExplainCode("0xDEADBEEF"), "unknown NetSetup code");
        }

        private static void AssertTrue(bool value, string name)
        {
            if (!value) Fail(name);
        }

        private static void AssertFalse(bool value, string name)
        {
            if (value) Fail(name);
        }

        private static void AssertNull(object value, string name)
        {
            if (value != null) Fail(name);
        }

        private static void AssertNotNull(object value, string name)
        {
            if (value == null) Fail(name);
        }

        private static void AssertEqual(string expected, string actual, string name)
        {
            if (!String.Equals(expected, actual, StringComparison.Ordinal))
                Fail(name + " (expected '" + expected + "', actual '" + actual + "')");
        }

        private static void Fail(string name)
        {
            failures++;
            Console.Error.WriteLine("FAIL: " + name);
        }
    }
}
