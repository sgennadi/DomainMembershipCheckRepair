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
            TestDnToDnsConversion();
            TestElevationActions();
            TestGuiResumeOptions();
            TestNetSetupErrorMapping();
            TestUiLayoutMath();
            TestKerberosEncryptionTypeDecoding();
            TestRemoteProtocolArguments();
            TestReplicationSummaryParsing();
            TestExpectedSpns();
            TestSmbKerberosMismatchClassification();

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


        private static void TestDnToDnsConversion()
        {
            AssertEqual(
                "yosh.ac.il",
                DomainValidation.DnToDns("DC=yosh,DC=ac,DC=il"),
                "DN to DNS conversion");

            AssertEqual(
                "example.com",
                DomainValidation.DnToDns("OU=Computers,DC=example,DC=com"),
                "DN to DNS ignores non-DC components");

            AssertEqual(
                String.Empty,
                DomainValidation.DnToDns(String.Empty),
                "empty DN converts to empty DNS");
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

        private static void TestKerberosEncryptionTypeDecoding()
        {
            string rc4 = HardeningDiagnosticsService.DecodeEncryptionTypes(0x4);
            AssertTrue(rc4.IndexOf("RC4", StringComparison.OrdinalIgnoreCase) >= 0, "RC4 encryption flag decoded");

            string aes = HardeningDiagnosticsService.DecodeEncryptionTypes(0x18);
            AssertTrue(aes.IndexOf("AES128", StringComparison.OrdinalIgnoreCase) >= 0, "AES128 encryption flag decoded");
            AssertTrue(aes.IndexOf("AES256", StringComparison.OrdinalIgnoreCase) >= 0, "AES256 encryption flag decoded");

            string mixed = HardeningDiagnosticsService.DecodeEncryptionTypes(0x1C);
            AssertTrue(mixed.IndexOf("RC4", StringComparison.OrdinalIgnoreCase) >= 0, "mixed RC4 flag decoded");
            AssertTrue(mixed.IndexOf("AES256", StringComparison.OrdinalIgnoreCase) >= 0, "mixed AES flag decoded");
        }

        private static void TestRemoteProtocolArguments()
        {
            AssertEqual(
                @"\\dc01.example.com query Netlogon",
                ProtocolDiagnosticsService.BuildRemoteScArguments(@"\\dc01.example.com", "Netlogon"),
                "SC remote target uses UNC");

            AssertEqual(
                @"view \\dc01.example.com",
                ProtocolDiagnosticsService.BuildRemoteNetViewArguments("dc01.example.com"),
                "NET VIEW remote target uses UNC");
        }

        private static void TestReplicationSummaryParsing()
        {
            string healthy =
                "Source DSA          largest delta    fails/total %%   error\r\n" +
                " DC01                    05m:10s    0 /   5    0\r\n";

            string failed =
                "Source DSA          largest delta    fails/total %%   error\r\n" +
                " DC01                    05m:10s    2 /   5   40   1722\r\n";

            string accessDenied =
                "DsReplicaGetInfo() failed with status 8453 (0x2105): Replication access was denied.\r\n";

            AssertFalse(
                ReplicationMetadataService.HasReplicationFailures(healthy),
                "repadmin healthy summary is not a failure");

            AssertTrue(
                ReplicationMetadataService.HasReplicationFailures(failed),
                "repadmin non-zero failure count detected");

            AssertFalse(
                ReplicationMetadataService.HasReplicationFailures(accessDenied),
                "repadmin access denied is not a replication health failure");

            AssertTrue(
                ReplicationMetadataService.IsAccessDenied(accessDenied),
                "repadmin replication access denied is recognized");

            AssertEqual(
                "/replsummary \"dc01.example.com\"",
                ReplicationMetadataService.BuildReplSummaryArguments(@"\\dc01.example.com"),
                "repadmin summary targets preferred DC");
        }

        private static void TestExpectedSpns()
        {
            string[] values = SpnCollisionAnalyzer.BuildExpectedSpns(
                "PC01",
                "PC01.example.com");

            AssertTrue(Array.Exists(values, delegate(string value)
            {
                return String.Equals(value, "HOST/PC01", StringComparison.OrdinalIgnoreCase);
            }), "HOST short SPN included");

            AssertTrue(Array.Exists(values, delegate(string value)
            {
                return String.Equals(value, "HOST/PC01.example.com", StringComparison.OrdinalIgnoreCase);
            }), "HOST FQDN SPN included");

            AssertTrue(Array.Exists(values, delegate(string value)
            {
                return String.Equals(value, "CIFS/PC01", StringComparison.OrdinalIgnoreCase);
            }), "CIFS short SPN included");

            AssertTrue(Array.Exists(values, delegate(string value)
            {
                return String.Equals(value, "CIFS/PC01.example.com", StringComparison.OrdinalIgnoreCase);
            }), "CIFS FQDN SPN included");

            string[] deduplicated = SpnCollisionAnalyzer.BuildExpectedSpns("PC01", "PC01");
            AssertEqualInt(4, deduplicated.Length, "duplicate short/FQDN SPNs removed");
        }

        private static void TestSmbKerberosMismatchClassification()
        {
            AssertTrue(
                SmbKerberosAuthAnalyzer.HasKerberosSmbMismatch("FAILED", "OK"),
                "Kerberos failure with SMB success detected");

            AssertTrue(
                SmbKerberosAuthAnalyzer.HasKerberosSmbMismatch("FAILED / TIMEOUT", "OK"),
                "Kerberos timeout with SMB success detected");

            AssertFalse(
                SmbKerberosAuthAnalyzer.HasKerberosSmbMismatch("NOT TESTED", "OK"),
                "untested Kerberos is not reported as fallback evidence");

            AssertFalse(
                SmbKerberosAuthAnalyzer.HasKerberosSmbMismatch("OK", "OK"),
                "healthy Kerberos is not mismatch");
        }

        private static void TestUiLayoutMath()
        {
            System.Drawing.Size fitted = UiLayoutHelper.CalculateFittedSize(
                new System.Drawing.Size(1200, 900),
                new System.Drawing.Size(1024, 768),
                20,
                new System.Drawing.Size(640, 480));

            AssertEqualInt(984, fitted.Width, "UI fitted width");
            AssertEqualInt(728, fitted.Height, "UI fitted height");

            System.Drawing.Size tiny = UiLayoutHelper.CalculateFittedSize(
                new System.Drawing.Size(300, 200),
                new System.Drawing.Size(640, 480),
                16,
                new System.Drawing.Size(640, 480));

            AssertEqualInt(608, tiny.Width, "UI minimum clamped to working width");
            AssertEqualInt(448, tiny.Height, "UI minimum clamped to working height");
        }

        private static void AssertEqualInt(int expected, int actual, string name)
        {
            if (expected != actual)
                Fail(name + " (expected '" + expected + "', actual '" + actual + "')");
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
