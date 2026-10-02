using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.AccessControl;
using System.Security.Principal;

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
            TestDirectoryServerSelection();
            TestDnToDnsConversion();
            TestDomainArgumentValidation();
            TestWindowsCommandLineQuoting();
            TestWindowsArgumentListBuilding();
            TestOfflineDomainJoinArguments();
            TestSafeRecoveryArguments();
            TestProcessExecutableResolution();
            TestElevationActions();
            TestGuiResumeOptions();
            TestPostRebootResumeCommand();
            TestNetSetupErrorMapping();
            TestSamDomainJoinPolicyAccessDeniedEvidence();
            TestDomainJoinReuseEventClassification();
            TestUiLayoutMath();
            TestKerberosEncryptionTypeDecoding();
            TestRemoteProtocolArguments();
            TestReplicationSummaryParsing();
            TestExpectedSpns();
            TestSmbKerberosMismatchClassification();
            TestNetworkCredentialParsing();
            TestJsonReporting();
            TestDiagnosticExitCodes();
            TestSpnStateFingerprint();
            TestKerberosDeepParsing();
            TestLdapCompatibilityClassification();
            TestRpcEndpointParsing();
            TestRpcKnownInterfaces();
            TestIdentityConsistencyFilter();
            TestTransactionJournalParsing();
            TestTransactionJournalAtomicWrite();
            TestAdRecoveryPackageAtomicWrite();
            TestAdRecoveryHelpers();
            TestAdRestoreFinalSafety();
            TestProtectedStorageAclPolicy();
            TestSafetyBundleStoragePath();
            TestPrivateStagingAclPolicy();
            TestAdDeleteFinalSafety();
            TestSupportBundleSanitizer();
            TestSupportBundleZipRedaction();
            TestAtomicArchiveCommit();

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
            AssertEqual(String.Empty, DomainValidation.NormalizeDirectoryServer("dc01.example.com /syncall"), "DC with whitespace/extra argument rejected");
            AssertEqual(String.Empty, DomainValidation.NormalizeDirectoryServer("dc01.example.com\" /showrepl"), "DC with quote rejected");
            AssertEqual(String.Empty, DomainValidation.NormalizeDirectoryServer("dc01.example.com/path"), "DC with embedded path rejected");
            AssertTrue(DomainValidation.IsSafeDirectoryServer("[fe80::1]"), "IPv6-style DC accepted");
        }


        private static void TestDirectoryServerSelection()
        {
            AssertEqual(
                "dc01.example.com",
                DomainValidation.SelectDirectoryServer(@"\\dc01.example.com", @"\\dc02.example.com"),
                "explicit preferred DC wins over discovery");

            AssertEqual(
                "dc02.example.com",
                DomainValidation.SelectDirectoryServer(String.Empty, @"\\dc02.example.com"),
                "discovered DC used when preferred DC is empty");
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

        private static void TestDomainArgumentValidation()
        {
            AssertNull(
                DomainValidation.ValidateDomainArgument("example.com"),
                "DNS domain argument accepted");
            AssertNull(
                DomainValidation.ValidateDomainArgument("EXAMPLE"),
                "NetBIOS domain argument accepted");
            AssertNotNull(
                DomainValidation.ValidateDomainArgument("example.com /reuse"),
                "domain argument with injected option rejected");
            AssertNotNull(
                DomainValidation.ValidateDomainArgument("example.com\" /reuse"),
                "domain argument with quote rejected");
            AssertNotNull(
                DomainValidation.ValidateDomainArgument(@"example\child"),
                "domain argument with slash rejected");
            AssertNotNull(
                DomainValidation.ValidateDomainArgument(".example.com"),
                "domain argument with leading dot rejected");
            AssertNotNull(
                DomainValidation.ValidateDomainArgument("example..com"),
                "domain argument with empty DNS label rejected");
        }

        private static void TestWindowsCommandLineQuoting()
        {
            AssertEqual(
                "simple",
                WindowsCommandLine.QuoteArgument("simple"),
                "simple Windows argument stays unquoted");

            AssertEqual(
                "\"C:\\Path With Space\\file.txt\"",
                WindowsCommandLine.QuoteArgument(@"C:\Path With Space\file.txt"),
                "Windows argument with spaces is quoted");

            AssertEqual(
                "\"C:\\Path With Space\\\\\"",
                WindowsCommandLine.QuoteArgument("C:\\Path With Space\\"),
                "trailing backslash is doubled before closing quote");

            AssertEqual(
                "\"a\\\"b\"",
                WindowsCommandLine.QuoteArgument("a\"b"),
                "embedded quote is escaped using Windows argv rules");

            AssertEqual(
                "\"\"",
                WindowsCommandLine.QuoteArgument(String.Empty),
                "empty Windows argument is quoted");
        }

        private static void TestWindowsArgumentListBuilding()
        {
            AssertEqual(
                "one \"two words\" three",
                WindowsCommandLine.BuildArguments(
                    new string[] { "one", "two words", "three" }),
                "Windows argv builder quotes only the argument that needs it");

            AssertEqual(
                "get cifs/dc01.example.com \"\"",
                WindowsCommandLine.BuildArguments(
                    new string[] { "get", "cifs/dc01.example.com", String.Empty }),
                "Windows argv builder preserves an empty argument");

            AssertEqual(
                "a \"C:\\Path With Space\\\\\"",
                WindowsCommandLine.BuildArguments(
                    new string[] { "a", "C:\\Path With Space\\" }),
                "Windows argv builder preserves trailing backslashes");
        }

        private static void TestOfflineDomainJoinArguments()
        {
            AssertEqual(
                "/requestODJ /loadfile \"C:\\ODJ Files\\pc.txt\" /windowspath C:\\Windows /localos",
                OfflineDomainJoinService.BuildApplyArguments(
                    @"C:\ODJ Files\pc.txt",
                    @"C:\Windows"),
                "ODJ apply arguments use canonical quoting");

            AssertEqual(
                "/provision /domain example.com /machine PC-01 /savefile \"C:\\ODJ Files\\pc.txt\" /reuse",
                OfflineDomainJoinService.BuildProvisionArguments(
                    "example.com",
                    "PC-01",
                    @"C:\ODJ Files\pc.txt",
                    true),
                "ODJ provision arguments use canonical quoting and reuse flag");

            AssertEqual(
                "/provision /domain EXAMPLE /machine PC-01 /savefile C:\\Temp\\pc.txt",
                OfflineDomainJoinService.BuildProvisionArguments(
                    "EXAMPLE",
                    "PC-01",
                    @"C:\Temp\pc.txt",
                    false),
                "ODJ provision omits reuse when not requested");
        }

        private static void TestSafeRecoveryArguments()
        {
            AssertEqual(
                "/dsgetdc:example.com /force",
                SafeRecoveryService.BuildDcRediscoveryArguments("example.com"),
                "Safe Recovery DC rediscovery uses separate canonical argv tokens");

            bool rejected = false;
            try
            {
                SafeRecoveryService.BuildDcRediscoveryArguments(
                    "example.com /force");
            }
            catch (ArgumentException)
            {
                rejected = true;
            }

            AssertTrue(
                rejected,
                "Safe Recovery rejects injected domain options before nltest");
        }

        private static void TestProcessExecutableResolution()
        {
            string systemCmd =
                Path.Combine(Environment.SystemDirectory, "cmd.exe");

            if (File.Exists(systemCmd))
            {
                AssertEqual(
                    systemCmd,
                    ProcessRunner.ResolveExecutable("cmd.exe"),
                    "Process runner prefers trusted System32 executable");
            }

            string missing =
                Path.Combine(
                    Path.GetTempPath(),
                    "dmcr-missing-" + Guid.NewGuid().ToString("N") + ".exe");

            AssertEqual(
                String.Empty,
                ProcessRunner.ResolveExecutable(missing),
                "Process runner rejects a missing absolute executable path");

            AssertEqual(
                String.Empty,
                ProcessRunner.ResolveExecutable(
                    "dmcr-definitely-missing-tool.exe"),
                "Process runner does not fall back to PATH/current directory for an unresolved bare executable");
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
            AssertTrue(ElevationHelper.RequiresElevation("rollback-local"), "rollback-local requires elevation");
            AssertTrue(ElevationHelper.RequiresElevation("ad-restore"), "ad-restore requires elevation");
            AssertTrue(ElevationHelper.RequiresElevation("elevation-probe"), "elevation probe requires elevation");

            AssertFalse(ElevationHelper.RequiresElevation("status"), "status does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("check"), "check does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("detect"), "detect does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("ad-check"), "ad-check does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("diagnose"), "diagnose does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("export-diagnostics"), "export diagnostics does not require elevation");
            AssertFalse(ElevationHelper.RequiresElevation("ui-smoke"), "UI smoke does not require elevation");

            AssertTrue(ElevationHelper.RequiresRecoverySnapshot("repair"), "repair captures recovery snapshot");
            AssertTrue(ElevationHelper.RequiresRecoverySnapshot("join"), "join captures recovery snapshot");
            AssertTrue(ElevationHelper.RequiresRecoverySnapshot("rename"), "rename captures recovery snapshot");
            AssertTrue(ElevationHelper.RequiresRecoverySnapshot("mii-disable"), "mii-disable captures recovery snapshot");
            AssertTrue(ElevationHelper.RequiresRecoverySnapshot("odj-apply"), "odj-apply captures recovery snapshot");
            AssertTrue(ElevationHelper.RequiresRecoverySnapshot("safe-fixes"), "safe-fixes captures recovery snapshot");
            AssertTrue(ElevationHelper.RequiresRecoverySnapshot("rollback-local"), "rollback-local captures recovery snapshot");
            AssertTrue(ElevationHelper.RequiresRecoverySnapshot("ad-restore"), "ad-restore captures recovery snapshot");

            AssertFalse(ElevationHelper.RequiresRecoverySnapshot("restart"), "restart does not create recovery snapshot");
            AssertFalse(ElevationHelper.RequiresRecoverySnapshot("elevation-probe"), "elevation probe remains side-effect free");
            AssertFalse(ElevationHelper.RequiresRecoverySnapshot("status"), "status does not create recovery snapshot");

            AssertTrue(
                ElevationHelper.RedirectedPasswordRequiresPreElevation("ad-restore", true, false),
                "redirected password on elevated action requires caller to pre-elevate");
            AssertFalse(
                ElevationHelper.RedirectedPasswordRequiresPreElevation("ad-restore", true, true),
                "dry-run does not require pre-elevation for redirected password");
            AssertFalse(
                ElevationHelper.RedirectedPasswordRequiresPreElevation("status", true, false),
                "read-only action does not require pre-elevation for redirected password");
            AssertFalse(
                ElevationHelper.RedirectedPasswordRequiresPreElevation("ad-restore", false, false),
                "interactive password can use normal elevation broker");

            AssertEqual(
                "--resume-action join --domain example.com --user \"EXAMPLE\\admin user\"",
                ElevationHelper.BuildElevationArguments(
                    new string[]
                    {
                        "--resume-action",
                        "join",
                        "--domain",
                        "example.com",
                        "--user",
                        @"EXAMPLE\admin user"
                    }),
                "elevation relaunch uses shared canonical argv quoting");
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

            GuiResumeOptions rollback = ElevationHelper.ParseGuiResumeOptions(
                new string[] { "--resume-action", "rollback-local", "--elevation-attempted" });
            AssertEqual("rollback-local", rollback.Action, "rollback GUI resume action");
            AssertTrue(rollback.ElevationAttempted, "rollback resume elevation marker");

            GuiResumeOptions adRestore = ElevationHelper.ParseGuiResumeOptions(
                new string[] { "--resume-action", "ad-restore", "--elevation-attempted" });
            AssertEqual("ad-restore", adRestore.Action, "AD restore GUI resume action");
            AssertTrue(adRestore.ElevationAttempted, "AD restore resume elevation marker");
        }

        private static void TestPostRebootResumeCommand()
        {
            AssertEqual(
                "\"C:\\Program Files\\DomainMembershipCheckRepair\\DomainMembershipCheckRepair.exe\" --resume-action post-reboot-check --no-log --domain example.com",
                ResumeService.BuildRunOnceCommand(
                    @"C:\Program Files\DomainMembershipCheckRepair\DomainMembershipCheckRepair.exe",
                    " example.com "),
                "post-reboot RunOnce command uses canonical quoting and trims validated domain");

            AssertEqual(
                @"C:\Tools\DomainMembershipCheckRepair.exe --resume-action post-reboot-check --no-log",
                ResumeService.BuildRunOnceCommand(
                    @"C:\Tools\DomainMembershipCheckRepair.exe",
                    String.Empty),
                "post-reboot RunOnce command omits empty domain");

            bool badDomainRejected = false;
            try
            {
                ResumeService.BuildRunOnceCommand(
                    @"C:\Tools\DomainMembershipCheckRepair.exe",
                    "example.com --user attacker");
            }
            catch (ArgumentException)
            {
                badDomainRejected = true;
            }

            AssertTrue(
                badDomainRejected,
                "post-reboot RunOnce rejects option-injection-shaped domain");

            bool relativeExecutableRejected = false;
            try
            {
                ResumeService.BuildRunOnceCommand(
                    "DomainMembershipCheckRepair.exe",
                    "example.com");
            }
            catch (ArgumentException)
            {
                relativeExecutableRejected = true;
            }

            AssertTrue(
                relativeExecutableRejected,
                "post-reboot RunOnce rejects relative executable path");

            AssertEqual(
                "S-1-5-21-111-222-333-1001",
                ResumeService.SelectPostRebootTargetSid(
                    " S-1-5-21-111-222-333-1001 ",
                    "S-1-5-21-111-222-333-500"),
                "post-reboot target uses the detected interactive user SID");

            AssertEqual(
                String.Empty,
                ResumeService.SelectPostRebootTargetSid(
                    String.Empty,
                    "S-1-5-21-111-222-333-500"),
                "post-reboot target never falls back to current elevated process SID");

            AssertEqual(
                String.Empty,
                ResumeService.SelectPostRebootTargetSid(
                    null,
                    null),
                "post-reboot target fails closed when no interactive SID is known");
        }

        private static void TestNetSetupErrorMapping()
        {
            string reuse = NetSetupLogAnalyzer.ExplainCode("0xAAC");
            AssertTrue(reuse.IndexOf("reuse", StringComparison.OrdinalIgnoreCase) >= 0, "0xAAC account reuse mapping");
            AssertTrue(
                reuse.IndexOf("ComputerAccountReuseAllowList", StringComparison.OrdinalIgnoreCase) >= 0,
                "0xAAC guidance names supported DC reuse allow-list policy");
            AssertTrue(
                reuse.IndexOf("SAMRPC", StringComparison.OrdinalIgnoreCase) >= 0,
                "0xAAC guidance includes SAMRPC policy/access");

            string rpc = NetSetupLogAnalyzer.ExplainCode("0x6ba");
            AssertTrue(rpc.IndexOf("RPC", StringComparison.OrdinalIgnoreCase) >= 0, "0x6BA RPC mapping");

            AssertEqual(String.Empty, NetSetupLogAnalyzer.ExplainCode("0xDEADBEEF"), "unknown NetSetup code");
        }

        private static void TestSamDomainJoinPolicyAccessDeniedEvidence()
        {
            AssertTrue(
                NetSetupLogAnalyzer.HasSamDomainJoinPolicyAccessDeniedEvidence(
                    "NetpDsValidateComputerAccountReuseAttempt: returning NtStatus: c0000022, NetStatus: 5\r\n" +
                    "NetpCheckIfAccountShouldBeReused: Active Directory Policy check with SAM_DOMAIN_JOIN_POLICY_LEVEL_V2 returned NetStatus:0x5."),
                "SAM domain-join policy V2 access denied is detected");

            AssertTrue(
                NetSetupLogAnalyzer.HasSamDomainJoinPolicyAccessDeniedEvidence(
                    "NetpDsValidateComputerAccountReuseAttempt: access denied"),
                "SAM domain-join reuse validation access denied is detected");

            AssertFalse(
                NetSetupLogAnalyzer.HasSamDomainJoinPolicyAccessDeniedEvidence(
                    "SAM_DOMAIN_JOIN_POLICY_LEVEL_V2 returned NetStatus:0x0."),
                "successful SAM domain-join policy validation is not flagged");

            AssertFalse(
                NetSetupLogAnalyzer.HasSamDomainJoinPolicyAccessDeniedEvidence(
                    "Access denied while opening an unrelated file."),
                "unrelated access denied text is not treated as SAM domain-join policy denial");
        }

        private static void TestDomainJoinReuseEventClassification()
        {
            AssertTrue(
                EventTimelineService.IsRelevant(
                    "Netjoin",
                    4101,
                    "An attempt to re-use this account was prevented for security reasons."),
                "Netjoin 4101 reuse-block event is relevant");

            AssertTrue(
                EventTimelineService.IsRelevant(
                    "Directory-Services-SAM",
                    16998,
                    "The security account manager rejected a client request to re-use a computer account during domain join."),
                "Directory-Services-SAM 16998 reuse rejection is relevant");

            AssertTrue(
                EventTimelineService.IsRelevant(
                    String.Empty,
                    16996,
                    String.Empty),
                "Directory-Services-SAM malformed allow-list event ID is relevant");

            AssertTrue(
                EventTimelineService.IsRelevant(
                    String.Empty,
                    9999,
                    "NetpDsValidateComputerAccountReuseAttempt SAM_DOMAIN_JOIN_POLICY_LEVEL_V2 returned access denied."),
                "SAMRPC account-reuse policy evidence is relevant");

            AssertFalse(
                EventTimelineService.IsRelevant(
                    "Application",
                    1000,
                    "Unrelated application event."),
                "unrelated application event is ignored");
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
                "/replsummary dc01.example.com",
                ReplicationMetadataService.BuildReplSummaryArguments(@"\\dc01.example.com"),
                "repadmin summary targets preferred DC");

            AssertEqual(
                "/showobjmeta dc01.example.com \"CN=PC 01,OU=Lab,DC=example,DC=com\"",
                ReplicationMetadataService.BuildShowObjectMetadataArguments(
                    "dc01.example.com",
                    "CN=PC 01,OU=Lab,DC=example,DC=com"),
                "repadmin object metadata quotes a DN as one argv token");

            AssertEqual(
                "/showattr dc01.example.com \"CN=PC 01,OU=Lab,DC=example,DC=com\" /atts:objectGUID,pwdLastSet,whenChanged,uSNChanged,servicePrincipalName",
                ReplicationMetadataService.BuildShowAttributesArguments(
                    "dc01.example.com",
                    "CN=PC 01,OU=Lab,DC=example,DC=com"),
                "repadmin attribute query preserves the DN as one argv token");
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

        private static void TestNetworkCredentialParsing()
        {
            string user;
            string domain;

            AssertTrue(
                NetworkCredentialProcessRunner.TrySplitUser(@"EXAMPLE\admin", out user, out domain),
                "DOMAIN\\user parses for net-only credentials");
            AssertEqual("admin", user, "net-only DOMAIN user account");
            AssertEqual("EXAMPLE", domain, "net-only DOMAIN name");

            AssertTrue(
                NetworkCredentialProcessRunner.TrySplitUser("admin@example.com", out user, out domain),
                "UPN parses for net-only credentials");
            AssertEqual("admin@example.com", user, "net-only UPN account");
            AssertNull(domain, "UPN uses null logon domain");

            AssertFalse(
                NetworkCredentialProcessRunner.TrySplitUser("admin", out user, out domain),
                "short user rejected for net-only credentials");
        }

        private static void TestJsonReporting()
        {
            Dictionary<string, object> payload = new Dictionary<string, object>();
            payload["message"] = "line1\n\"quoted\"";
            payload["ok"] = true;
            payload["count"] = 2;

            string json = JsonReportSerializer.SerializeAction(
                "test-action",
                DiagnosticExitCodes.Partial,
                payload);

            AssertTrue(json.StartsWith("{", StringComparison.Ordinal), "JSON envelope starts with object");
            AssertTrue(json.IndexOf("\"action\":\"test-action\"", StringComparison.Ordinal) >= 0, "JSON action serialized");
            AssertTrue(json.IndexOf("\"exitCode\":23", StringComparison.Ordinal) >= 0, "JSON diagnostic exit serialized");
            AssertTrue(json.IndexOf("line1\\n\\\"quoted\\\"", StringComparison.Ordinal) >= 0, "JSON escaping serialized");
        }

        private static void TestDiagnosticExitCodes()
        {
            AssertEqualInt(
                DiagnosticExitCodes.NotTested,
                DiagnosticExitCodes.FromFindings(new string[0], false),
                "missing capability returns diagnostic not-tested");

            AssertEqualInt(
                DiagnosticExitCodes.FindingDetected,
                DiagnosticExitCodes.FromFindings(
                    new string[] { "HIGH: duplicate SPN detected" },
                    true),
                "HIGH finding returns diagnostic finding");

            AssertEqualInt(
                DiagnosticExitCodes.AccessDenied,
                DiagnosticExitCodes.FromFindings(
                    new string[] { "INFO: access denied for replication query" },
                    true),
                "access denied returns diagnostic access-denied");

            AssertEqualInt(
                DiagnosticExitCodes.Partial,
                DiagnosticExitCodes.FromFindings(
                    new string[] { "CHECK: optional data unavailable" },
                    true),
                "CHECK finding returns diagnostic partial");

            AssertEqualInt(
                DiagnosticExitCodes.Success,
                DiagnosticExitCodes.FromFindings(new string[0], true),
                "no findings returns diagnostic success");

            AssertEqualInt(
                DiagnosticExitCodes.AccessDenied,
                DiagnosticExitCodes.FromFindings(
                    new string[] { "INFO: LDAP access denied for current security context" },
                    false),
                "access denied wins over unavailable capability");

            AssertEqualInt(
                DiagnosticExitCodes.FindingDetected,
                DiagnosticExitCodes.FromFindings(
                    new string[] { "MEDIUM: hardening mismatch detected" },
                    true),
                "MEDIUM finding returns diagnostic finding");

            AssertEqualInt(
                DiagnosticExitCodes.Success,
                DiagnosticExitCodes.FromFindings(
                    new string[] { "INFO: optional policy evidence present" },
                    true),
                "INFO-only finding remains diagnostic success");

            AssertEqualInt(
                DiagnosticExitCodes.AccessDenied,
                DiagnosticExitCodes.FromFindings(
                    new string[] { "INFO: current security context does not have permission." },
                    true),
                "explicit no-permission wording returns diagnostic access-denied");
        }

        private static void TestSpnStateFingerprint()
        {
            SpnCollisionResult first = new SpnCollisionResult();
            SpnCollisionEntry a = new SpnCollisionEntry();
            a.Spn = "HOST/PC01";
            a.DistinguishedNames.Add("CN=PC01,OU=A,DC=example,DC=com");
            a.DistinguishedNames.Add("CN=PC01-OLD,OU=B,DC=example,DC=com");
            first.Entries.Add(a);

            SpnCollisionResult second = new SpnCollisionResult();
            SpnCollisionEntry b = new SpnCollisionEntry();
            b.Spn = "host/pc01";
            b.DistinguishedNames.Add("CN=PC01-OLD,OU=B,DC=example,DC=com");
            b.DistinguishedNames.Add("CN=PC01,OU=A,DC=example,DC=com");
            second.Entries.Add(b);

            AssertEqual(
                SpnCollisionAnalyzer.BuildStateFingerprint(first),
                SpnCollisionAnalyzer.BuildStateFingerprint(second),
                "SPN state fingerprint ignores case and DN ordering");
        }

        private static void TestKerberosDeepParsing()
        {
            string sample =
                "Client: user @ EXAMPLE.COM\r\n" +
                "Server: cifs/dc01.example.com @ EXAMPLE.COM\r\n" +
                "KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96\r\n" +
                "Session Key Type: AES-256-CTS-HMAC-SHA1-96\r\n" +
                "Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize\r\n" +
                "Start Time: 9/26/2026 10:00:00\r\n" +
                "End Time: 9/26/2026 20:00:00\r\n" +
                "Renew Time: 10/3/2026 10:00:00\r\n";

            KerberosTicketDetails ticket = KerberosDeepAnalyzer.ParseTicketText("CIFS", sample);
            AssertEqual("user @ EXAMPLE.COM", ticket.Client, "Kerberos client parsed");
            AssertEqual("cifs/dc01.example.com @ EXAMPLE.COM", ticket.Server, "Kerberos server parsed");
            AssertTrue(ticket.EncryptionType.IndexOf("AES-256", StringComparison.OrdinalIgnoreCase) >= 0, "Kerberos AES encryption parsed");
            AssertFalse(KerberosDeepAnalyzer.IsLegacyEncryption(ticket.EncryptionType), "AES is not legacy Kerberos encryption");
            AssertTrue(KerberosDeepAnalyzer.IsLegacyEncryption("RC4-HMAC"), "RC4 detected as legacy Kerberos encryption");
        }

        private static void TestLdapCompatibilityClassification()
        {
            AssertEqual(
                "FAILED / SIGNING REQUIRED",
                LdapCompatibilityAnalyzer.ClassifyException(new Exception("stronger authentication required")),
                "LDAP signing requirement classified");

            AssertEqual(
                "FAILED / CREDENTIALS",
                LdapCompatibilityAnalyzer.ClassifyException(new Exception("invalid credentials")),
                "LDAP invalid credentials classified");

            AssertEqual(
                "FAILED / TLS",
                LdapCompatibilityAnalyzer.ClassifyException(new Exception("TLS certificate failure")),
                "LDAP TLS failure classified");
        }

        private static void TestRpcEndpointParsing()
        {
            AssertEqualInt(
                49667,
                RpcEndpointMapperAnalyzer.ExtractTcpPort("ncacn_ip_tcp:dc01.example.com[49667]"),
                "RPC dynamic TCP port parsed");

            AssertEqualInt(
                135,
                RpcEndpointMapperAnalyzer.ExtractTcpPort("ncacn_ip_tcp:dc01.example.com[135]"),
                "RPC endpoint mapper port parsed");

            AssertEqualInt(
                0,
                RpcEndpointMapperAnalyzer.ExtractTcpPort("ncalrpc:[LRPC-abc]"),
                "non-TCP RPC binding ignored");
        }

        private static void TestRpcKnownInterfaces()
        {
            AssertEqual(
                "Netlogon (MS-NRPC)",
                RpcEndpointMapperAnalyzer.DescribeKnownInterface(
                    "12345678-1234-abcd-ef00-01234567cffb"),
                "Netlogon RPC UUID mapped");

            AssertEqual(
                "LSA Policy (MS-LSAD)",
                RpcEndpointMapperAnalyzer.DescribeKnownInterface(
                    "12345778-1234-abcd-ef00-0123456789ab"),
                "LSA RPC UUID mapped");

            AssertEqual(
                "SAMR (MS-SAMR)",
                RpcEndpointMapperAnalyzer.DescribeKnownInterface(
                    "12345778-1234-abcd-ef00-0123456789ac"),
                "SAMR RPC UUID mapped");

            AssertEqual(
                "Directory Replication Service (MS-DRSR)",
                RpcEndpointMapperAnalyzer.DescribeKnownInterface(
                    "e3514235-4b06-11d1-ab04-00c04fc2dcd2"),
                "DRSUAPI RPC UUID mapped");

            AssertEqual(
                String.Empty,
                RpcEndpointMapperAnalyzer.DescribeKnownInterface(
                    "00000000-0000-0000-0000-000000000000"),
                "unknown RPC UUID not mislabeled");
        }

        private static void TestIdentityConsistencyFilter()
        {
            string filter = IdentityConsistencyAnalyzer.BuildFilter(
                "PC01",
                "PC01.example.com",
                new string[] { "HOST/PC01", "CIFS/PC01.example.com" });

            AssertTrue(filter.IndexOf("(sAMAccountName=PC01$)", StringComparison.Ordinal) >= 0, "identity filter includes SAM");
            AssertTrue(filter.IndexOf("(dNSHostName=PC01.example.com)", StringComparison.Ordinal) >= 0, "identity filter includes DNS");
            AssertTrue(filter.IndexOf("(servicePrincipalName=HOST/PC01)", StringComparison.Ordinal) >= 0, "identity filter includes HOST SPN");

            string escaped = IdentityConsistencyAnalyzer.BuildFilter(
                "PC*01",
                String.Empty,
                new string[0]);
            AssertTrue(escaped.IndexOf(@"PC\2a01$", StringComparison.Ordinal) >= 0, "identity filter escapes LDAP metacharacters");
        }

        private static void TestTransactionJournalParsing()
        {
            string json =
                "{\"entries\":[" +
                "{\"kind\":\"RegistryDword\",\"target\":\"HKLM\\\\SOFTWARE\\\\Test|Value\",\"before\":\"2\",\"after\":\"0\",\"reversible\":true,\"note\":\"test\"}," +
                "{\"kind\":\"Note\",\"target\":\"DNS\",\"before\":\"\",\"after\":\"\",\"reversible\":false,\"note\":\"flush\"}" +
                "]}";

            List<TransactionJournalEntry> entries = TransactionJournalService.ParseEntries(json);
            AssertEqualInt(2, entries.Count, "transaction journal entries parsed");
            AssertEqual("RegistryDword", entries[0].Kind, "transaction journal kind parsed");
            AssertTrue(entries[0].Reversible, "transaction registry entry reversible parsed");
            AssertFalse(entries[1].Reversible, "transaction note is not reversible");

            AssertTrue(
                TransactionJournalService.IsAllowedRollbackTarget(
                    "RegistryDword",
                    @"HKLM\SYSTEM\CurrentControlSet\Control\Lsa|MachineIdentityIsolation"),
                "MII LSA rollback target allowed");

            AssertTrue(
                TransactionJournalService.IsAllowedRollbackTarget(
                    "ServiceState",
                    "Netlogon"),
                "Netlogon rollback target allowed");

            AssertFalse(
                TransactionJournalService.IsAllowedRollbackTarget(
                    "RegistryDword",
                    @"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run|Bad"),
                "arbitrary HKLM rollback target blocked");

            AssertFalse(
                TransactionJournalService.IsAllowedRollbackTarget(
                    "ServiceState",
                    "WinDefend"),
                "arbitrary service rollback target blocked");
        }

        private static void TestTransactionJournalAtomicWrite()
        {
            string folder = Path.Combine(
                Path.GetTempPath(),
                "DomainMembershipCheckRepair-tests-" +
                Guid.NewGuid().ToString("N"));
            string path = Path.Combine(folder, "journal.json");

            try
            {
                Directory.CreateDirectory(folder);

                TransactionJournalService.WriteTextAtomically(
                    path,
                    "{\"value\":1}");

                AssertEqual(
                    "{\"value\":1}",
                    File.ReadAllText(path),
                    "transaction journal atomic writer creates initial file");

                TransactionJournalService.WriteTextAtomically(
                    path,
                    "{\"value\":2}");

                AssertEqual(
                    "{\"value\":2}",
                    File.ReadAllText(path),
                    "transaction journal atomic writer replaces existing file");

                AssertEqual(
                    "0",
                    Directory.GetFiles(
                        folder,
                        "*.tmp-*").Length.ToString(),
                    "transaction journal atomic writer leaves no temp files");
            }
            finally
            {
                try
                {
                    if (Directory.Exists(folder))
                        Directory.Delete(folder, true);
                }
                catch
                {
                }
            }
        }

        private static void TestAdRecoveryPackageAtomicWrite()
        {
            string folder = Path.Combine(
                Path.GetTempPath(),
                "DomainMembershipCheckRepair-recovery-tests-" +
                Guid.NewGuid().ToString("N"));
            string path = Path.Combine(folder, "recovery.json");

            try
            {
                Directory.CreateDirectory(folder);

                AdRecycleBinRecoveryService.WriteRecoveryPackageTextAtomically(
                    path,
                    "{\"value\":1}");

                AssertEqual(
                    "{\"value\":1}",
                    File.ReadAllText(path),
                    "AD recovery package atomic writer creates initial file");

                AdRecycleBinRecoveryService.WriteRecoveryPackageTextAtomically(
                    path,
                    "{\"value\":2}");

                AssertEqual(
                    "{\"value\":2}",
                    File.ReadAllText(path),
                    "AD recovery package atomic writer replaces existing file");

                AssertEqual(
                    "0",
                    Directory.GetFiles(
                        folder,
                        "*.tmp-*").Length.ToString(),
                    "AD recovery package atomic writer leaves no temp files");
            }
            finally
            {
                try
                {
                    if (Directory.Exists(folder))
                        Directory.Delete(folder, true);
                }
                catch
                {
                }
            }
        }

        private static void TestAdRecoveryHelpers()
        {
            AssertEqual(
                "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a",
                AdRecycleBinRecoveryService.RecycleBinFeatureGuid,
                "AD Recycle Bin feature GUID");

            AssertEqual(
                "(&(isDeleted=TRUE)(objectClass=computer)(sAMAccountName=PC01$))",
                AdRecycleBinRecoveryService.BuildDeletedComputerFilter("PC01"),
                "deleted computer LDAP filter");

            string escapedFilter =
                AdRecycleBinRecoveryService.BuildDeletedComputerFilter("PC*01");
            AssertTrue(
                escapedFilter.IndexOf(@"PC\2a01$", StringComparison.Ordinal) >= 0,
                "deleted computer filter escapes LDAP metacharacters");

            AssertEqual(
                "CN=PC01,OU=Computers,DC=example,DC=com",
                AdRecycleBinRecoveryService.BuildRestoreDn(
                    "PC01",
                    "CN=PC01",
                    "OU=Computers,DC=example,DC=com"),
                "restore DN uses last known RDN and parent");

            AssertEqual(
                @"CN=PC\2c01,OU=Computers,DC=example,DC=com",
                AdRecycleBinRecoveryService.BuildRestoreDn(
                    "PC,01",
                    String.Empty,
                    "OU=Computers,DC=example,DC=com"),
                "restore DN fallback escapes DN component");

            AssertEqual(
                String.Empty,
                AdRecycleBinRecoveryService.BuildRestoreDn(
                    "PC01",
                    "CN=PC01",
                    String.Empty),
                "restore DN requires last known parent");
        }

        private static void TestAdRestoreFinalSafety()
        {
            string guid = "12345678-1234-1234-1234-1234567890ab";
            string parent = "OU=Computers,DC=example,DC=com";
            string rdn = "CN=PC01";

            AssertNull(
                AdRecycleBinRecoveryService.ValidateDeletedObjectForRestore(
                    "PC01",
                    guid,
                    "PC01$",
                    parent,
                    rdn,
                    "PC01$",
                    guid,
                    true,
                    false,
                    parent,
                    rdn),
                "final AD restore safety accepts exact deleted-object identity and state");

            AssertNotNull(
                AdRecycleBinRecoveryService.ValidateDeletedObjectForRestore(
                    "PC01",
                    String.Empty,
                    "PC01$",
                    parent,
                    rdn,
                    "PC01$",
                    guid,
                    true,
                    false,
                    parent,
                    rdn),
                "final AD restore safety requires expected GUID");

            AssertNotNull(
                AdRecycleBinRecoveryService.ValidateDeletedObjectForRestore(
                    "PC01",
                    guid,
                    "PC01$",
                    parent,
                    rdn,
                    "PC02$",
                    guid,
                    true,
                    false,
                    parent,
                    rdn),
                "final AD restore safety blocks changed sAMAccountName");

            AssertNotNull(
                AdRecycleBinRecoveryService.ValidateDeletedObjectForRestore(
                    "PC01",
                    guid,
                    "PC01$",
                    parent,
                    rdn,
                    "PC01$",
                    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    true,
                    false,
                    parent,
                    rdn),
                "final AD restore safety blocks changed object GUID");

            AssertNotNull(
                AdRecycleBinRecoveryService.ValidateDeletedObjectForRestore(
                    "PC01",
                    guid,
                    "PC01$",
                    parent,
                    rdn,
                    "PC01$",
                    guid,
                    false,
                    false,
                    parent,
                    rdn),
                "final AD restore safety requires object to remain deleted");

            AssertNotNull(
                AdRecycleBinRecoveryService.ValidateDeletedObjectForRestore(
                    "PC01",
                    guid,
                    "PC01$",
                    parent,
                    rdn,
                    "PC01$",
                    guid,
                    true,
                    true,
                    parent,
                    rdn),
                "final AD restore safety blocks recycled object");

            AssertNotNull(
                AdRecycleBinRecoveryService.ValidateDeletedObjectForRestore(
                    "PC01",
                    guid,
                    "PC01$",
                    parent,
                    rdn,
                    "PC01$",
                    guid,
                    true,
                    false,
                    "OU=Other,DC=example,DC=com",
                    rdn),
                "final AD restore safety blocks changed last-known parent");

            AssertNotNull(
                AdRecycleBinRecoveryService.ValidateDeletedObjectForRestore(
                    "PC01",
                    guid,
                    "PC01$",
                    parent,
                    rdn,
                    "PC01$",
                    guid,
                    true,
                    false,
                    parent,
                    "CN=PC01-OLD"),
                "final AD restore safety blocks changed last-known RDN");
        }

        private static void TestProtectedStorageAclPolicy()
        {
            SecurityIdentifier users =
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinUsersSid,
                    null);
            SecurityIdentifier authenticated =
                new SecurityIdentifier(
                    WellKnownSidType.AuthenticatedUserSid,
                    null);
            SecurityIdentifier everyone =
                new SecurityIdentifier(
                    WellKnownSidType.WorldSid,
                    null);
            SecurityIdentifier administrators =
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null);
            SecurityIdentifier system =
                new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid,
                    null);
            SecurityIdentifier localService =
                new SecurityIdentifier(
                    WellKnownSidType.LocalServiceSid,
                    null);

            AssertTrue(
                ProtectedStorageAcl.IsDangerousBroadWriteGrant(
                    users,
                    FileSystemRights.Write,
                    AccessControlType.Allow),
                "protected storage blocks Builtin Users write grant");

            AssertTrue(
                ProtectedStorageAcl.IsDangerousBroadWriteGrant(
                    authenticated,
                    FileSystemRights.Modify,
                    AccessControlType.Allow),
                "protected storage blocks Authenticated Users modify grant");

            AssertTrue(
                ProtectedStorageAcl.IsDangerousBroadWriteGrant(
                    everyone,
                    FileSystemRights.CreateFiles,
                    AccessControlType.Allow),
                "protected storage blocks Everyone create-files grant");

            AssertFalse(
                ProtectedStorageAcl.IsDangerousBroadWriteGrant(
                    users,
                    FileSystemRights.ReadAndExecute | FileSystemRights.Read,
                    AccessControlType.Allow),
                "protected storage allows broad read-only grant");

            AssertFalse(
                ProtectedStorageAcl.IsDangerousBroadWriteGrant(
                    administrators,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow),
                "protected storage allows Administrators full control");

            AssertFalse(
                ProtectedStorageAcl.IsDangerousBroadWriteGrant(
                    users,
                    FileSystemRights.Write,
                    AccessControlType.Deny),
                "protected storage ignores deny rule as dangerous allow grant");

            AssertTrue(
                ProtectedStorageAcl.IsTrustedOwner(system),
                "protected storage trusts LocalSystem as owner");

            AssertTrue(
                ProtectedStorageAcl.IsTrustedOwner(administrators),
                "protected storage trusts Builtin Administrators as owner");

            AssertFalse(
                ProtectedStorageAcl.IsTrustedOwner(users),
                "protected storage rejects Builtin Users as owner");

            AssertTrue(
                ProtectedStorageAcl.IsUntrustedWriteGrant(
                    localService,
                    FileSystemRights.Write,
                    AccessControlType.Allow),
                "protected storage rejects write access for a non-owner-privileged SID");

            AssertFalse(
                ProtectedStorageAcl.IsUntrustedWriteGrant(
                    administrators,
                    FileSystemRights.FullControl,
                    AccessControlType.Allow),
                "protected storage permits Administrators full control");

            AssertFalse(
                ProtectedStorageAcl.IsUntrustedWriteGrant(
                    users,
                    FileSystemRights.ReadAndExecute | FileSystemRights.Read,
                    AccessControlType.Allow),
                "protected storage permits non-privileged read-only access");

            AssertTrue(
                ProtectedStorageAcl.IsReparsePoint(
                    FileAttributes.Directory |
                    FileAttributes.ReparsePoint),
                "protected storage detects directory reparse-point attribute");

            AssertFalse(
                ProtectedStorageAcl.IsReparsePoint(
                    FileAttributes.Directory),
                "protected storage accepts normal directory attribute");

            string fileSecurityDetails;
            string outsideManagedRoot = Path.Combine(
                Path.GetTempPath(),
                "DomainMembershipCheckRepair-outside-" +
                Guid.NewGuid().ToString("N") +
                ".txt");

            AssertFalse(
                ProtectedStorageAcl.PrepareProtectedFileTarget(
                    outsideManagedRoot,
                    out fileSecurityDetails),
                "protected file target cannot escape managed ProgramData root");

            AssertFalse(
                ProtectedStorageAcl.IsProtectedFileTrusted(
                    outsideManagedRoot,
                    out fileSecurityDetails),
                "protected file trust rejects paths outside managed ProgramData root");

            AssertFalse(
                ProtectedStorageAcl.PrepareProtectedFileTarget(
                    ProtectedStorageAcl.GetApplicationRootPath(),
                    out fileSecurityDetails),
                "protected file target cannot be the managed root directory itself");
        }

        private static void TestSafetyBundleStoragePath()
        {
            string root =
                Path.GetFullPath(
                    ProtectedStorageAcl.GetApplicationRootPath())
                .TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar);

            string folder =
                Path.GetFullPath(
                    SafetyBundleService.GetSafetyFolderPath());

            string prefix =
                root +
                Path.DirectorySeparatorChar;

            AssertTrue(
                folder.StartsWith(
                    prefix,
                    StringComparison.OrdinalIgnoreCase),
                "safety bundle storage stays under managed ProgramData root");

            AssertTrue(
                folder.EndsWith(
                    Path.DirectorySeparatorChar +
                    "SafetyBundles",
                    StringComparison.OrdinalIgnoreCase),
                "safety bundle storage uses dedicated SafetyBundles child");
        }

        private static void TestPrivateStagingAclPolicy()
        {
            SecurityIdentifier currentUser =
                new SecurityIdentifier(
                    "S-1-5-21-1000-1000-1000-1001");
            SecurityIdentifier otherUser =
                new SecurityIdentifier(
                    "S-1-5-21-1000-1000-1000-1002");
            SecurityIdentifier administrators =
                new SecurityIdentifier(
                    WellKnownSidType.BuiltinAdministratorsSid,
                    null);
            SecurityIdentifier system =
                new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid,
                    null);

            AssertTrue(
                PrivateStagingService.IsUntrustedPrivateAllowRule(
                    otherUser,
                    currentUser,
                    AccessControlType.Allow),
                "private staging rejects another user's allow access even when read-only");

            AssertFalse(
                PrivateStagingService.IsUntrustedPrivateAllowRule(
                    currentUser,
                    currentUser,
                    AccessControlType.Allow),
                "private staging permits the current user");

            AssertFalse(
                PrivateStagingService.IsUntrustedPrivateAllowRule(
                    administrators,
                    currentUser,
                    AccessControlType.Allow),
                "private staging permits Administrators allow access");

            AssertFalse(
                PrivateStagingService.IsUntrustedPrivateAllowRule(
                    system,
                    currentUser,
                    AccessControlType.Allow),
                "private staging permits LocalSystem allow access");

            AssertFalse(
                PrivateStagingService.IsUntrustedPrivateAllowRule(
                    otherUser,
                    currentUser,
                    AccessControlType.Deny),
                "private staging does not treat deny rules as allow access");
        }

        private static void TestAdDeleteFinalSafety()
        {
            string guid = "12345678-1234-1234-1234-1234567890ab";

            AssertNull(
                AdDirectoryService.ValidateDeleteTargetState(
                    "PC01",
                    guid,
                    "PC01$",
                    true,
                    guid,
                    0),
                "final AD delete safety accepts exact leaf computer identity");

            AssertNotNull(
                AdDirectoryService.ValidateDeleteTargetState(
                    "PC01",
                    String.Empty,
                    "PC01$",
                    true,
                    guid,
                    0),
                "final AD delete safety requires expected GUID");

            AssertNotNull(
                AdDirectoryService.ValidateDeleteTargetState(
                    "PC01",
                    guid,
                    "PC02$",
                    true,
                    guid,
                    0),
                "final AD delete safety blocks changed sAMAccountName");

            AssertNotNull(
                AdDirectoryService.ValidateDeleteTargetState(
                    "PC01",
                    guid,
                    "PC01$",
                    false,
                    guid,
                    0),
                "final AD delete safety requires computer object class");

            AssertNotNull(
                AdDirectoryService.ValidateDeleteTargetState(
                    "PC01",
                    guid,
                    "PC01$",
                    true,
                    "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
                    0),
                "final AD delete safety blocks changed object GUID");

            AssertNotNull(
                AdDirectoryService.ValidateDeleteTargetState(
                    "PC01",
                    guid,
                    "PC01$",
                    true,
                    guid,
                    1),
                "final AD delete safety blocks newly appeared child object");
        }

        private static void TestSupportBundleSanitizer()
        {
            SupportBundleSanitizer sanitizer =
                new SupportBundleSanitizer(
                    new string[]
                    {
                        "PC01",
                        "example.com",
                        "dc01.example.com",
                        @"EXAMPLE\admin",
                        "CN=PC01,OU=Computers,DC=example,DC=com"
                    });

            string input =
                "Computer=PC01\r\n" +
                "Domain=example.com\r\n" +
                "DC=dc01.example.com\r\n" +
                "User=EXAMPLE\\admin\r\n" +
                "UPN=admin@example.com\r\n" +
                "DN=CN=PC01,OU=Computers,DC=example,DC=com\r\n" +
                "IPv4=10.20.30.40\r\n" +
                "MAC=00-11-22-33-44-55\r\n" +
                "SID=S-1-5-21-111-222-333-444\r\n" +
                "GUID=12345678-1234-1234-1234-1234567890ab\r\n" +
                "password=Secret123!\r\n" +
                "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\r\n" +
                "Repeat=dc01.example.com\r\n";

            string output = sanitizer.Sanitize(input);

            AssertTrue(
                output.IndexOf("Secret123", StringComparison.OrdinalIgnoreCase) < 0,
                "support bundle secret redacted");
            AssertTrue(
                output.IndexOf("admin@example.com", StringComparison.OrdinalIgnoreCase) < 0,
                "support bundle UPN redacted");
            AssertTrue(
                output.IndexOf("10.20.30.40", StringComparison.OrdinalIgnoreCase) < 0,
                "support bundle IPv4 redacted");
            AssertTrue(
                output.IndexOf("00-11-22-33-44-55", StringComparison.OrdinalIgnoreCase) < 0,
                "support bundle MAC redacted");
            AssertTrue(
                output.IndexOf("S-1-5-21-111-222-333-444", StringComparison.OrdinalIgnoreCase) < 0,
                "support bundle SID redacted");
            AssertTrue(
                output.IndexOf("12345678-1234-1234-1234-1234567890ab", StringComparison.OrdinalIgnoreCase) < 0,
                "support bundle GUID redacted");
            AssertTrue(
                output.IndexOf(@"EXAMPLE\admin", StringComparison.OrdinalIgnoreCase) < 0,
                "support bundle domain account redacted");
            AssertTrue(
                output.IndexOf("CN=PC01,OU=Computers,DC=example,DC=com", StringComparison.OrdinalIgnoreCase) < 0,
                "support bundle DN redacted");
            AssertTrue(
                output.IndexOf("[REDACTED]", StringComparison.Ordinal) >= 0,
                "support bundle redaction marker present");

            string repeated = sanitizer.Sanitize(
                "dc01.example.com dc01.example.com");
            int firstTokenStart = repeated.IndexOf("<HOST:", StringComparison.Ordinal);
            AssertTrue(
                firstTokenStart >= 0 &&
                repeated.IndexOf(repeated.Substring(firstTokenStart, 17), firstTokenStart + 1, StringComparison.Ordinal) >= 0,
                "support bundle opaque token stable within bundle");
        }

        private static void TestSupportBundleZipRedaction()
        {
            string root = Path.Combine(
                Path.GetTempPath(),
                "DomainMembershipCheckRepair.Tests",
                Guid.NewGuid().ToString("N"));
            string source = Path.Combine(root, "source");
            string archive = Path.Combine(root, "bundle.zip");

            Directory.CreateDirectory(source);

            try
            {
                File.WriteAllText(
                    Path.Combine(source, "diagnostics.txt"),
                    "Computer=PC01\r\n" +
                    "Domain=example.com\r\n" +
                    "DC=dc01.example.com\r\n" +
                    "User=EXAMPLE\\admin\r\n" +
                    "UPN=admin@example.com\r\n" +
                    "IPv4=10.20.30.40\r\n" +
                    "SID=S-1-5-21-111-222-333-444\r\n" +
                    "GUID=12345678-1234-1234-1234-1234567890ab\r\n");

                File.WriteAllText(
                    Path.Combine(source, "NetSetup.log"),
                    "NetpJoinDomain: machine PC01 contacting dc01.example.com (10.20.30.40)\r\n" +
                    "DN=CN=PC01,OU=Computers,DC=example,DC=com\r\n");

                File.WriteAllText(
                    Path.Combine(source, "DomainMembershipRepair.log"),
                    "password=Secret123!\r\n" +
                    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123456789\r\n");

                SupportBundleSanitizer sanitizer =
                    new SupportBundleSanitizer(
                        new string[]
                        {
                            "PC01",
                            "example.com",
                            "dc01.example.com",
                            @"EXAMPLE\admin",
                            "CN=PC01,OU=Computers,DC=example,DC=com"
                        });

                SupportBundleRedactionService.SanitizeDirectory(
                    source,
                    sanitizer);
                SupportBundleRedactionService.WriteSummary(
                    source,
                    sanitizer);

                ZipFile.CreateFromDirectory(
                    source,
                    archive,
                    CompressionLevel.Optimal,
                    false);

                string combined = String.Empty;
                bool summaryFound = false;

                using (ZipArchive zip = ZipFile.OpenRead(archive))
                {
                    foreach (ZipArchiveEntry entry in zip.Entries)
                    {
                        if (String.Equals(
                            entry.FullName,
                            "redaction-summary.txt",
                            StringComparison.OrdinalIgnoreCase))
                        {
                            summaryFound = true;
                        }

                        using (StreamReader reader = new StreamReader(entry.Open()))
                            combined += reader.ReadToEnd() + "\r\n";
                    }
                }

                AssertTrue(
                    summaryFound,
                    "support bundle ZIP contains redaction summary");
                AssertTrue(
                    combined.IndexOf("Secret123", StringComparison.OrdinalIgnoreCase) < 0,
                    "support bundle ZIP secret absent");
                AssertTrue(
                    combined.IndexOf("admin@example.com", StringComparison.OrdinalIgnoreCase) < 0,
                    "support bundle ZIP UPN absent");
                AssertTrue(
                    combined.IndexOf(@"EXAMPLE\admin", StringComparison.OrdinalIgnoreCase) < 0,
                    "support bundle ZIP account absent");
                AssertTrue(
                    combined.IndexOf("10.20.30.40", StringComparison.OrdinalIgnoreCase) < 0,
                    "support bundle ZIP IPv4 absent");
                AssertTrue(
                    combined.IndexOf("S-1-5-21-111-222-333-444", StringComparison.OrdinalIgnoreCase) < 0,
                    "support bundle ZIP SID absent");
                AssertTrue(
                    combined.IndexOf("12345678-1234-1234-1234-1234567890ab", StringComparison.OrdinalIgnoreCase) < 0,
                    "support bundle ZIP GUID absent");
                AssertTrue(
                    combined.IndexOf("CN=PC01,OU=Computers,DC=example,DC=com", StringComparison.OrdinalIgnoreCase) < 0,
                    "support bundle ZIP DN absent");
                AssertTrue(
                    combined.IndexOf("dc01.example.com", StringComparison.OrdinalIgnoreCase) < 0,
                    "support bundle ZIP host absent");
                AssertTrue(
                    combined.IndexOf("[REDACTED]", StringComparison.Ordinal) >= 0,
                    "support bundle ZIP contains secret redaction marker");
            }
            finally
            {
                try
                {
                    if (Directory.Exists(root))
                        Directory.Delete(root, true);
                }
                catch
                {
                }
            }
        }

        private static void TestAtomicArchiveCommit()
        {
            string root = Path.Combine(
                Path.GetTempPath(),
                "DomainMembershipCheckRepair.Tests",
                Guid.NewGuid().ToString("N"));
            string source = Path.Combine(root, "source");
            string destination = Path.Combine(root, "bundle.zip");

            Directory.CreateDirectory(source);

            try
            {
                File.WriteAllText(
                    Path.Combine(source, "new.txt"),
                    "new-content");

                string oldSource = Path.Combine(root, "old-source");
                Directory.CreateDirectory(oldSource);
                File.WriteAllText(
                    Path.Combine(oldSource, "old.txt"),
                    "old-content");

                ZipFile.CreateFromDirectory(
                    oldSource,
                    destination,
                    CompressionLevel.Optimal,
                    false);

                AtomicArchiveService.CreateZipFromDirectoryAtomically(
                    source,
                    destination);

                AtomicArchiveService.VerifyArchive(destination);

                using (ZipArchive archive = ZipFile.OpenRead(destination))
                {
                    AssertTrue(
                        archive.GetEntry("new.txt") != null,
                        "atomic archive replacement contains new content");
                    AssertTrue(
                        archive.GetEntry("old.txt") == null,
                        "atomic archive replacement removed previous content");
                }

                AssertEqualInt(
                    0,
                    Directory.GetFiles(
                        root,
                        "bundle.zip.tmp-*",
                        SearchOption.TopDirectoryOnly).Length,
                    "atomic archive leaves no temporary ZIP after success");

                string failureSource = Path.Combine(root, "failure-source");
                Directory.CreateDirectory(failureSource);
                string lockedPath = Path.Combine(failureSource, "locked.txt");
                File.WriteAllText(lockedPath, "locked");

                string stableSource = Path.Combine(root, "stable-source");
                Directory.CreateDirectory(stableSource);
                File.WriteAllText(
                    Path.Combine(stableSource, "stable.txt"),
                    "stable-content");

                ZipFile.CreateFromDirectory(
                    stableSource,
                    destination + ".stable",
                    CompressionLevel.Optimal,
                    false);
                File.Replace(
                    destination + ".stable",
                    destination,
                    null);

                bool failed = false;
                using (FileStream locked = new FileStream(
                    lockedPath,
                    FileMode.Open,
                    FileAccess.ReadWrite,
                    FileShare.None))
                {
                    try
                    {
                        AtomicArchiveService.CreateZipFromDirectoryAtomically(
                            failureSource,
                            destination);
                    }
                    catch
                    {
                        failed = true;
                    }
                }

                AssertTrue(
                    failed,
                    "atomic archive reports packaging failure");

                using (ZipArchive archive = ZipFile.OpenRead(destination))
                {
                    AssertTrue(
                        archive.GetEntry("stable.txt") != null,
                        "previous archive survives failed replacement");
                }

                AssertEqualInt(
                    0,
                    Directory.GetFiles(
                        root,
                        "bundle.zip.tmp-*",
                        SearchOption.TopDirectoryOnly).Length,
                    "atomic archive cleans temporary ZIP after failure");
            }
            finally
            {
                try
                {
                    if (Directory.Exists(root))
                        Directory.Delete(root, true);
                }
                catch
                {
                }
            }
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
