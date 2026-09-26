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
            TestDirectoryServerSelection();
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
            TestAdRecoveryHelpers();

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

            GuiResumeOptions rollback = ElevationHelper.ParseGuiResumeOptions(
                new string[] { "--resume-action", "rollback-local", "--elevation-attempted" });
            AssertEqual("rollback-local", rollback.Action, "rollback GUI resume action");
            AssertTrue(rollback.ElevationAttempted, "rollback resume elevation marker");

            GuiResumeOptions adRestore = ElevationHelper.ParseGuiResumeOptions(
                new string[] { "--resume-action", "ad-restore", "--elevation-attempted" });
            AssertEqual("ad-restore", adRestore.Action, "AD restore GUI resume action");
            AssertTrue(adRestore.ElevationAttempted, "AD restore resume elevation marker");
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
