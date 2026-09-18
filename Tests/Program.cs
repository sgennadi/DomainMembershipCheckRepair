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

            if (failures == 0)
            {
                Console.WriteLine("All DomainValidation tests passed.");
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
