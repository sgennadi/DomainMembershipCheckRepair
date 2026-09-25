using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class JoinPermissionsResult
    {
        internal string Domain = String.Empty;
        internal string Dc = String.Empty;
        internal int? MachineAccountQuota;
        internal string OperatorSid = String.Empty;
        internal string TargetContainerDn = String.Empty;
        internal string ExistingObjectDn = String.Empty;
        internal string ExistingOwner = String.Empty;
        internal readonly List<string> MatchingAces = new List<string>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class JoinPermissionsAnalyzer
    {
        private static readonly Guid ComputerClass =
            new Guid("bf967a86-0de6-11d0-a285-00aa003049e2");
        private static readonly Guid ResetPassword =
            new Guid("00299570-246d-11d0-a768-00aa006e0529");
        private static readonly Guid ValidatedDnsHostName =
            new Guid("72e39547-7b18-11d1-adef-00c04fd8d5cd");
        private static readonly Guid ValidatedSpn =
            new Guid("f3a64788-5306-11d1-a9c5-0000f80367c1");
        private static readonly Guid AccountRestrictions =
            new Guid("4c164200-20c0-11d0-a768-00aa006e0529");
        private static readonly Guid AllowedToAuthenticate =
            new Guid("68b1d179-0d15-4d4f-ab71-46152e79a7bc");

        internal static JoinPermissionsResult Analyze(
            string domain,
            string dc,
            string computerName,
            string user,
            string password,
            AdComputerAccountInfo existingAccount)
        {
            JoinPermissionsResult r = new JoinPermissionsResult();
            r.Domain = (domain ?? String.Empty).Trim();
            r.Dc = DomainValidation.NormalizeDirectoryServer(dc);

            if (String.IsNullOrWhiteSpace(r.Dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(r.Domain, false);
                if (discovered.Success)
                    r.Dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            if (String.IsNullOrWhiteSpace(r.Dc))
            {
                r.Findings.Add("No DC is available for Join Permissions analysis.");
                return r;
            }

            try
            {
                DirectoryEntry rootDse = CreateEntry("LDAP://" + r.Dc + "/RootDSE", user, password);
                string defaultNc;
                using (rootDse)
                    defaultNc = Convert.ToString(rootDse.Properties["defaultNamingContext"].Value) ?? String.Empty;

                if (String.IsNullOrWhiteSpace(defaultNc))
                {
                    r.Findings.Add("AD did not return defaultNamingContext.");
                    return r;
                }

                DirectoryEntry domainEntry = CreateEntry("LDAP://" + r.Dc + "/" + defaultNc, user, password);
                using (domainEntry)
                {
                    object quota = domainEntry.Properties["ms-DS-MachineAccountQuota"].Value;
                    if (quota != null)
                        r.MachineAccountQuota = Convert.ToInt32(quota);

                    if (existingAccount != null && existingAccount.Exists)
                    {
                        r.ExistingObjectDn = existingAccount.DistinguishedName ?? String.Empty;
                        r.ExistingOwner = existingAccount.Owner ?? String.Empty;
                        r.TargetContainerDn = ParentDn(r.ExistingObjectDn);
                    }
                    else
                    {
                        r.TargetContainerDn = FindDefaultComputersContainer(domainEntry, defaultNc);
                    }

                    HashSet<string> operatorSids = ResolveOperatorSids(
                        domainEntry,
                        user,
                        password,
                        r);

                    if (operatorSids.Count == 0)
                    {
                        r.Findings.Add(
                            "Operator SID/group token could not be resolved. ACL evidence is limited; credentials can still be valid.");
                    }

                    if (!String.IsNullOrWhiteSpace(r.TargetContainerDn))
                    {
                        AnalyzeAcl(
                            "Target container",
                            "LDAP://" + r.Dc + "/" + r.TargetContainerDn,
                            user,
                            password,
                            operatorSids,
                            r,
                            true);
                    }

                    if (existingAccount != null &&
                        existingAccount.Exists &&
                        !String.IsNullOrWhiteSpace(existingAccount.LdapPath))
                    {
                        AnalyzeAcl(
                            "Existing computer",
                            existingAccount.LdapPath,
                            user,
                            password,
                            operatorSids,
                            r,
                            false);
                    }
                }
            }
            catch (Exception ex)
            {
                r.Findings.Add("Join Permissions query failed: " + ex.Message);
            }

            BuildFindings(r, existingAccount);
            return r;
        }

        internal static string ToText(JoinPermissionsResult r)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Domain Join Permissions Analyzer");
            sb.AppendLine("===============================");
            sb.AppendLine("Domain:               " + First(r.Domain, "(none)"));
            sb.AppendLine("DC:                   " + First(r.Dc, "(none)"));
            sb.AppendLine("Operator SID:         " + First(r.OperatorSid, "(not resolved)"));
            sb.AppendLine("MachineAccountQuota:  " +
                (r.MachineAccountQuota.HasValue ? r.MachineAccountQuota.Value.ToString() : "(not returned)"));
            sb.AppendLine("Target container:     " + First(r.TargetContainerDn, "(not resolved)"));
            sb.AppendLine("Existing object:      " + First(r.ExistingObjectDn, "(none / not found)"));
            sb.AppendLine("Existing owner:       " + First(r.ExistingOwner, "(not returned)"));

            if (r.MatchingAces.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Matching ACL evidence:");
                foreach (string ace in r.MatchingAces)
                    sb.AppendLine("- " + ace);
            }

            if (r.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Findings:");
                foreach (string finding in r.Findings)
                    sb.AppendLine("- " + finding);
            }

            sb.AppendLine();
            sb.AppendLine(
                "ACL evidence is intentionally conservative. Nested-group evaluation, owner trust and deny/allow precedence can make effective permissions differ from a simple ACE list.");

            return sb.ToString();
        }

        private static HashSet<string> ResolveOperatorSids(
            DirectoryEntry domainEntry,
            string user,
            string password,
            JoinPermissionsResult result)
        {
            HashSet<string> sids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            sids.Add("S-1-1-0");
            sids.Add("S-1-5-11");

            if (String.IsNullOrWhiteSpace(user))
                return sids;

            try
            {
                string filter;
                int slash = user.IndexOf('\\');
                if (slash >= 0 && slash < user.Length - 1)
                {
                    string sam = DomainValidation.EscapeLdapFilterValue(user.Substring(slash + 1));
                    filter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=" + sam + "))";
                }
                else
                {
                    string upn = DomainValidation.EscapeLdapFilterValue(user);
                    filter = "(&(objectCategory=person)(objectClass=user)(userPrincipalName=" + upn + "))";
                }

                using (DirectorySearcher searcher = new DirectorySearcher(domainEntry))
                {
                    searcher.Filter = filter;
                    searcher.SearchScope = SearchScope.Subtree;
                    searcher.SizeLimit = 1;
                    searcher.PropertiesToLoad.Add("objectSid");

                    SearchResult found = searcher.FindOne();
                    if (found == null)
                        return sids;

                    if (found.Properties.Contains("objectSid") &&
                        found.Properties["objectSid"].Count > 0)
                    {
                        byte[] raw = found.Properties["objectSid"][0] as byte[];
                        if (raw != null)
                        {
                            SecurityIdentifier sid = new SecurityIdentifier(raw, 0);
                            result.OperatorSid = sid.Value;
                            sids.Add(sid.Value);
                        }
                    }

                    try
                    {
                        DirectoryEntry userEntry = CreateEntry(found.Path, user, password);
                        using (userEntry)
                        {
                            userEntry.RefreshCache(new string[] { "tokenGroups" });
                            foreach (object value in userEntry.Properties["tokenGroups"])
                            {
                                byte[] raw = value as byte[];
                                if (raw == null) continue;
                                sids.Add(new SecurityIdentifier(raw, 0).Value);
                            }
                        }
                    }
                    catch
                    {
                        result.Findings.Add(
                            "Group token expansion was unavailable; direct/well-known ACE evidence is still shown.");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Findings.Add("Unable to resolve operator SID/token groups: " + ex.Message);
            }

            return sids;
        }

        private static void AnalyzeAcl(
            string label,
            string ldapPath,
            string user,
            string password,
            HashSet<string> operatorSids,
            JoinPermissionsResult result,
            bool container)
        {
            try
            {
                DirectoryEntry entry = CreateEntry(ldapPath, user, password);
                using (entry)
                {
                    AuthorizationRuleCollection rules =
                        entry.ObjectSecurity.GetAccessRules(
                            true,
                            true,
                            typeof(SecurityIdentifier));

                    foreach (ActiveDirectoryAccessRule rule in rules)
                    {
                        SecurityIdentifier sid = rule.IdentityReference as SecurityIdentifier;
                        if (sid == null || !operatorSids.Contains(sid.Value))
                            continue;

                        string objectType = rule.ObjectType == Guid.Empty
                            ? "All"
                            : DescribeGuid(rule.ObjectType);

                        string inheritedType = rule.InheritedObjectType == Guid.Empty
                            ? "All"
                            : DescribeGuid(rule.InheritedObjectType);

                        result.MatchingAces.Add(
                            label + " | " +
                            rule.AccessControlType + " | " +
                            rule.ActiveDirectoryRights + " | object=" +
                            objectType + " | inheritedObject=" + inheritedType +
                            (rule.IsInherited ? " | inherited" : " | explicit"));
                    }

                    if (container)
                    {
                        result.Findings.Add(
                            "CHECK: For a new computer object, review target-container ACEs for CreateChild on the Computer class. MachineAccountQuota is a separate creation path and is not a substitute for delegated OU permissions.");
                    }
                    else
                    {
                        result.Findings.Add(
                            "CHECK: Reuse of an existing computer account requires more than object existence. Review Read/List, Allowed-to-Authenticate, Change/Reset Password, validated DNS/SPN writes, Account Restrictions and trusted ownership/reuse policy.");
                    }
                }
            }
            catch (Exception ex)
            {
                result.Findings.Add("Unable to inspect " + label + " ACL: " + ex.Message);
            }
        }

        private static void BuildFindings(
            JoinPermissionsResult r,
            AdComputerAccountInfo existingAccount)
        {
            if (r.MachineAccountQuota.HasValue && r.MachineAccountQuota.Value == 0)
            {
                r.Findings.Add(
                    "INFO: ms-DS-MachineAccountQuota is 0. Ordinary users cannot rely on the default quota to create computer accounts; delegated OU rights or privileged join rights are required.");
            }

            if (existingAccount != null && existingAccount.Exists)
            {
                if (!String.IsNullOrWhiteSpace(r.ExistingOwner))
                {
                    r.Findings.Add(
                        "CHECK: Existing computer owner is '" + r.ExistingOwner +
                        "'. Account-reuse hardening can block reuse when ownership is not trusted for the joining operator.");
                }
            }

            if (r.MatchingAces.Count == 0)
            {
                r.Findings.Add(
                    "CHECK: No matching direct/group-token ACE evidence was collected. This does not prove access is denied; inherited/nested effective permissions and privileged ownership still matter.");
            }
        }

        private static string FindDefaultComputersContainer(
            DirectoryEntry domainEntry,
            string defaultNc)
        {
            try
            {
                foreach (object value in domainEntry.Properties["wellKnownObjects"])
                {
                    string text = Convert.ToString(value) ?? String.Empty;
                    if (text.IndexOf(
                        "AA312825768811D1ADED00C04FD8D5CD",
                        StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        int lastColon = text.IndexOf(':', 5);
                        if (lastColon >= 0 && lastColon < text.Length - 1)
                            return text.Substring(lastColon + 1);
                    }
                }
            }
            catch
            {
            }

            return "CN=Computers," + defaultNc;
        }

        private static string ParentDn(string dn)
        {
            if (String.IsNullOrWhiteSpace(dn))
                return String.Empty;

            bool escaped = false;
            for (int i = 0; i < dn.Length; i++)
            {
                char c = dn[i];
                if (c == '\\')
                {
                    escaped = !escaped;
                    continue;
                }

                if (c == ',' && !escaped)
                    return dn.Substring(i + 1);

                escaped = false;
            }

            return String.Empty;
        }

        private static string DescribeGuid(Guid guid)
        {
            if (guid == ComputerClass) return "Computer class";
            if (guid == ResetPassword) return "Reset password";
            if (guid == ValidatedDnsHostName) return "Validated DNS host name";
            if (guid == ValidatedSpn) return "Validated SPN";
            if (guid == AccountRestrictions) return "Account restrictions";
            if (guid == AllowedToAuthenticate) return "Allowed to authenticate";
            return guid.ToString();
        }

        private static DirectoryEntry CreateEntry(string path, string user, string password)
        {
            if (!String.IsNullOrWhiteSpace(user) && password != null)
                return new DirectoryEntry(path, user, password, AuthenticationTypes.Secure);
            return new DirectoryEntry(path);
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
