using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.Security.Principal;

namespace DomainMembershipCheckRepair
{
    internal static class AdDirectoryService
    {
        internal static AdComputerAccountInfo FindComputerAccount(
            string computerName,
            string user,
            string password,
            string targetDomain,
            string preferredDirectoryServer,
            Action<string, string> log)
        {
            AdComputerAccountInfo info = new AdComputerAccountInfo();

            try
            {
                string ldapDomain = targetDomain;
                DomainDiscoveryResult resolved = NativeMethods.DiscoverDomain(targetDomain, false);
                if (resolved.Success && !String.IsNullOrWhiteSpace(resolved.DnsDomainName))
                    ldapDomain = resolved.DnsDomainName;

                string ldapServer = DomainValidation.NormalizeDirectoryServer(preferredDirectoryServer);
                if (String.IsNullOrWhiteSpace(ldapServer))
                {
                    ldapServer = resolved.Success && !String.IsNullOrWhiteSpace(resolved.DomainControllerName)
                        ? DomainValidation.NormalizeDirectoryServer(resolved.DomainControllerName)
                        : ldapDomain;
                }

                using (DirectoryEntry rootDse = CreateEntry("LDAP://" + ldapServer + "/RootDSE", user, password))
                {
                    object namingContextValue = rootDse.Properties["defaultNamingContext"].Value;
                    if (namingContextValue == null)
                    {
                        WriteLog(log, "WARN", "Active Directory did not return defaultNamingContext.");
                        return info;
                    }

                    string namingContext = namingContextValue.ToString();
                    using (DirectoryEntry root = CreateEntry("LDAP://" + ldapServer + "/" + namingContext, user, password))
                    using (DirectorySearcher searcher = new DirectorySearcher(root))
                    {
                        string samAccountName = DomainValidation.EscapeLdapFilterValue(computerName + "$");
                        searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=" + samAccountName + "))";
                        searcher.SearchScope = SearchScope.Subtree;
                        searcher.SizeLimit = 1;
                        searcher.PropertiesToLoad.Add("distinguishedName");
                        searcher.PropertiesToLoad.Add("dNSHostName");
                        searcher.PropertiesToLoad.Add("operatingSystem");
                        searcher.PropertiesToLoad.Add("description");
                        searcher.PropertiesToLoad.Add("objectGUID");
                        searcher.PropertiesToLoad.Add("whenCreated");
                        searcher.PropertiesToLoad.Add("whenChanged");
                        searcher.PropertiesToLoad.Add("userAccountControl");
                        searcher.PropertiesToLoad.Add("sAMAccountName");
                        searcher.PropertiesToLoad.Add("pwdLastSet");
                        searcher.PropertiesToLoad.Add("lastLogonTimestamp");
                        searcher.PropertiesToLoad.Add("canonicalName");
                        searcher.PropertiesToLoad.Add("servicePrincipalName");
                        searcher.PropertiesToLoad.Add("msDS-SupportedEncryptionTypes");

                        SearchResult result = searcher.FindOne();
                        info.LookupSucceeded = true;

                        if (result == null)
                        {
                            info.Exists = false;
                            WriteLog(log, "INFO", "No AD computer account found for '" + computerName + "'.");
                            return info;
                        }

                        info.Exists = true;
                        info.LdapPath = result.Path;
                        info.DistinguishedName = GetSearchPropertyString(result, "distinguishedName", computerName + "$");
                        info.DnsHostName = GetSearchPropertyString(result, "dNSHostName", String.Empty);
                        info.OperatingSystem = GetSearchPropertyString(result, "operatingSystem", String.Empty);
                        info.Description = GetSearchPropertyString(result, "description", String.Empty);
                        info.WhenCreated = GetSearchPropertyString(result, "whenCreated", String.Empty);
                        info.WhenChanged = GetSearchPropertyString(result, "whenChanged", String.Empty);
                        info.SamAccountName = GetSearchPropertyString(result, "sAMAccountName", String.Empty);
                        info.CanonicalName = GetSearchPropertyString(result, "canonicalName", String.Empty);
                        info.PwdLastSet = GetAdFileTimeString(result, "pwdLastSet");
                        info.LastLogonTimestamp = GetAdFileTimeString(result, "lastLogonTimestamp");
                        int spnCount;
                        info.ServicePrincipalNames = GetMultiValueProperty(result, "servicePrincipalName", out spnCount);
                        info.ServicePrincipalNameCount = spnCount;

                        if (result.Properties.Contains("objectGUID") && result.Properties["objectGUID"].Count > 0)
                        {
                            byte[] guidBytes = result.Properties["objectGUID"][0] as byte[];
                            if (guidBytes != null && guidBytes.Length == 16)
                                info.ObjectGuid = new Guid(guidBytes).ToString();
                        }

                        if (result.Properties.Contains("userAccountControl") && result.Properties["userAccountControl"].Count > 0)
                        {
                            int uac;
                            if (Int32.TryParse(Convert.ToString(result.Properties["userAccountControl"][0]), out uac))
                            {
                                info.UserAccountControl = uac;
                                info.Enabled = (uac & 0x0002) == 0;
                            }
                        }

                        if (result.Properties.Contains("msDS-SupportedEncryptionTypes") && result.Properties["msDS-SupportedEncryptionTypes"].Count > 0)
                        {
                            int encryptionTypes;
                            if (Int32.TryParse(Convert.ToString(result.Properties["msDS-SupportedEncryptionTypes"][0]), out encryptionTypes))
                                info.SupportedEncryptionTypes = encryptionTypes;
                        }

                        ReadObjectSecurityAndChildren(info, user, password);
                        WriteLog(log, "INFO", "AD computer account found on LDAP server '" + ldapServer + "'.");
                        return info;
                    }
                }
            }
            catch (Exception ex)
            {
                WriteLog(log, "WARN", "Unable to query Active Directory for computer account existence: " + ex.Message);
                return info;
            }
        }

        internal static bool DeleteComputerAccount(
            AdComputerAccountInfo account,
            string computerName,
            string user,
            string password,
            Action<string, string> log,
            out string error)
        {
            error = null;

            if (account == null ||
                !account.LookupSucceeded ||
                !account.Exists ||
                String.IsNullOrWhiteSpace(account.LdapPath) ||
                String.IsNullOrWhiteSpace(account.ObjectGuid))
            {
                error = "The existing AD computer account could not be located and identity-verified reliably.";
                return false;
            }

            try
            {
                using (DirectoryEntry target = CreateEntry(account.LdapPath, user, password))
                {
                    target.RefreshCache(new string[] { "sAMAccountName", "objectClass", "objectGUID" });

                    string actualSam = Convert.ToString(target.Properties["sAMAccountName"].Value);
                    bool isComputerObject = false;
                    foreach (object value in target.Properties["objectClass"])
                    {
                        if (String.Equals(Convert.ToString(value), "computer", StringComparison.OrdinalIgnoreCase))
                        {
                            isComputerObject = true;
                            break;
                        }
                    }

                    string actualGuid = String.Empty;
                    byte[] guidBytes = target.Properties["objectGUID"].Value as byte[];
                    if (guidBytes != null && guidBytes.Length == 16)
                        actualGuid = new Guid(guidBytes).ToString();

                    int childObjectCount = 0;
                    try
                    {
                        foreach (DirectoryEntry child in target.Children)
                        {
                            childObjectCount++;
                            child.Dispose();
                            break;
                        }
                    }
                    catch (Exception childEx)
                    {
                        error =
                            "Safety check failed: child-object state could not be verified immediately before deletion: " +
                            childEx.Message;
                        WriteLog(log, "ERROR", error);
                        return false;
                    }

                    error = ValidateDeleteTargetState(
                        computerName,
                        account.ObjectGuid,
                        actualSam,
                        isComputerObject,
                        actualGuid,
                        childObjectCount);

                    if (!String.IsNullOrWhiteSpace(error))
                    {
                        WriteLog(log, "ERROR", error);
                        return false;
                    }

                    WriteLog(
                        log,
                        "WARN",
                        "Deleting the confirmed AD computer account with a non-recursive LDAP delete: " +
                        account.DistinguishedName);

                    using (DirectoryEntry parent = target.Parent)
                    {
                        if (parent == null)
                        {
                            error = "Safety check failed: the parent container could not be resolved.";
                            WriteLog(log, "ERROR", error);
                            return false;
                        }

                        // DirectoryEntries.Remove is intentionally non-recursive. If a child
                        // appears after the pre-delete check, Active Directory rejects the
                        // delete instead of recursively removing the newly-added subtree.
                        parent.Children.Remove(target);
                    }
                }

                WriteLog(log, "SUCCESS", "AD computer account deleted.");
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                WriteLog(log, "ERROR", "Unable to delete the AD computer account: " + ex.Message);
                return false;
            }
        }

        internal static string ValidateDeleteTargetState(
            string computerName,
            string expectedGuid,
            string actualSam,
            bool isComputerObject,
            string actualGuid,
            int childObjectCount)
        {
            if (String.IsNullOrWhiteSpace(computerName) ||
                String.IsNullOrWhiteSpace(expectedGuid))
            {
                return "Safety check failed: the expected AD computer identity is incomplete.";
            }

            if (!isComputerObject ||
                !String.Equals(actualSam, computerName + "$", StringComparison.OrdinalIgnoreCase))
            {
                return "Safety check failed: the LDAP object no longer matches the requested computer account.";
            }

            if (String.IsNullOrWhiteSpace(actualGuid) ||
                !String.Equals(actualGuid, expectedGuid, StringComparison.OrdinalIgnoreCase))
            {
                return "Safety check failed: the AD object identity changed after lookup. Run the lookup again.";
            }

            if (childObjectCount > 0)
            {
                return
                    "Safety check failed: the AD computer object now has child objects. " +
                    "Re-run diagnostics before deletion.";
            }

            return null;
        }


        private static void ReadObjectSecurityAndChildren(AdComputerAccountInfo info, string user, string password)
        {
            if (info == null || String.IsNullOrWhiteSpace(info.LdapPath))
                return;

            try
            {
                using (DirectoryEntry entry = CreateEntry(info.LdapPath, user, password))
                {
                    try
                    {
                        IdentityReference owner = entry.ObjectSecurity.GetOwner(typeof(NTAccount));
                        if (owner != null)
                            info.Owner = owner.Value;
                    }
                    catch
                    {
                    }

                    try
                    {
                        int count = 0;
                        foreach (DirectoryEntry child in entry.Children)
                        {
                            count++;
                            child.Dispose();
                            if (count >= 1000)
                                break;
                        }
                        info.ChildObjectCount = count;
                    }
                    catch
                    {
                    }
                }
            }
            catch
            {
            }
        }

        private static DirectoryEntry CreateEntry(string path, string user, string password)
        {
            if (!String.IsNullOrWhiteSpace(user) && password != null)
                return new DirectoryEntry(path, user, password, AuthenticationTypes.Secure);

            return new DirectoryEntry(path);
        }

        private static string GetMultiValueProperty(SearchResult result, string propertyName, out int count)
        {
            count = 0;
            if (result == null || !result.Properties.Contains(propertyName))
                return String.Empty;

            List<string> values = new List<string>();
            foreach (object value in result.Properties[propertyName])
            {
                count++;
                if (values.Count < 50)
                    values.Add(Convert.ToString(value) ?? String.Empty);
            }

            return String.Join("; ", values.ToArray());
        }

        private static string GetAdFileTimeString(SearchResult result, string propertyName)
        {
            if (result == null || !result.Properties.Contains(propertyName) || result.Properties[propertyName].Count == 0)
                return String.Empty;

            try
            {
                long value = Convert.ToInt64(result.Properties[propertyName][0]);
                if (value <= 0)
                    return String.Empty;
                return DateTime.FromFileTimeUtc(value).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch
            {
                return Convert.ToString(result.Properties[propertyName][0]) ?? String.Empty;
            }
        }

        private static string GetSearchPropertyString(SearchResult result, string propertyName, string fallback)
        {
            if (result != null && result.Properties.Contains(propertyName) && result.Properties[propertyName].Count > 0)
            {
                object value = result.Properties[propertyName][0];
                if (value is DateTime)
                    return ((DateTime)value).ToString("yyyy-MM-dd HH:mm:ss");
                return Convert.ToString(value) ?? fallback;
            }

            return fallback;
        }

        private static void WriteLog(Action<string, string> log, string level, string message)
        {
            if (log != null)
                log(level, message);
        }
    }
}
