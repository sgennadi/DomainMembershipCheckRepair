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

                using (DirectoryEntry rootDse = new DirectoryEntry("LDAP://" + ldapServer + "/RootDSE", user, password, AuthenticationTypes.Secure))
                {
                    object namingContextValue = rootDse.Properties["defaultNamingContext"].Value;
                    if (namingContextValue == null)
                    {
                        WriteLog(log, "WARN", "Active Directory did not return defaultNamingContext.");
                        return info;
                    }

                    string namingContext = namingContextValue.ToString();
                    using (DirectoryEntry root = new DirectoryEntry("LDAP://" + ldapServer + "/" + namingContext, user, password, AuthenticationTypes.Secure))
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

            if (account == null || !account.LookupSucceeded || !account.Exists || String.IsNullOrWhiteSpace(account.LdapPath))
            {
                error = "The existing AD computer account could not be located reliably.";
                return false;
            }

            try
            {
                using (DirectoryEntry target = new DirectoryEntry(account.LdapPath, user, password, AuthenticationTypes.Secure))
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

                    if (!isComputerObject || !String.Equals(actualSam, computerName + "$", StringComparison.OrdinalIgnoreCase))
                    {
                        error = "Safety check failed: the LDAP object no longer matches the requested computer account.";
                        return false;
                    }

                    if (!String.IsNullOrWhiteSpace(account.ObjectGuid) && target.Properties["objectGUID"].Value is byte[])
                    {
                        string actualGuid = new Guid((byte[])target.Properties["objectGUID"].Value).ToString();
                        if (!String.Equals(actualGuid, account.ObjectGuid, StringComparison.OrdinalIgnoreCase))
                        {
                            error = "Safety check failed: the AD object changed after it was looked up. Run the lookup again.";
                            return false;
                        }
                    }

                    WriteLog(log, "WARN", "Deleting the confirmed AD computer account: " + account.DistinguishedName);
                    target.DeleteTree();
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


        private static void ReadObjectSecurityAndChildren(AdComputerAccountInfo info, string user, string password)
        {
            if (info == null || String.IsNullOrWhiteSpace(info.LdapPath))
                return;

            try
            {
                using (DirectoryEntry entry = new DirectoryEntry(info.LdapPath, user, password, AuthenticationTypes.Secure))
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
