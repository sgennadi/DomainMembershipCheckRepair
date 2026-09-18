using System;
using System.DirectoryServices;

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
                                info.Enabled = (uac & 0x0002) == 0;
                        }

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
