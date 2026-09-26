using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.IO;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class AdRecycleBinStatus
    {
        internal bool QuerySucceeded;
        internal bool Enabled;
        internal string Dc = String.Empty;
        internal string DefaultNamingContext = String.Empty;
        internal string ConfigurationNamingContext = String.Empty;
        internal string FeatureDn = String.Empty;
        internal string Details = String.Empty;
        internal string Error = String.Empty;
    }

    internal sealed class DeletedComputerObjectInfo
    {
        internal bool QuerySucceeded;
        internal bool Found;
        internal int MatchCount;
        internal bool Restorable;
        internal bool Recycled;
        internal string Dc = String.Empty;
        internal string DistinguishedName = String.Empty;
        internal string LastKnownParent = String.Empty;
        internal string LastKnownRdn = String.Empty;
        internal string RestoreDistinguishedName = String.Empty;
        internal string SamAccountName = String.Empty;
        internal string DnsHostName = String.Empty;
        internal string ObjectGuid = String.Empty;
        internal string ObjectSid = String.Empty;
        internal string WhenChanged = String.Empty;
        internal string OperatingSystem = String.Empty;
        internal string Description = String.Empty;
        internal string PwdLastSet = String.Empty;
        internal string ServicePrincipalNames = String.Empty;
        internal int ServicePrincipalNameCount;
        internal int? UserAccountControl;
        internal int? SupportedEncryptionTypes;
        internal string Error = String.Empty;
    }

    internal sealed class AdRecoveryPackage
    {
        internal string Id = String.Empty;
        internal string CreatedUtc = String.Empty;
        internal string Domain = String.Empty;
        internal string Dc = String.Empty;
        internal string ComputerName = String.Empty;
        internal string OriginalDistinguishedName = String.Empty;
        internal string ObjectGuid = String.Empty;
        internal string SamAccountName = String.Empty;
        internal string DnsHostName = String.Empty;
        internal string OperatingSystem = String.Empty;
        internal string Description = String.Empty;
        internal string Owner = String.Empty;
        internal string WhenCreated = String.Empty;
        internal string WhenChanged = String.Empty;
        internal string PwdLastSet = String.Empty;
        internal string LastLogonTimestamp = String.Empty;
        internal string CanonicalName = String.Empty;
        internal string ServicePrincipalNames = String.Empty;
        internal int ServicePrincipalNameCount;
        internal int ChildObjectCount;
        internal int? UserAccountControl;
        internal int? SupportedEncryptionTypes;
        internal bool RecycleBinQuerySucceeded;
        internal bool RecycleBinEnabled;
        internal string RecycleBinDetails = String.Empty;
        internal string RecoveryNote = String.Empty;
    }

    internal sealed class AdRestoreResult
    {
        internal bool Success;
        internal string Dc = String.Empty;
        internal string DeletedDn = String.Empty;
        internal string RestoredDn = String.Empty;
        internal string Message = String.Empty;
    }

    internal static class AdRecycleBinRecoveryService
    {
        internal const string RecycleBinFeatureGuid = "766ddcd8-acd0-445e-f3b9-a7f9b6744f2a";
        internal const string ShowDeletedOid = "1.2.840.113556.1.4.417";
        internal const string ShowRecycledOid = "1.2.840.113556.1.4.2064";

        internal static AdRecycleBinStatus GetStatus(
            string domain,
            string dc,
            string user,
            string password)
        {
            AdRecycleBinStatus result = new AdRecycleBinStatus();
            result.Dc = ResolveDc(domain, dc);

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                result.Error = "No domain controller is available.";
                return result;
            }

            try
            {
                using (LdapConnection connection = CreateConnection(result.Dc, user, password))
                {
                    string defaultNc;
                    string configNc;
                    ReadNamingContexts(connection, out defaultNc, out configNc);
                    result.DefaultNamingContext = defaultNc;
                    result.ConfigurationNamingContext = configNc;

                    if (String.IsNullOrWhiteSpace(configNc))
                    {
                        result.Error = "configurationNamingContext was not returned by RootDSE.";
                        return result;
                    }

                    result.FeatureDn =
                        "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service," +
                        "CN=Windows NT,CN=Services," + configNc;

                    SearchRequest featureRequest = new SearchRequest(
                        result.FeatureDn,
                        "(objectClass=*)",
                        SearchScope.Base,
                        "msDS-OptionalFeatureGUID",
                        "msDS-EnabledFeatureBL");

                    SearchResponse featureResponse =
                        (SearchResponse)connection.SendRequest(featureRequest);

                    bool backlinkEnabled = false;
                    if (featureResponse.Entries.Count > 0)
                    {
                        SearchResultEntry entry = featureResponse.Entries[0];
                        backlinkEnabled = HasAnyValue(entry, "msDS-EnabledFeatureBL");
                    }

                    string partitionsDn = "CN=Partitions," + configNc;
                    SearchRequest partitionsRequest = new SearchRequest(
                        partitionsDn,
                        "(objectClass=*)",
                        SearchScope.Base,
                        "msDS-EnabledFeature");

                    SearchResponse partitionsResponse =
                        (SearchResponse)connection.SendRequest(partitionsRequest);

                    bool partitionsEnabled = false;
                    if (partitionsResponse.Entries.Count > 0)
                    {
                        SearchResultEntry entry = partitionsResponse.Entries[0];
                        partitionsEnabled = ContainsDn(
                            entry,
                            "msDS-EnabledFeature",
                            result.FeatureDn);
                    }

                    result.QuerySucceeded = true;
                    result.Enabled = partitionsEnabled || backlinkEnabled;
                    result.Details = result.Enabled
                        ? "Active Directory Recycle Bin is enabled for the forest."
                        : "Active Directory Recycle Bin is not enabled for the forest.";
                    return result;
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                result.Details = "Recycle Bin status could not be determined.";
                return result;
            }
        }

        internal static DeletedComputerObjectInfo FindDeletedComputer(
            string domain,
            string dc,
            string computerName,
            string user,
            string password)
        {
            DeletedComputerObjectInfo result = new DeletedComputerObjectInfo();
            result.Dc = ResolveDc(domain, dc);

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                result.Error = "No domain controller is available.";
                return result;
            }

            if (String.IsNullOrWhiteSpace(computerName))
            {
                result.Error = "Computer name is required.";
                return result;
            }

            try
            {
                using (LdapConnection connection = CreateConnection(result.Dc, user, password))
                {
                    string defaultNc;
                    string configNc;
                    ReadNamingContexts(connection, out defaultNc, out configNc);
                    if (String.IsNullOrWhiteSpace(defaultNc))
                    {
                        result.Error = "defaultNamingContext was not returned by RootDSE.";
                        return result;
                    }

                    string deletedBase = "CN=Deleted Objects," + defaultNc;
                    string filter =
                        BuildDeletedComputerFilter(computerName);

                    SearchRequest request = new SearchRequest(
                        deletedBase,
                        filter,
                        SearchScope.OneLevel,
                        "distinguishedName",
                        "lastKnownParent",
                        "msDS-LastKnownRDN",
                        "sAMAccountName",
                        "dNSHostName",
                        "objectGUID",
                        "objectSid",
                        "whenChanged",
                        "isDeleted",
                        "isRecycled",
                        "operatingSystem",
                        "description",
                        "pwdLastSet",
                        "servicePrincipalName",
                        "userAccountControl",
                        "msDS-SupportedEncryptionTypes");

                    request.Controls.Add(
                        new DirectoryControl(ShowRecycledOid, null, true, true));

                    SearchResponse response = (SearchResponse)connection.SendRequest(request);
                    result.QuerySucceeded = true;
                    result.MatchCount = response.Entries.Count;

                    if (response.Entries.Count == 0)
                        return result;

                    if (response.Entries.Count > 1)
                    {
                        result.Found = true;
                        result.Restorable = false;
                        result.Error =
                            "Multiple deleted computer objects match " +
                            computerName + "$. Restore is blocked until the intended object is identified unambiguously.";
                        return result;
                    }

                    SearchResultEntry best = response.Entries[0];
                    result.Found = true;
                    result.DistinguishedName = GetString(best, "distinguishedName");
                    result.LastKnownParent = GetString(best, "lastKnownParent");
                    result.LastKnownRdn = GetString(best, "msDS-LastKnownRDN");
                    result.SamAccountName = GetString(best, "sAMAccountName");
                    result.DnsHostName = GetString(best, "dNSHostName");
                    result.ObjectGuid = GetGuid(best, "objectGUID");
                    result.ObjectSid = GetSid(best, "objectSid");
                    result.WhenChanged = GetString(best, "whenChanged");
                    result.OperatingSystem = GetString(best, "operatingSystem");
                    result.Description = GetString(best, "description");
                    result.PwdLastSet = GetString(best, "pwdLastSet");
                    result.Recycled = GetBoolean(best, "isRecycled");

                    int count;
                    result.ServicePrincipalNames = GetMulti(best, "servicePrincipalName", out count);
                    result.ServicePrincipalNameCount = count;
                    result.UserAccountControl = GetInt(best, "userAccountControl");
                    result.SupportedEncryptionTypes = GetInt(best, "msDS-SupportedEncryptionTypes");

                    result.RestoreDistinguishedName =
                        BuildRestoreDn(
                            computerName,
                            result.LastKnownRdn,
                            result.LastKnownParent);

                    result.Restorable =
                        !result.Recycled &&
                        !String.IsNullOrWhiteSpace(result.DistinguishedName) &&
                        !String.IsNullOrWhiteSpace(result.RestoreDistinguishedName);

                    return result;
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                return result;
            }
        }

        internal static bool CreatePreDeleteRecoveryPackage(
            AdComputerAccountInfo account,
            string domain,
            string dc,
            string user,
            string password,
            out string path,
            out string error)
        {
            path = String.Empty;
            error = String.Empty;

            if (account == null || !account.LookupSucceeded || !account.Exists)
            {
                error = "The AD computer account is not available for recovery-package creation.";
                return false;
            }

            try
            {
                AdRecycleBinStatus recycle = GetStatus(domain, dc, user, password);

                AdRecoveryPackage package = new AdRecoveryPackage();
                package.Id =
                    DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" +
                    Guid.NewGuid().ToString("N").Substring(0, 8);
                package.CreatedUtc = DateTime.UtcNow.ToString("o");
                package.Domain = domain ?? String.Empty;
                package.Dc = ResolveDc(domain, dc);
                package.ComputerName =
                    !String.IsNullOrWhiteSpace(account.SamAccountName)
                        ? account.SamAccountName.TrimEnd('$')
                        : Environment.MachineName;
                package.OriginalDistinguishedName = account.DistinguishedName ?? String.Empty;
                package.ObjectGuid = account.ObjectGuid ?? String.Empty;
                package.SamAccountName = account.SamAccountName ?? String.Empty;
                package.DnsHostName = account.DnsHostName ?? String.Empty;
                package.OperatingSystem = account.OperatingSystem ?? String.Empty;
                package.Description = account.Description ?? String.Empty;
                package.Owner = account.Owner ?? String.Empty;
                package.WhenCreated = account.WhenCreated ?? String.Empty;
                package.WhenChanged = account.WhenChanged ?? String.Empty;
                package.PwdLastSet = account.PwdLastSet ?? String.Empty;
                package.LastLogonTimestamp = account.LastLogonTimestamp ?? String.Empty;
                package.CanonicalName = account.CanonicalName ?? String.Empty;
                package.ServicePrincipalNames = account.ServicePrincipalNames ?? String.Empty;
                package.ServicePrincipalNameCount = account.ServicePrincipalNameCount;
                package.ChildObjectCount = account.ChildObjectCount;
                package.UserAccountControl = account.UserAccountControl;
                package.SupportedEncryptionTypes = account.SupportedEncryptionTypes;
                package.RecycleBinQuerySucceeded = recycle.QuerySucceeded;
                package.RecycleBinEnabled = recycle.Enabled;
                package.RecycleBinDetails =
                    !String.IsNullOrWhiteSpace(recycle.Details)
                        ? recycle.Details
                        : recycle.Error;
                package.RecoveryNote = recycle.Enabled
                    ? "Recycle Bin is enabled. A deleted object can be searched and restored while it remains a deleted-object."
                    : "Recycle Bin is not confirmed as enabled. This package preserves pre-delete identity metadata, but automatic full-fidelity restore is disabled.";

                string folder = GetRecoveryFolder();
                path = Path.Combine(
                    folder,
                    package.Id + "-" + SafeFileName(package.ComputerName) + ".json");

                File.WriteAllText(
                    path,
                    JsonReportSerializer.Serialize(package),
                    new UTF8Encoding(false));

                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        internal static AdRestoreResult RestoreDeletedComputer(
            string domain,
            string dc,
            string computerName,
            string user,
            string password)
        {
            AdRestoreResult result = new AdRestoreResult();
            result.Dc = ResolveDc(domain, dc);

            AdRecycleBinStatus status = GetStatus(
                domain,
                result.Dc,
                user,
                password);

            if (!status.QuerySucceeded)
            {
                result.Message =
                    "Recycle Bin status could not be verified: " + status.Error;
                return result;
            }

            if (!status.Enabled)
            {
                result.Message =
                    "Active Directory Recycle Bin is not enabled. Automatic restore is blocked to avoid incomplete tombstone reanimation.";
                return result;
            }

            DeletedComputerObjectInfo deleted = FindDeletedComputer(
                domain,
                result.Dc,
                computerName,
                user,
                password);

            if (!deleted.QuerySucceeded)
            {
                result.Message =
                    "Deleted-object search failed: " + deleted.Error;
                return result;
            }

            if (!deleted.Found)
            {
                result.Message =
                    "No deleted computer object was found for " +
                    computerName + "$.";
                return result;
            }

            if (deleted.Recycled)
            {
                result.Message =
                    "The object is already recycled and is no longer eligible for Recycle Bin restore.";
                return result;
            }

            if (!deleted.Restorable)
            {
                result.Message =
                    "The deleted object does not contain enough last-known parent/RDN data for safe restore.";
                return result;
            }

            try
            {
                using (LdapConnection connection = CreateConnection(result.Dc, user, password))
                {
                    SearchRequest parentRequest = new SearchRequest(
                        deleted.LastKnownParent,
                        "(objectClass=*)",
                        SearchScope.Base,
                        "distinguishedName");

                    SearchResponse parentResponse =
                        (SearchResponse)connection.SendRequest(parentRequest);

                    if (parentResponse.Entries.Count == 0)
                    {
                        result.Message =
                            "The original parent container no longer exists: " +
                            deleted.LastKnownParent;
                        return result;
                    }

                    try
                    {
                        SearchRequest targetRequest = new SearchRequest(
                            deleted.RestoreDistinguishedName,
                            "(objectClass=*)",
                            SearchScope.Base,
                            "distinguishedName");

                        SearchResponse targetResponse =
                            (SearchResponse)connection.SendRequest(targetRequest);

                        if (targetResponse.Entries.Count > 0)
                        {
                            result.Message =
                                "Restore is blocked because the original target DN is already occupied: " +
                                deleted.RestoreDistinguishedName;
                            return result;
                        }
                    }
                    catch (DirectoryOperationException ex)
                    {
                        if (ex.Response == null ||
                            ex.Response.ResultCode != ResultCode.NoSuchObject)
                            throw;
                    }

                    ModifyRequest modify = new ModifyRequest(deleted.DistinguishedName);

                    DirectoryAttributeModification removeDeleted =
                        new DirectoryAttributeModification();
                    removeDeleted.Name = "isDeleted";
                    removeDeleted.Operation = DirectoryAttributeOperation.Delete;
                    modify.Modifications.Add(removeDeleted);

                    DirectoryAttributeModification restoreDn =
                        new DirectoryAttributeModification();
                    restoreDn.Name = "distinguishedName";
                    restoreDn.Operation = DirectoryAttributeOperation.Replace;
                    restoreDn.Add(deleted.RestoreDistinguishedName);
                    modify.Modifications.Add(restoreDn);

                    modify.Controls.Add(
                        new DirectoryControl(ShowDeletedOid, null, true, true));

                    connection.SendRequest(modify);

                    result.Success = true;
                    result.DeletedDn = deleted.DistinguishedName;
                    result.RestoredDn = deleted.RestoreDistinguishedName;
                    result.Message =
                        "Deleted computer object restored to " +
                        deleted.RestoreDistinguishedName + ".";
                    return result;
                }
            }
            catch (Exception ex)
            {
                result.Message = ex.Message;
                return result;
            }
        }

        internal static string ToText(AdRecycleBinStatus status)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Active Directory Recycle Bin");
            sb.AppendLine("============================");
            sb.AppendLine("DC:             " + First(status.Dc, "(none)"));
            sb.AppendLine("Query:          " + (status.QuerySucceeded ? "OK" : "FAILED"));
            sb.AppendLine("Recycle Bin:    " + (status.QuerySucceeded ? (status.Enabled ? "ENABLED" : "DISABLED") : "UNKNOWN"));
            sb.AppendLine("Default NC:     " + First(status.DefaultNamingContext, "(not returned)"));
            sb.AppendLine("Configuration:  " + First(status.ConfigurationNamingContext, "(not returned)"));
            sb.AppendLine("Feature GUID:   " + RecycleBinFeatureGuid);
            if (!String.IsNullOrWhiteSpace(status.Details))
                sb.AppendLine("Details:        " + status.Details);
            if (!String.IsNullOrWhiteSpace(status.Error))
                sb.AppendLine("Error:          " + status.Error);
            return sb.ToString();
        }

        internal static string ToText(DeletedComputerObjectInfo deleted)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Deleted AD Computer Object");
            sb.AppendLine("==========================");
            sb.AppendLine("DC:             " + First(deleted.Dc, "(none)"));
            sb.AppendLine("Query:          " + (deleted.QuerySucceeded ? "OK" : "FAILED"));
            sb.AppendLine("Found:          " + (deleted.Found ? "YES" : "NO"));

            if (deleted.Found)
            {
                sb.AppendLine("Restorable:     " + (deleted.Restorable ? "YES" : "NO"));
                sb.AppendLine("Recycled:       " + (deleted.Recycled ? "YES" : "NO"));
                sb.AppendLine("Deleted DN:     " + First(deleted.DistinguishedName, "(unknown)"));
                sb.AppendLine("Restore DN:     " + First(deleted.RestoreDistinguishedName, "(unknown)"));
                sb.AppendLine("Last parent:    " + First(deleted.LastKnownParent, "(unknown)"));
                sb.AppendLine("Last RDN:       " + First(deleted.LastKnownRdn, "(unknown)"));
                sb.AppendLine("SAM:            " + First(deleted.SamAccountName, "(unknown)"));
                sb.AppendLine("DNS:            " + First(deleted.DnsHostName, "(unknown)"));
                sb.AppendLine("GUID:           " + First(deleted.ObjectGuid, "(unknown)"));
                sb.AppendLine("SID:            " + First(deleted.ObjectSid, "(unknown)"));
                sb.AppendLine("Changed:        " + First(deleted.WhenChanged, "(unknown)"));
                sb.AppendLine("SPN count:      " + deleted.ServicePrincipalNameCount);
                if (!String.IsNullOrWhiteSpace(deleted.ServicePrincipalNames))
                    sb.AppendLine("SPNs:           " + deleted.ServicePrincipalNames);
            }

            if (!String.IsNullOrWhiteSpace(deleted.Error))
                sb.AppendLine("Error:          " + deleted.Error);

            return sb.ToString();
        }

        internal static string ToText(AdRestoreResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Deleted AD Computer Restore");
            sb.AppendLine("===========================");
            sb.AppendLine("Result:      " + (result.Success ? "SUCCESS" : "FAILED"));
            sb.AppendLine("DC:          " + First(result.Dc, "(none)"));
            if (!String.IsNullOrWhiteSpace(result.DeletedDn))
                sb.AppendLine("Deleted DN:  " + result.DeletedDn);
            if (!String.IsNullOrWhiteSpace(result.RestoredDn))
                sb.AppendLine("Restored DN: " + result.RestoredDn);
            sb.AppendLine("Details:     " + First(result.Message, "(none)"));
            return sb.ToString();
        }

        internal static string GetLatestRecoveryPackagePath()
        {
            string folder = GetRecoveryFolderPath();
            if (!Directory.Exists(folder))
                return String.Empty;

            FileInfo[] files = new DirectoryInfo(folder).GetFiles("*.json");
            if (files.Length == 0)
                return String.Empty;

            Array.Sort(files, delegate(FileInfo a, FileInfo b)
            {
                return b.LastWriteTimeUtc.CompareTo(a.LastWriteTimeUtc);
            });

            return files[0].FullName;
        }

        private static LdapConnection CreateConnection(
            string dc,
            string user,
            string password)
        {
            LdapDirectoryIdentifier id =
                new LdapDirectoryIdentifier(dc, 389, true, false);
            LdapConnection connection = new LdapConnection(id);
            connection.Timeout = TimeSpan.FromSeconds(10);
            connection.AuthType = AuthType.Negotiate;
            connection.SessionOptions.ProtocolVersion = 3;

            NetworkCredential credential = BuildCredential(user, password);
            if (credential != null)
                connection.Credential = credential;

            connection.Bind();
            return connection;
        }

        private static NetworkCredential BuildCredential(string user, string password)
        {
            if (String.IsNullOrWhiteSpace(user) || password == null)
                return null;

            string account;
            string domain;
            if (!NetworkCredentialProcessRunner.TrySplitUser(
                user,
                out account,
                out domain))
                return null;

            return String.IsNullOrWhiteSpace(domain)
                ? new NetworkCredential(account, password)
                : new NetworkCredential(account, password, domain);
        }

        private static void ReadNamingContexts(
            LdapConnection connection,
            out string defaultNc,
            out string configNc)
        {
            SearchRequest request = new SearchRequest(
                null,
                "(objectClass=*)",
                SearchScope.Base,
                "defaultNamingContext",
                "configurationNamingContext");

            SearchResponse response =
                (SearchResponse)connection.SendRequest(request);

            defaultNc = String.Empty;
            configNc = String.Empty;

            if (response.Entries.Count == 0)
                return;

            SearchResultEntry root = response.Entries[0];
            defaultNc = GetString(root, "defaultNamingContext");
            configNc = GetString(root, "configurationNamingContext");
        }

        private static string ResolveDc(string domain, string dc)
        {
            string result = DomainValidation.NormalizeDirectoryServer(dc);
            if (!String.IsNullOrWhiteSpace(result))
                return result;

            DomainDiscoveryResult discovery =
                NativeMethods.DiscoverDomain(domain, false);

            return discovery.Success
                ? DomainValidation.NormalizeDirectoryServer(
                    discovery.DomainControllerName)
                : String.Empty;
        }

        private static bool ContainsDn(
            SearchResultEntry entry,
            string attribute,
            string expected)
        {
            if (entry == null ||
                !entry.Attributes.Contains(attribute) ||
                String.IsNullOrWhiteSpace(expected))
                return false;

            foreach (object value in entry.Attributes[attribute])
            {
                if (String.Equals(
                    Convert.ToString(value),
                    expected,
                    StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static bool HasAnyValue(
            SearchResultEntry entry,
            string attribute)
        {
            return entry != null &&
                   entry.Attributes.Contains(attribute) &&
                   entry.Attributes[attribute].Count > 0;
        }

        private static string GetString(
            SearchResultEntry entry,
            string attribute)
        {
            if (entry == null ||
                !entry.Attributes.Contains(attribute) ||
                entry.Attributes[attribute].Count == 0)
                return String.Empty;

            return Convert.ToString(entry.Attributes[attribute][0]) ??
                   String.Empty;
        }

        private static bool GetBoolean(
            SearchResultEntry entry,
            string attribute)
        {
            string value = GetString(entry, attribute);
            return String.Equals(value, "TRUE", StringComparison.OrdinalIgnoreCase) ||
                   String.Equals(value, "1", StringComparison.OrdinalIgnoreCase);
        }

        private static int? GetInt(
            SearchResultEntry entry,
            string attribute)
        {
            int value;
            return Int32.TryParse(GetString(entry, attribute), out value)
                ? (int?)value
                : null;
        }

        private static string GetGuid(
            SearchResultEntry entry,
            string attribute)
        {
            if (entry == null ||
                !entry.Attributes.Contains(attribute) ||
                entry.Attributes[attribute].Count == 0)
                return String.Empty;

            byte[] value = entry.Attributes[attribute][0] as byte[];
            return value != null && value.Length == 16
                ? new Guid(value).ToString()
                : String.Empty;
        }

        private static string GetSid(
            SearchResultEntry entry,
            string attribute)
        {
            if (entry == null ||
                !entry.Attributes.Contains(attribute) ||
                entry.Attributes[attribute].Count == 0)
                return String.Empty;

            byte[] value = entry.Attributes[attribute][0] as byte[];
            if (value == null)
                return String.Empty;

            try
            {
                return new SecurityIdentifier(value, 0).Value;
            }
            catch
            {
                return String.Empty;
            }
        }

        private static string GetMulti(
            SearchResultEntry entry,
            string attribute,
            out int count)
        {
            count = 0;
            if (entry == null || !entry.Attributes.Contains(attribute))
                return String.Empty;

            List<string> values = new List<string>();
            foreach (object value in entry.Attributes[attribute])
            {
                string text = Convert.ToString(value) ?? String.Empty;
                if (text.Length == 0)
                    continue;
                values.Add(text);
            }

            count = values.Count;
            values.Sort(StringComparer.OrdinalIgnoreCase);
            return String.Join("; ", values.ToArray());
        }

        internal static string BuildDeletedComputerFilter(string computerName)
        {
            string sam =
                DomainValidation.EscapeLdapFilterValue(
                    (computerName ?? String.Empty).Trim() + "$");
            return "(&(isDeleted=TRUE)(objectClass=computer)(sAMAccountName=" +
                   sam + "))";
        }

        internal static string BuildRestoreDn(
            string computerName,
            string lastKnownRdn,
            string lastKnownParent)
        {
            if (String.IsNullOrWhiteSpace(lastKnownParent))
                return String.Empty;

            string rdn = lastKnownRdn;
            if (String.IsNullOrWhiteSpace(rdn))
                rdn = "CN=" + EscapeDnComponent(computerName ?? String.Empty);

            return rdn + "," + lastKnownParent;
        }

        private static string EscapeDnComponent(string value)
        {
            string text = value ?? String.Empty;
            return text
                .Replace("\\", "\\5c")
                .Replace(",", "\\2c")
                .Replace("+", "\\2b")
                .Replace("\"", "\\22")
                .Replace("<", "\\3c")
                .Replace(">", "\\3e")
                .Replace(";", "\\3b");
        }

        private static string GetRecoveryFolder()
        {
            string path = GetRecoveryFolderPath();
            Directory.CreateDirectory(path);
            HardenFolder(path);
            return path;
        }

        private static string GetRecoveryFolderPath()
        {
            return Path.Combine(
                Environment.GetFolderPath(
                    Environment.SpecialFolder.CommonApplicationData),
                "DomainMembershipCheckRepair",
                "RecoveryPackages");
        }

        private static void HardenFolder(string path)
        {
            try
            {
                DirectorySecurity security = new DirectorySecurity();
                security.SetAccessRuleProtection(true, false);
                InheritanceFlags inheritance =
                    InheritanceFlags.ContainerInherit |
                    InheritanceFlags.ObjectInherit;

                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(
                        WellKnownSidType.LocalSystemSid,
                        null),
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(
                        WellKnownSidType.BuiltinAdministratorsSid,
                        null),
                    FileSystemRights.FullControl,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                security.AddAccessRule(new FileSystemAccessRule(
                    new SecurityIdentifier(
                        WellKnownSidType.BuiltinUsersSid,
                        null),
                    FileSystemRights.ReadAndExecute |
                    FileSystemRights.Read,
                    inheritance,
                    PropagationFlags.None,
                    AccessControlType.Allow));

                Directory.SetAccessControl(path, security);
            }
            catch
            {
            }
        }

        private static string SafeFileName(string value)
        {
            string text = String.IsNullOrWhiteSpace(value)
                ? "computer"
                : value;

            foreach (char c in Path.GetInvalidFileNameChars())
                text = text.Replace(c, '_');

            return text;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value)
                ? fallback
                : value;
        }
    }
}
