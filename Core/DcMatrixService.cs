using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.DirectoryServices;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal sealed class DcMatrixEntry
    {
        internal string Host = String.Empty;
        internal bool DnsResolved;
        internal string Ports = String.Empty;
        internal string TimeSkew = String.Empty;
        internal bool RootDseOk;
        internal string DnsHostName = String.Empty;
        internal string DefaultNamingContext = String.Empty;
        internal string ConfigurationNamingContext = String.Empty;
        internal string LdapError = String.Empty;
        internal string Site = String.Empty;
        internal bool? IsReadOnly;
        internal bool? IsSynchronized;
        internal bool? IsGlobalCatalogReady;
        internal bool? ComputerAccountExists;
        internal string ComputerObjectGuid = String.Empty;
        internal string ComputerPwdLastSet = String.Empty;
        internal string ComputerWhenChanged = String.Empty;
        internal int SpnCollisionCount;
        internal string SpnStateFingerprint = String.Empty;
        internal string SpnStateSummary = String.Empty;
    }

    internal sealed class DcMatrixResult
    {
        internal string Domain = String.Empty;
        internal readonly List<DcMatrixEntry> Entries = new List<DcMatrixEntry>();
        internal readonly List<string> Notes = new List<string>();
    }

    internal static class DcMatrixService
    {
        private static readonly Regex SrvHost = new Regex(
            @"(?:svr hostname|service)\s*=\s*([^\s]+)",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        internal static DcMatrixResult Analyze(
            string domain,
            string fallbackDc,
            string computerName,
            string user,
            string password)
        {
            return Analyze(
                domain,
                fallbackDc,
                computerName,
                user,
                password,
                CancellationToken.None,
                null);
        }

        internal static DcMatrixResult Analyze(
            string domain,
            string fallbackDc,
            string computerName,
            string user,
            string password,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            cancellationToken.ThrowIfCancellationRequested();
            DcMatrixResult result = new DcMatrixResult();
            result.Domain = (domain ?? String.Empty).Trim();

            List<string> hosts = DiscoverDomainControllers(result.Domain);
            string fallback = DomainValidation.NormalizeDirectoryServer(fallbackDc);
            if (!String.IsNullOrWhiteSpace(fallback) && !ContainsIgnoreCase(hosts, fallback))
                hosts.Add(fallback);

            if (hosts.Count == 0)
            {
                result.Notes.Add("No domain controllers were discovered from DNS SRV records.");
                return result;
            }

            foreach (string host in hosts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (progress != null)
                    progress("DC Matrix: " + host);

                DcMatrixEntry entry = new DcMatrixEntry();
                entry.Host = host.TrimEnd('.');
                try
                {
                    System.Net.Dns.GetHostAddresses(entry.Host);
                    entry.DnsResolved = true;
                }
                catch
                {
                    entry.DnsResolved = false;
                }
                entry.Ports = ProbePorts(entry.Host);
                entry.TimeSkew = QueryTimeSkew(entry.Host, cancellationToken);
                ReadRootDse(entry, user, password);

                if (!String.IsNullOrWhiteSpace(computerName))
                {
                    AdComputerAccountInfo account = AdDirectoryService.FindComputerAccount(
                        computerName,
                        user,
                        password,
                        result.Domain,
                        entry.Host,
                        null);
                    if (account.LookupSucceeded)
                    {
                        entry.ComputerAccountExists = account.Exists;
                        if (account.Exists)
                        {
                            entry.ComputerObjectGuid = account.ObjectGuid;
                            entry.ComputerPwdLastSet = account.PwdLastSet;
                            entry.ComputerWhenChanged = account.WhenChanged;
                        }
                    }
                }

                if (entry.RootDseOk && !String.IsNullOrWhiteSpace(computerName))
                {
                    SpnCollisionResult spn = SpnCollisionAnalyzer.Analyze(
                        result.Domain,
                        entry.Host,
                        computerName,
                        user,
                        password,
                        cancellationToken);

                    entry.SpnCollisionCount = SpnCollisionAnalyzer.CountCollisions(spn);
                    entry.SpnStateFingerprint = SpnCollisionAnalyzer.BuildStateFingerprint(spn);
                    entry.SpnStateSummary = spn.Entries.Count + " expected SPNs checked; collisions=" +
                        entry.SpnCollisionCount;

                    if (entry.SpnCollisionCount > 0)
                        result.Notes.Add("SPN collision detected on " + entry.Host + "; review the per-DC SPN state before trust repair.");
                }

                result.Entries.Add(entry);
            }

            DetectInconsistency(result);

            foreach (DcMatrixEntry entry in result.Entries)
            {
                if (entry.IsReadOnly == true)
                    result.Notes.Add("RODC detected: " + entry.Host + ". Join/rejoin and account changes should use a writable DC.");
                if (entry.IsSynchronized == false)
                    result.Notes.Add("DC reports isSynchronized=FALSE: " + entry.Host + ". Investigate AD replication/initial synchronization.");
            }

            return result;
        }

        internal static string ToText(DcMatrixResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Domain Controller Matrix");
            sb.AppendLine("========================");
            sb.AppendLine("Domain: " + (String.IsNullOrWhiteSpace(result.Domain) ? "(not specified)" : result.Domain));
            sb.AppendLine();

            foreach (DcMatrixEntry e in result.Entries)
            {
                sb.AppendLine("DC: " + e.Host);
                sb.AppendLine("  DNS resolve: " + (e.DnsResolved ? "OK" : "FAILED"));
                sb.AppendLine("  Ports:       " + e.Ports);
                sb.AppendLine("  Time skew:   " + e.TimeSkew);
                sb.AppendLine("  RootDSE:     " + (e.RootDseOk ? "OK" : "FAILED"));
                if (!String.IsNullOrWhiteSpace(e.DnsHostName))
                    sb.AppendLine("  LDAP host:   " + e.DnsHostName);
                if (!String.IsNullOrWhiteSpace(e.DefaultNamingContext))
                    sb.AppendLine("  Naming ctx:  " + e.DefaultNamingContext);
                if (!String.IsNullOrWhiteSpace(e.Site))
                    sb.AppendLine("  Site:        " + e.Site);
                if (e.IsReadOnly.HasValue)
                    sb.AppendLine("  DC type:     " + (e.IsReadOnly.Value ? "RODC (read-only)" : "Writable"));
                if (e.IsSynchronized.HasValue)
                    sb.AppendLine("  Synced:      " + (e.IsSynchronized.Value ? "Yes" : "No"));
                if (e.IsGlobalCatalogReady.HasValue)
                    sb.AppendLine("  GC ready:    " + (e.IsGlobalCatalogReady.Value ? "Yes" : "No"));
                if (!String.IsNullOrWhiteSpace(e.LdapError))
                    sb.AppendLine("  LDAP error:  " + e.LdapError);

                if (e.ComputerAccountExists.HasValue)
                {
                    sb.AppendLine("  Computer:    " + (e.ComputerAccountExists.Value ? "FOUND" : "NOT FOUND"));
                    if (e.ComputerAccountExists.Value)
                    {
                        sb.AppendLine("  objectGUID:  " + First(e.ComputerObjectGuid, "(not returned)"));
                        sb.AppendLine("  pwdLastSet:  " + First(e.ComputerPwdLastSet, "(not returned)"));
                        sb.AppendLine("  whenChanged: " + First(e.ComputerWhenChanged, "(not returned)"));
                    }
                }

                if (!String.IsNullOrWhiteSpace(e.SpnStateSummary))
                    sb.AppendLine("  SPN state:   " + e.SpnStateSummary);

                sb.AppendLine();
            }

            if (result.Notes.Count > 0)
            {
                sb.AppendLine("Notes:");
                foreach (string note in result.Notes)
                    sb.AppendLine("- " + note);
            }

            return sb.ToString();
        }

        internal static List<string> DiscoverDomainControllers(string domain)
        {
            List<string> hosts = new List<string>();
            if (String.IsNullOrWhiteSpace(domain))
                return hosts;

            string output = RunProcess("nslookup.exe", "-type=SRV _ldap._tcp.dc._msdcs." + domain, 7000);
            if (String.IsNullOrWhiteSpace(output))
                return hosts;

            MatchCollection matches = SrvHost.Matches(output);
            foreach (Match match in matches)
            {
                if (match.Groups.Count < 2)
                    continue;
                string host = match.Groups[1].Value.Trim().TrimEnd('.');
                if (host.Length > 0 && !ContainsIgnoreCase(hosts, host))
                    hosts.Add(host);
            }

            return hosts;
        }

        private static void ReadRootDse(DcMatrixEntry entry, string user, string password)
        {
            try
            {
                string path = "LDAP://" + entry.Host + "/RootDSE";
                DirectoryEntry root = !String.IsNullOrWhiteSpace(user) && password != null
                    ? new DirectoryEntry(path, user, password, AuthenticationTypes.Secure)
                    : new DirectoryEntry(path);

                using (root)
                {
                    entry.DnsHostName = Convert.ToString(root.Properties["dnsHostName"].Value) ?? String.Empty;
                    entry.DefaultNamingContext = Convert.ToString(root.Properties["defaultNamingContext"].Value) ?? String.Empty;
                    entry.ConfigurationNamingContext = Convert.ToString(root.Properties["configurationNamingContext"].Value) ?? String.Empty;
                    string serverName = Convert.ToString(root.Properties["serverName"].Value) ?? String.Empty;

                    entry.IsSynchronized = ReadBoolean(root, "isSynchronized");
                    entry.IsGlobalCatalogReady = ReadBoolean(root, "isGlobalCatalogReady");
                    entry.Site = ParseSiteFromServerDn(serverName);
                    entry.RootDseOk = !String.IsNullOrWhiteSpace(entry.DefaultNamingContext);

                    if (!String.IsNullOrWhiteSpace(serverName))
                    {
                        string ntdsPath = "LDAP://" + entry.Host + "/" + serverName;
                        try
                        {
                            DirectoryEntry ntds = !String.IsNullOrWhiteSpace(user) && password != null
                                ? new DirectoryEntry(ntdsPath, user, password, AuthenticationTypes.Secure)
                                : new DirectoryEntry(ntdsPath);

                            using (ntds)
                            {
                                object rodc = ntds.Properties["msDS-isRODC"].Value;
                                if (rodc != null)
                                    entry.IsReadOnly = Convert.ToBoolean(rodc);
                            }
                        }
                        catch
                        {
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                entry.LdapError = ex.Message;
            }
        }

        private static bool? ReadBoolean(DirectoryEntry entry, string propertyName)
        {
            try
            {
                object value = entry.Properties[propertyName].Value;
                if (value == null)
                    return null;
                return Convert.ToBoolean(value);
            }
            catch
            {
                return null;
            }
        }

        private static string ParseSiteFromServerDn(string serverDn)
        {
            if (String.IsNullOrWhiteSpace(serverDn))
                return String.Empty;

            Match match = Regex.Match(
                serverDn,
                @"CN=NTDS Settings,CN=[^,]+,CN=Servers,CN=([^,]+),CN=Sites",
                RegexOptions.IgnoreCase);

            return match.Success ? match.Groups[1].Value : String.Empty;
        }

        private static string ProbePorts(string host)
        {
            int[] ports = new int[] { 53, 88, 135, 389, 445 };
            List<string> values = new List<string>();
            foreach (int port in ports)
                values.Add(port + "=" + (CanConnect(host, port, 650) ? "OK" : "FAIL"));
            return String.Join(" ", values.ToArray());
        }

        private static bool CanConnect(string host, int port, int timeoutMs)
        {
            TcpClient client = null;
            try
            {
                client = new TcpClient();
                IAsyncResult ar = client.BeginConnect(host, port, null, null);
                if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
                    return false;
                client.EndConnect(ar);
                return true;
            }
            catch { return false; }
            finally { if (client != null) client.Close(); }
        }

        private static string QueryTimeSkew(string host, CancellationToken cancellationToken)
        {
            string output = RunProcess(
                "w32tm.exe",
                "/stripchart /computer:" + host + " /dataonly /samples:1",
                7000,
                cancellationToken);
            if (String.IsNullOrWhiteSpace(output))
                return "(not available)";

            string[] lines = output.Split(new string[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = lines.Length - 1; i >= 0; i--)
            {
                string line = lines[i].Trim();
                if (line.IndexOf("s", StringComparison.OrdinalIgnoreCase) >= 0 && line.IndexOf(",", StringComparison.Ordinal) >= 0)
                    return line;
            }
            return Collapse(output, 180);
        }

        private static string RunProcess(string file, string args, int timeoutMs)
        {
            return RunProcess(file, args, timeoutMs, CancellationToken.None);
        }

        private static string RunProcess(
            string file,
            string args,
            int timeoutMs,
            CancellationToken cancellationToken)
        {
            CommandResult result = ProcessRunner.Run(file, args, timeoutMs, cancellationToken);
            if (!String.IsNullOrWhiteSpace(result.Error))
                return result.Error;
            return result.CombinedOutput;
        }

        private static void DetectInconsistency(DcMatrixResult result)
        {
            string firstGuid = null;
            string firstPwd = null;
            string firstWhenChanged = null;
            string firstSpnState = null;
            string firstSpnDc = null;
            bool sawFound = false;
            bool sawMissing = false;
            bool spnStateDiffers = false;

            foreach (DcMatrixEntry e in result.Entries)
            {
                if (!e.ComputerAccountExists.HasValue)
                    continue;

                if (e.ComputerAccountExists.Value)
                {
                    sawFound = true;
                    if (firstGuid == null)
                    {
                        firstGuid = e.ComputerObjectGuid;
                        firstPwd = e.ComputerPwdLastSet;
                        firstWhenChanged = e.ComputerWhenChanged;
                    }
                    else if ((!String.IsNullOrWhiteSpace(e.ComputerObjectGuid) &&
                              !String.Equals(firstGuid, e.ComputerObjectGuid, StringComparison.OrdinalIgnoreCase)) ||
                             (!String.IsNullOrWhiteSpace(e.ComputerPwdLastSet) &&
                              !String.Equals(firstPwd, e.ComputerPwdLastSet, StringComparison.OrdinalIgnoreCase)) ||
                             (!String.IsNullOrWhiteSpace(e.ComputerWhenChanged) &&
                              !String.Equals(firstWhenChanged, e.ComputerWhenChanged, StringComparison.OrdinalIgnoreCase)))
                    {
                        result.Notes.Add("Computer-account metadata differs between DCs; AD replication or stale state should be investigated before destructive recovery.");
                        break;
                    }
                }
                else
                {
                    sawMissing = true;
                }
            }

            if (sawFound && sawMissing)
                result.Notes.Add("The computer account is visible on some DCs but missing on others. This strongly suggests replication inconsistency or a recent delete/create operation.");

            foreach (DcMatrixEntry e in result.Entries)
            {
                if (String.IsNullOrWhiteSpace(e.SpnStateFingerprint))
                    continue;

                if (firstSpnState == null)
                {
                    firstSpnState = e.SpnStateFingerprint;
                    firstSpnDc = e.Host;
                    continue;
                }

                if (!String.Equals(firstSpnState, e.SpnStateFingerprint, StringComparison.Ordinal))
                {
                    spnStateDiffers = true;
                    result.Notes.Add(
                        "Expected SPN visibility differs between DCs (" + firstSpnDc + " vs " + e.Host +
                        "). This can indicate replication latency, stale objects, or a duplicate SPN visible only on some DCs.");
                    break;
                }
            }

            if (spnStateDiffers)
                result.Notes.Add("Cross-DC SPN state is inconsistent; avoid destructive recovery until AD replication converges.");
        }

        private static bool ContainsIgnoreCase(List<string> values, string value)
        {
            foreach (string item in values)
                if (String.Equals(item, value, StringComparison.OrdinalIgnoreCase))
                    return true;
            return false;
        }

        private static string Collapse(string value, int max)
        {
            string text = (value ?? String.Empty).Replace("\r", " ").Replace("\n", " ").Trim();
            while (text.Contains("  ")) text = text.Replace("  ", " ");
            return text.Length > max ? text.Substring(0, max) + "..." : text;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
