using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class ProtocolCheckResult
    {
        internal string Name = String.Empty;
        internal string Status = String.Empty;
        internal string Details = String.Empty;
    }

    internal sealed class ProtocolDiagnosticsResult
    {
        internal string Domain = String.Empty;
        internal string Dc = String.Empty;
        internal readonly List<ProtocolCheckResult> Checks = new List<ProtocolCheckResult>();
    }

    internal static class ProtocolDiagnosticsService
    {
        internal static ProtocolDiagnosticsResult Analyze(
            string domain,
            string dc,
            string user,
            string password)
        {
            ProtocolDiagnosticsResult result = new ProtocolDiagnosticsResult();
            result.Domain = (domain ?? String.Empty).Trim();
            result.Dc = DomainValidation.NormalizeDirectoryServer(dc);

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(result.Domain, false);
                if (discovered.Success)
                    result.Dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            TestDnsUdp(result);
            TestLdap(result, 389, false, user, password);
            TestLdap(result, 636, true, user, password);
            TestKerberos(result);
            TestRpc(result);
            TestSmb(result);

            return result;
        }

        internal static string ToText(ProtocolDiagnosticsResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("Protocol-level diagnostics");
            sb.AppendLine("==========================");
            sb.AppendLine("Domain: " + First(result.Domain, "(none)"));
            sb.AppendLine("DC:     " + First(result.Dc, "(none)"));
            sb.AppendLine();

            foreach (ProtocolCheckResult check in result.Checks)
            {
                sb.AppendLine(check.Name + ": " + check.Status);
                if (!String.IsNullOrWhiteSpace(check.Details))
                    sb.AppendLine("  " + check.Details);
            }

            return sb.ToString();
        }

        private static void TestDnsUdp(ProtocolDiagnosticsResult result)
        {
            string dnsServer = GetFirstIpv4DnsServer();
            if (String.IsNullOrWhiteSpace(dnsServer) || String.IsNullOrWhiteSpace(result.Domain))
            {
                Add(result, "DNS UDP 53", "NOT TESTED", "No IPv4 DNS server or target domain is available.");
                return;
            }

            try
            {
                string qname = "_ldap._tcp.dc._msdcs." + result.Domain.Trim('.');
                byte[] request = BuildDnsQuery(qname, 33);
                int transactionId = (request[0] << 8) | request[1];

                using (UdpClient udp = new UdpClient(AddressFamily.InterNetwork))
                {
                    udp.Client.ReceiveTimeout = 3000;
                    udp.Connect(dnsServer, 53);
                    udp.Send(request, request.Length);

                    IPEndPoint remote = new IPEndPoint(IPAddress.Any, 0);
                    byte[] response = udp.Receive(ref remote);

                    if (response == null || response.Length < 12)
                    {
                        Add(result, "DNS UDP 53", "FAILED", "DNS server returned an invalid response.");
                        return;
                    }

                    int responseId = (response[0] << 8) | response[1];
                    int flags = (response[2] << 8) | response[3];
                    int rcode = flags & 0x000F;
                    int answers = (response[6] << 8) | response[7];

                    if (responseId != transactionId)
                    {
                        Add(result, "DNS UDP 53", "FAILED", "DNS response transaction ID did not match.");
                        return;
                    }

                    if (rcode == 0)
                    {
                        Add(
                            result,
                            "DNS UDP 53",
                            answers > 0 ? "OK" : "RESPONSE / NO ANSWERS",
                            "Server " + dnsServer + " answered the AD SRV query; answer count=" + answers + ".");
                    }
                    else
                    {
                        Add(result, "DNS UDP 53", "FAILED", "DNS response RCODE=" + rcode + " from " + dnsServer + ".");
                    }
                }
            }
            catch (Exception ex)
            {
                Add(result, "DNS UDP 53", "FAILED", ex.Message);
            }
        }

        private static void TestLdap(
            ProtocolDiagnosticsResult result,
            int port,
            bool ssl,
            string user,
            string password)
        {
            string name = ssl ? "LDAPS 636 bind" : "LDAP 389 Negotiate bind";
            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                Add(result, name, "NOT TESTED", "No DC is available.");
                return;
            }

            try
            {
                LdapDirectoryIdentifier id =
                    new LdapDirectoryIdentifier(result.Dc, port, false, false);

                using (LdapConnection connection = new LdapConnection(id))
                {
                    connection.Timeout = TimeSpan.FromSeconds(6);
                    connection.AuthType = AuthType.Negotiate;
                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.SessionOptions.SecureSocketLayer = ssl;

                    if (!String.IsNullOrWhiteSpace(user) && password != null)
                        connection.Credential = new NetworkCredential(user, password);

                    connection.Bind();
                    Add(
                        result,
                        name,
                        "OK",
                        ssl
                            ? "TLS certificate validation and authenticated LDAP bind succeeded."
                            : "Authenticated LDAP Negotiate bind succeeded.");
                }
            }
            catch (Exception ex)
            {
                Add(result, name, "FAILED", Collapse(ex.Message, 260));
            }
        }

        private static void TestKerberos(ProtocolDiagnosticsResult result)
        {
            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                Add(result, "Kerberos ticket request", "NOT TESTED", "No DC is available.");
                return;
            }

            string spn = "ldap/" + result.Dc;
            CommandResult command = ProcessRunner.Run("klist.exe", "get " + spn, 10000);

            if (!String.IsNullOrWhiteSpace(command.Error))
            {
                Add(result, "Kerberos ticket request", "NOT TESTED", command.Error);
                return;
            }

            string details = Collapse(command.CombinedOutput, 360);
            Add(
                result,
                "Kerberos ticket request",
                command.ExitCode == 0 && !command.TimedOut ? "OK" : "FAILED",
                (command.TimedOut ? "Timed out. " : String.Empty) +
                "Current logon context requested " + spn + ". " + details);
        }

        private static void TestRpc(ProtocolDiagnosticsResult result)
        {
            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                Add(result, "RPC service-control test", "NOT TESTED", "No DC is available.");
                return;
            }

            CommandResult command = ProcessRunner.Run(
                "sc.exe",
                "\\" + result.Dc + " query Netlogon",
                10000);

            string text = Collapse(command.CombinedOutput, 360);
            if (command.TimedOut)
            {
                Add(result, "RPC service-control test", "FAILED", "Timed out.");
                return;
            }

            if (command.ExitCode == 0)
            {
                Add(result, "RPC service-control test", "OK", text);
                return;
            }

            if (text.IndexOf("Access is denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("FAILED 5", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add(
                    result,
                    "RPC service-control test",
                    "REACHABLE / ACCESS DENIED",
                    "RPC reached the remote Service Control Manager but the current identity was denied. " + text);
                return;
            }

            Add(result, "RPC service-control test", "FAILED", text);
        }

        private static void TestSmb(ProtocolDiagnosticsResult result)
        {
            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                Add(result, "SMB server enumeration", "NOT TESTED", "No DC is available.");
                return;
            }

            CommandResult command = ProcessRunner.Run(
                "net.exe",
                "view \\" + result.Dc,
                10000);

            string text = Collapse(command.CombinedOutput, 360);
            if (command.TimedOut)
            {
                Add(result, "SMB server enumeration", "FAILED", "Timed out.");
                return;
            }

            if (command.ExitCode == 0)
            {
                Add(result, "SMB server enumeration", "OK", text);
                return;
            }

            if (text.IndexOf("Access is denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("System error 5", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                Add(
                    result,
                    "SMB server enumeration",
                    "REACHABLE / ACCESS DENIED",
                    "SMB responded but the current identity was denied. " + text);
                return;
            }

            Add(result, "SMB server enumeration", "FAILED", text);
        }

        private static byte[] BuildDnsQuery(string name, ushort type)
        {
            List<byte> bytes = new List<byte>();
            ushort id = unchecked((ushort)Environment.TickCount);

            AddU16(bytes, id);
            AddU16(bytes, 0x0100);
            AddU16(bytes, 1);
            AddU16(bytes, 0);
            AddU16(bytes, 0);
            AddU16(bytes, 0);

            string[] labels = name.Split('.');
            foreach (string label in labels)
            {
                byte[] data = Encoding.ASCII.GetBytes(label);
                if (data.Length == 0 || data.Length > 63)
                    throw new InvalidOperationException("Invalid DNS label in query name.");
                bytes.Add((byte)data.Length);
                bytes.AddRange(data);
            }

            bytes.Add(0);
            AddU16(bytes, type);
            AddU16(bytes, 1);
            return bytes.ToArray();
        }

        private static void AddU16(List<byte> bytes, ushort value)
        {
            bytes.Add((byte)(value >> 8));
            bytes.Add((byte)(value & 0xFF));
        }

        private static string GetFirstIpv4DnsServer()
        {
            try
            {
                foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (ni.OperationalStatus != OperationalStatus.Up ||
                        ni.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    foreach (IPAddress address in ni.GetIPProperties().DnsAddresses)
                    {
                        if (address.AddressFamily == AddressFamily.InterNetwork)
                            return address.ToString();
                    }
                }
            }
            catch
            {
            }

            return String.Empty;
        }

        private static void Add(
            ProtocolDiagnosticsResult result,
            string name,
            string status,
            string details)
        {
            ProtocolCheckResult item = new ProtocolCheckResult();
            item.Name = name;
            item.Status = status;
            item.Details = details ?? String.Empty;
            result.Checks.Add(item);
        }

        private static string Collapse(string value, int max)
        {
            string text = (value ?? String.Empty).Replace("\r", " ").Replace("\n", " ").Trim();
            while (text.Contains("  "))
                text = text.Replace("  ", " ");
            return text.Length > max ? text.Substring(0, max) + "..." : text;
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
