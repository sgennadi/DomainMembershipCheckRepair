using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal sealed class RpcEndpointEntry
    {
        internal string InterfaceId = String.Empty;
        internal int VersionMajor;
        internal int VersionMinor;
        internal string Binding = String.Empty;
        internal int Port;
        internal bool TcpTested;
        internal bool TcpReachable;
        internal string Annotation = String.Empty;
    }

    internal sealed class RpcInterfaceProbe
    {
        internal string Name = String.Empty;
        internal string InterfaceId = String.Empty;
        internal bool Registered;
        internal readonly List<string> Bindings = new List<string>();
        internal string FunctionalStatus = "NOT TESTED";
        internal string FunctionalDetails = String.Empty;
    }

    internal sealed class RpcEndpointMapperResult
    {
        internal string Dc = String.Empty;
        internal bool EndpointMapperReachable;
        internal bool EnumerationSucceeded;
        internal uint EnumerationStatus;
        internal readonly List<RpcEndpointEntry> Endpoints = new List<RpcEndpointEntry>();
        internal readonly List<RpcInterfaceProbe> InterfaceProbes = new List<RpcInterfaceProbe>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class RpcEndpointMapperAnalyzer
    {
        private const uint RPC_C_EP_ALL_ELTS = 0;
        private const uint RPC_S_OK = 0;
        private const uint RPC_X_NO_MORE_ENTRIES = 1772;
        private const uint POLICY_VIEW_LOCAL_INFORMATION = 0x00000001;
        private const int FILTER_NORMAL_ACCOUNT = 0x0002;
        private const int ERROR_MORE_DATA = 234;

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_UNICODE_STRING
        {
            internal ushort Length;
            internal ushort MaximumLength;
            internal IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LSA_OBJECT_ATTRIBUTES
        {
            internal uint Length;
            internal IntPtr RootDirectory;
            internal IntPtr ObjectName;
            internal uint Attributes;
            internal IntPtr SecurityDescriptor;
            internal IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_IF_ID
        {
            internal Guid Uuid;
            internal ushort VersMajor;
            internal ushort VersMinor;
        }

        internal static RpcEndpointMapperResult Analyze(
            string domain,
            string dc,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            return Analyze(domain, dc, String.Empty, null, cancellationToken, progress);
        }

        internal static RpcEndpointMapperResult Analyze(
            string domain,
            string dc,
            string user,
            string password,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            RpcEndpointMapperResult result = new RpcEndpointMapperResult();
            result.Dc = DomainValidation.NormalizeDirectoryServer(dc);

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(domain, false);
                if (discovered.Success)
                    result.Dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                result.Findings.Add("CHECK: No DC is available for RPC Endpoint Mapper testing.");
                return result;
            }

            Report(progress, "RPC: probing Endpoint Mapper TCP 135");
            result.EndpointMapperReachable = CanConnect(result.Dc, 135, 1500, cancellationToken);
            if (!result.EndpointMapperReachable)
            {
                result.Findings.Add("HIGH: RPC Endpoint Mapper TCP 135 is not reachable on " + result.Dc + ".");
                return result;
            }

            Report(progress, "RPC: enumerating dynamic endpoints");
            Enumerate(result, cancellationToken);

            if (!result.EnumerationSucceeded)
            {
                result.Findings.Add(
                    "CHECK: RPC Endpoint Mapper enumeration did not complete (status " +
                    result.EnumerationStatus + "). TCP 135 is reachable.");
                return result;
            }

            HashSet<int> tested = new HashSet<int>();
            foreach (RpcEndpointEntry endpoint in result.Endpoints)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (endpoint.Port <= 0 || endpoint.Port == 135 || tested.Contains(endpoint.Port))
                    continue;

                tested.Add(endpoint.Port);
                Report(progress, "RPC: testing dynamic TCP " + endpoint.Port);
                endpoint.TcpTested = true;
                endpoint.TcpReachable = CanConnect(result.Dc, endpoint.Port, 1500, cancellationToken);

                if (tested.Count >= 24)
                    break;
            }

            int dynamicCount = 0;
            int blockedCount = 0;
            foreach (RpcEndpointEntry endpoint in result.Endpoints)
            {
                if (endpoint.Port <= 0 || endpoint.Port == 135 || !endpoint.TcpTested)
                    continue;
                dynamicCount++;
                if (!endpoint.TcpReachable)
                    blockedCount++;
            }

            BuildKnownInterfaceProbes(result);

            Report(progress, "RPC: functional Netlogon probe");
            RunNetlogonProbe(result, domain, user, password, cancellationToken);

            Report(progress, "RPC: functional LSARPC probe");
            RunLsaProbe(result);

            Report(progress, "RPC: functional SAMR probe");
            RunSamrProbe(result);

            Report(progress, "RPC: functional DRSUAPI probe");
            RunDrsuapiProbe(result, user, password, cancellationToken);

            if (dynamicCount == 0)
            {
                result.Findings.Add("CHECK: No ncacn_ip_tcp dynamic RPC endpoints were returned by the endpoint mapper.");
            }
            else if (blockedCount > 0)
            {
                result.Findings.Add(
                    "HIGH: Endpoint Mapper is reachable, but " + blockedCount +
                    " enumerated dynamic RPC endpoint(s) did not accept TCP connections.");
            }
            else
            {
                result.Findings.Add(
                    "INFO: Endpoint Mapper and enumerated dynamic RPC TCP endpoints are reachable.");
            }

            foreach (RpcInterfaceProbe probe in result.InterfaceProbes)
            {
                if (probe.FunctionalStatus.StartsWith("FAILED", StringComparison.OrdinalIgnoreCase))
                {
                    result.Findings.Add(
                        "HIGH: The functional RPC probe failed for " + probe.Name +
                        " even though Endpoint Mapper was reachable.");
                }
                else if (probe.FunctionalStatus.IndexOf("ACCESS DENIED", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    result.Findings.Add(
                        "INFO: The " + probe.Name +
                        " RPC interface is reachable but the current security context was denied the requested read operation.");
                }
            }

            return result;
        }

        internal static int ExtractTcpPort(string binding)
        {
            if (String.IsNullOrWhiteSpace(binding) ||
                binding.IndexOf("ncacn_ip_tcp:", StringComparison.OrdinalIgnoreCase) < 0)
                return 0;

            int open = binding.LastIndexOf('[');
            int close = binding.LastIndexOf(']');
            if (open < 0 || close <= open + 1)
                return 0;

            int port;
            return Int32.TryParse(binding.Substring(open + 1, close - open - 1), out port)
                ? port
                : 0;
        }

        internal static string ToText(RpcEndpointMapperResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("RPC Endpoint Mapper Analyzer");
            sb.AppendLine("============================");
            sb.AppendLine("DC:                    " + First(result.Dc, "(none)"));
            sb.AppendLine("TCP 135:               " + (result.EndpointMapperReachable ? "OK" : "FAILED"));
            sb.AppendLine("Endpoint enumeration:  " + (result.EnumerationSucceeded ? "OK" : "FAILED"));

            if (result.InterfaceProbes.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Known AD RPC interfaces");
                sb.AppendLine("-----------------------");
                foreach (RpcInterfaceProbe probe in result.InterfaceProbes)
                {
                    sb.AppendLine(
                        probe.Name + " | " + probe.InterfaceId + " | " +
                        (probe.Registered ? "REGISTERED" : "NOT SEEN") + " | " +
                        probe.FunctionalStatus);
                    foreach (string binding in probe.Bindings)
                        sb.AppendLine("  Binding: " + binding);
                    if (!String.IsNullOrWhiteSpace(probe.FunctionalDetails))
                        sb.AppendLine("  Probe:   " + probe.FunctionalDetails);
                }
            }

            foreach (RpcEndpointEntry endpoint in result.Endpoints)
            {
                if (endpoint.Port <= 0)
                    continue;

                sb.AppendLine();
                sb.AppendLine(
                    endpoint.InterfaceId + " v" + endpoint.VersionMajor + "." + endpoint.VersionMinor +
                    " | TCP " + endpoint.Port + " | " +
                    (endpoint.Port == 135
                        ? "Endpoint Mapper"
                        : (!endpoint.TcpTested ? "NOT TESTED" : (endpoint.TcpReachable ? "OK" : "FAILED"))));
                sb.AppendLine("  " + endpoint.Binding);
                if (!String.IsNullOrWhiteSpace(endpoint.Annotation))
                    sb.AppendLine("  " + endpoint.Annotation);
            }

            if (result.Findings.Count > 0)
            {
                sb.AppendLine();
                sb.AppendLine("Findings:");
                foreach (string finding in result.Findings)
                    sb.AppendLine("- " + finding);
            }

            return sb.ToString();
        }

        private static void Enumerate(
            RpcEndpointMapperResult result,
            CancellationToken cancellationToken)
        {
            IntPtr stringBinding = IntPtr.Zero;
            IntPtr epBinding = IntPtr.Zero;
            IntPtr inquiry = IntPtr.Zero;

            try
            {
                uint status = RpcStringBindingComposeW(
                    null,
                    "ncacn_ip_tcp",
                    result.Dc,
                    "135",
                    null,
                    out stringBinding);
                if (status != RPC_S_OK)
                {
                    result.EnumerationStatus = status;
                    return;
                }

                status = RpcBindingFromStringBindingW(stringBinding, out epBinding);
                if (status != RPC_S_OK)
                {
                    result.EnumerationStatus = status;
                    return;
                }

                status = RpcMgmtEpEltInqBegin(
                    epBinding,
                    RPC_C_EP_ALL_ELTS,
                    IntPtr.Zero,
                    0,
                    IntPtr.Zero,
                    out inquiry);
                if (status != RPC_S_OK)
                {
                    result.EnumerationStatus = status;
                    return;
                }

                int count = 0;
                while (count < 256)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    RPC_IF_ID ifId;
                    IntPtr binding = IntPtr.Zero;
                    Guid objectUuid;
                    IntPtr annotation = IntPtr.Zero;

                    status = RpcMgmtEpEltInqNextW(
                        inquiry,
                        out ifId,
                        out binding,
                        out objectUuid,
                        out annotation);

                    if (status == RPC_X_NO_MORE_ENTRIES)
                    {
                        result.EnumerationSucceeded = true;
                        result.EnumerationStatus = RPC_S_OK;
                        break;
                    }

                    if (status != RPC_S_OK)
                    {
                        result.EnumerationStatus = status;
                        break;
                    }

                    try
                    {
                        IntPtr bindingText = IntPtr.Zero;
                        uint textStatus = RpcBindingToStringBindingW(binding, out bindingText);
                        try
                        {
                            if (textStatus == RPC_S_OK && bindingText != IntPtr.Zero)
                            {
                                string text = Marshal.PtrToStringUni(bindingText) ?? String.Empty;
                                int port = ExtractTcpPort(text);
                                RpcEndpointEntry entry = new RpcEndpointEntry();
                                entry.InterfaceId = ifId.Uuid.ToString();
                                entry.VersionMajor = ifId.VersMajor;
                                entry.VersionMinor = ifId.VersMinor;
                                entry.Binding = text;
                                entry.Port = port;
                                entry.Annotation = annotation == IntPtr.Zero
                                    ? String.Empty
                                    : (Marshal.PtrToStringUni(annotation) ?? String.Empty);
                                result.Endpoints.Add(entry);
                            }
                        }
                        finally
                        {
                            if (bindingText != IntPtr.Zero)
                                RpcStringFreeW(ref bindingText);
                        }
                    }
                    finally
                    {
                        if (annotation != IntPtr.Zero)
                            RpcStringFreeW(ref annotation);
                        if (binding != IntPtr.Zero)
                            RpcBindingFree(ref binding);
                    }

                    count++;
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                result.EnumerationStatus = 1;
            }
            finally
            {
                if (inquiry != IntPtr.Zero)
                    RpcMgmtEpEltInqDone(ref inquiry);
                if (epBinding != IntPtr.Zero)
                    RpcBindingFree(ref epBinding);
                if (stringBinding != IntPtr.Zero)
                    RpcStringFreeW(ref stringBinding);
            }
        }

        private static bool CanConnect(
            string host,
            int port,
            int timeoutMs,
            CancellationToken cancellationToken)
        {
            TcpClient client = null;
            try
            {
                client = new TcpClient();
                IAsyncResult ar = client.BeginConnect(host, port, null, null);
                int elapsed = 0;
                while (elapsed < timeoutMs)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (ar.AsyncWaitHandle.WaitOne(100))
                    {
                        client.EndConnect(ar);
                        return true;
                    }
                    elapsed += 100;
                }
                return false;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                return false;
            }
            finally
            {
                if (client != null)
                    client.Close();
            }
        }

        internal static string DescribeKnownInterface(string interfaceId)
        {
            string id = (interfaceId ?? String.Empty).Trim();
            if (String.Equals(id, "12345678-1234-abcd-ef00-01234567cffb", StringComparison.OrdinalIgnoreCase))
                return "Netlogon (MS-NRPC)";
            if (String.Equals(id, "12345778-1234-abcd-ef00-0123456789ab", StringComparison.OrdinalIgnoreCase))
                return "LSA Policy (MS-LSAD)";
            if (String.Equals(id, "12345778-1234-abcd-ef00-0123456789ac", StringComparison.OrdinalIgnoreCase))
                return "SAMR (MS-SAMR)";
            if (String.Equals(id, "e3514235-4b06-11d1-ab04-00c04fc2dcd2", StringComparison.OrdinalIgnoreCase))
                return "Directory Replication Service (MS-DRSR)";
            return String.Empty;
        }

        private static void BuildKnownInterfaceProbes(RpcEndpointMapperResult result)
        {
            string[] ids = new string[]
            {
                "12345678-1234-abcd-ef00-01234567cffb",
                "12345778-1234-abcd-ef00-0123456789ab",
                "12345778-1234-abcd-ef00-0123456789ac",
                "e3514235-4b06-11d1-ab04-00c04fc2dcd2"
            };

            foreach (string id in ids)
            {
                RpcInterfaceProbe probe = new RpcInterfaceProbe();
                probe.InterfaceId = id;
                probe.Name = DescribeKnownInterface(id);

                foreach (RpcEndpointEntry endpoint in result.Endpoints)
                {
                    if (!String.Equals(endpoint.InterfaceId, id, StringComparison.OrdinalIgnoreCase))
                        continue;

                    probe.Registered = true;
                    if (!String.IsNullOrWhiteSpace(endpoint.Binding) && !probe.Bindings.Contains(endpoint.Binding))
                        probe.Bindings.Add(endpoint.Binding);
                }

                result.InterfaceProbes.Add(probe);

                if (!probe.Registered)
                {
                    result.Findings.Add(
                        "CHECK: Endpoint Mapper did not expose the expected " +
                        probe.Name + " interface UUID " + id + ".");
                }
            }
        }

        private static RpcInterfaceProbe FindProbe(RpcEndpointMapperResult result, string id)
        {
            foreach (RpcInterfaceProbe probe in result.InterfaceProbes)
            {
                if (String.Equals(probe.InterfaceId, id, StringComparison.OrdinalIgnoreCase))
                    return probe;
            }
            return null;
        }

        private static void RunNetlogonProbe(
            RpcEndpointMapperResult result,
            string domain,
            string user,
            string password,
            CancellationToken cancellationToken)
        {
            RpcInterfaceProbe probe = FindProbe(result, "12345678-1234-abcd-ef00-01234567cffb");
            if (probe == null)
                return;

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                probe.FunctionalStatus = "NOT TESTED";
                probe.FunctionalDetails = "No DC is available.";
                return;
            }

            CommandResult command = NetworkCredentialProcessRunner.Run(
                "nltest.exe",
                "/server:" + result.Dc + " /query",
                10000,
                user,
                password,
                cancellationToken);

            SetCommandProbeResult(probe, command);
        }

        private static void RunDrsuapiProbe(
            RpcEndpointMapperResult result,
            string user,
            string password,
            CancellationToken cancellationToken)
        {
            RpcInterfaceProbe probe = FindProbe(result, "e3514235-4b06-11d1-ab04-00c04fc2dcd2");
            if (probe == null)
                return;

            string repadmin = Path.Combine(Environment.SystemDirectory, "repadmin.exe");
            if (!File.Exists(repadmin))
            {
                probe.FunctionalStatus = probe.Registered ? "REGISTERED / TOOL UNAVAILABLE" : "NOT TESTED";
                probe.FunctionalDetails = "repadmin.exe is not installed; endpoint registration is still reported.";
                return;
            }

            CommandResult command = NetworkCredentialProcessRunner.Run(
                repadmin,
                "/showrepl \"" + result.Dc.Replace("\"", "\\\"") + "\" /errorsonly",
                20000,
                user,
                password,
                cancellationToken);

            SetCommandProbeResult(probe, command);
        }

        private static void SetCommandProbeResult(RpcInterfaceProbe probe, CommandResult command)
        {
            if (command == null)
            {
                probe.FunctionalStatus = "NOT TESTED";
                return;
            }

            if (command.Cancelled)
                throw new OperationCanceledException();

            if (command.TimedOut)
            {
                probe.FunctionalStatus = "FAILED / TIMEOUT";
                probe.FunctionalDetails = Collapse(command.CombinedOutput, 500);
                return;
            }

            string text = (command.CombinedOutput ?? String.Empty) + " " + (command.Error ?? String.Empty);
            if (command.ExitCode == 0 && String.IsNullOrWhiteSpace(command.Error))
                probe.FunctionalStatus = "OK";
            else if (text.IndexOf("access denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     text.IndexOf("access is denied", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     text.IndexOf("8453", StringComparison.OrdinalIgnoreCase) >= 0)
                probe.FunctionalStatus = "REACHABLE / ACCESS DENIED";
            else
                probe.FunctionalStatus = "FAILED";

            probe.FunctionalDetails = Collapse(text, 500);
        }

        private static void RunLsaProbe(RpcEndpointMapperResult result)
        {
            RpcInterfaceProbe probe = FindProbe(result, "12345778-1234-abcd-ef00-0123456789ab");
            if (probe == null)
                return;

            IntPtr nameBuffer = IntPtr.Zero;
            IntPtr policyHandle = IntPtr.Zero;

            try
            {
                string server = @"\\" + result.Dc;
                nameBuffer = Marshal.StringToHGlobalUni(server);

                LSA_UNICODE_STRING systemName = new LSA_UNICODE_STRING();
                systemName.Buffer = nameBuffer;
                systemName.Length = (ushort)(server.Length * 2);
                systemName.MaximumLength = (ushort)((server.Length + 1) * 2);

                LSA_OBJECT_ATTRIBUTES attributes = new LSA_OBJECT_ATTRIBUTES();
                attributes.Length = (uint)Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));

                uint status = LsaOpenPolicy(
                    ref systemName,
                    ref attributes,
                    POLICY_VIEW_LOCAL_INFORMATION,
                    out policyHandle);

                uint error = LsaNtStatusToWinError(status);
                if (status == 0)
                {
                    probe.FunctionalStatus = "OK";
                    probe.FunctionalDetails = "Remote LsaOpenPolicy(POLICY_VIEW_LOCAL_INFORMATION) succeeded.";
                }
                else if (error == 5)
                {
                    probe.FunctionalStatus = "REACHABLE / ACCESS DENIED";
                    probe.FunctionalDetails = "Remote LSARPC answered but denied POLICY_VIEW_LOCAL_INFORMATION.";
                }
                else
                {
                    probe.FunctionalStatus = "FAILED";
                    probe.FunctionalDetails = error + " - " + new Win32Exception((int)error).Message;
                }
            }
            catch (Exception ex)
            {
                probe.FunctionalStatus = "FAILED";
                probe.FunctionalDetails = ex.Message;
            }
            finally
            {
                if (policyHandle != IntPtr.Zero)
                    LsaClose(policyHandle);
                if (nameBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(nameBuffer);
            }
        }

        private static void RunSamrProbe(RpcEndpointMapperResult result)
        {
            RpcInterfaceProbe probe = FindProbe(result, "12345778-1234-abcd-ef00-0123456789ac");
            if (probe == null)
                return;

            IntPtr buffer = IntPtr.Zero;
            int resume = 0;
            try
            {
                int entries;
                int total;
                int status = NetUserEnum(
                    @"\\" + result.Dc,
                    0,
                    FILTER_NORMAL_ACCOUNT,
                    out buffer,
                    4096,
                    out entries,
                    out total,
                    ref resume);

                if (status == 0 || status == ERROR_MORE_DATA)
                {
                    probe.FunctionalStatus = "OK";
                    probe.FunctionalDetails =
                        "Remote NetUserEnum succeeded (" + entries + " entry/entries returned; total=" + total + ").";
                }
                else if (status == 5)
                {
                    probe.FunctionalStatus = "REACHABLE / ACCESS DENIED";
                    probe.FunctionalDetails = "Remote SAM account enumeration reached the server but was denied.";
                }
                else
                {
                    probe.FunctionalStatus = "FAILED";
                    probe.FunctionalDetails = status + " - " + new Win32Exception(status).Message;
                }
            }
            catch (Exception ex)
            {
                probe.FunctionalStatus = "FAILED";
                probe.FunctionalDetails = ex.Message;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    NetApiBufferFree(buffer);
            }
        }

        private static string Collapse(string value, int max)
        {
            string text = (value ?? String.Empty).Replace("\r", " ").Replace("\n", " ").Trim();
            while (text.Contains("  "))
                text = text.Replace("  ", " ");
            if (text.Length > max)
                text = text.Substring(0, max) + "...";
            return text;
        }

        private static void Report(Action<string> progress, string text)
        {
            if (progress != null)
                progress(text);
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }

        [DllImport("advapi32.dll")]
        private static extern uint LsaOpenPolicy(
            ref LSA_UNICODE_STRING SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            uint DesiredAccess,
            out IntPtr PolicyHandle);

        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint Status);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int NetUserEnum(
            string servername,
            int level,
            int filter,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);

        [DllImport("Netapi32.dll")]
        private static extern int NetApiBufferFree(IntPtr Buffer);

        [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
        private static extern uint RpcStringBindingComposeW(
            string ObjUuid,
            string ProtSeq,
            string NetworkAddr,
            string Endpoint,
            string Options,
            out IntPtr StringBinding);

        [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
        private static extern uint RpcBindingFromStringBindingW(
            IntPtr StringBinding,
            out IntPtr Binding);

        [DllImport("Rpcrt4.dll")]
        private static extern uint RpcMgmtEpEltInqBegin(
            IntPtr EpBinding,
            uint InquiryType,
            IntPtr IfId,
            uint VersOption,
            IntPtr ObjectUuid,
            out IntPtr InquiryContext);

        [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
        private static extern uint RpcMgmtEpEltInqNextW(
            IntPtr InquiryContext,
            out RPC_IF_ID IfId,
            out IntPtr Binding,
            out Guid ObjectUuid,
            out IntPtr Annotation);

        [DllImport("Rpcrt4.dll")]
        private static extern uint RpcMgmtEpEltInqDone(ref IntPtr InquiryContext);

        [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
        private static extern uint RpcBindingToStringBindingW(
            IntPtr Binding,
            out IntPtr StringBinding);

        [DllImport("Rpcrt4.dll")]
        private static extern uint RpcBindingFree(ref IntPtr Binding);

        [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
        private static extern uint RpcStringFreeW(ref IntPtr String);
    }
}
