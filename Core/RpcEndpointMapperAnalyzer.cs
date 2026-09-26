using System;
using System.Collections.Generic;
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
        internal bool TcpReachable;
        internal string Annotation = String.Empty;
    }

    internal sealed class RpcEndpointMapperResult
    {
        internal string Dc = String.Empty;
        internal bool EndpointMapperReachable;
        internal bool EnumerationSucceeded;
        internal uint EnumerationStatus;
        internal readonly List<RpcEndpointEntry> Endpoints = new List<RpcEndpointEntry>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class RpcEndpointMapperAnalyzer
    {
        private const uint RPC_C_EP_ALL_ELTS = 0;
        private const uint RPC_S_OK = 0;
        private const uint RPC_X_NO_MORE_ENTRIES = 1772;

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
                endpoint.TcpReachable = CanConnect(result.Dc, endpoint.Port, 1500, cancellationToken);

                if (tested.Count >= 24)
                    break;
            }

            int dynamicCount = 0;
            int blockedCount = 0;
            foreach (RpcEndpointEntry endpoint in result.Endpoints)
            {
                if (endpoint.Port <= 0 || endpoint.Port == 135)
                    continue;
                dynamicCount++;
                if (!endpoint.TcpReachable)
                    blockedCount++;
            }

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

            foreach (RpcEndpointEntry endpoint in result.Endpoints)
            {
                if (endpoint.Port <= 0)
                    continue;

                sb.AppendLine();
                sb.AppendLine(
                    endpoint.InterfaceId + " v" + endpoint.VersionMajor + "." + endpoint.VersionMinor +
                    " | TCP " + endpoint.Port + " | " +
                    (endpoint.Port == 135 ? "Endpoint Mapper" : (endpoint.TcpReachable ? "OK" : "FAILED")));
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
                                if (port > 0)
                                {
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

        private static void Report(Action<string> progress, string text)
        {
            if (progress != null)
                progress(text);
        }

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }

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
