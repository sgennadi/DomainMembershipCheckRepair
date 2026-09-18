using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal static class NativeMethods
    {
        internal const int NERR_Success = 0;
        internal const int NERR_UserExists = 2224;
        internal const int NERR_AccountReuseBlockedByPolicy = 2732;
        internal const int ERROR_ACCESS_DENIED = 5;
        internal const int ERROR_LOGON_FAILURE = 1326;
        internal const int ERROR_NO_SUCH_DOMAIN = 1355;
        internal const int ERROR_NO_LOGON_SERVERS = 1311;

        internal const uint NETSETUP_JOIN_DOMAIN = 0x00000001;
        internal const uint NETSETUP_ACCT_CREATE = 0x00000002;
        internal const uint NETSETUP_DOMAIN_JOIN_IF_JOINED = 0x00000020;
        internal const uint NETSETUP_JOIN_WITH_NEW_NAME = 0x00000400;

        internal const uint NETLOGON_CONTROL_REDISCOVER = 5;
        internal const uint NETLOGON_CONTROL_CHANGE_PASSWORD = 9;
        internal const uint NETLOGON_CONTROL_TC_VERIFY = 10;

        private const uint DS_FORCE_REDISCOVERY = 0x00000001;
        private const uint DS_DIRECTORY_SERVICE_REQUIRED = 0x00000010;
        private const uint DS_IP_REQUIRED = 0x00000200;
        private const uint DS_RETURN_DNS_NAME = 0x40000000;

        internal static JoinInformation GetJoinInformation()
        {
            IntPtr buffer = IntPtr.Zero;
            NetJoinStatus status;
            int result = NetGetJoinInformation(null, out buffer, out status);
            string name = String.Empty;

            try
            {
                if (buffer != IntPtr.Zero)
                    name = Marshal.PtrToStringUni(buffer) ?? String.Empty;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    NetApiBufferFree(buffer);
            }

            return new JoinInformation
            {
                StatusCode = result,
                Name = name,
                Status = status
            };
        }

        internal static DomainDiscoveryResult DiscoverDomain(string hint, bool forceRediscovery)
        {
            IntPtr infoPtr = IntPtr.Zero;
            uint flags = DS_DIRECTORY_SERVICE_REQUIRED | DS_IP_REQUIRED | DS_RETURN_DNS_NAME;
            if (forceRediscovery)
                flags |= DS_FORCE_REDISCOVERY;

            int status = DsGetDcName(null, String.IsNullOrWhiteSpace(hint) ? null : hint.Trim(), IntPtr.Zero, null, flags, out infoPtr);
            DomainDiscoveryResult result = new DomainDiscoveryResult
            {
                Success = false,
                StatusCode = status,
                InputName = hint
            };

            try
            {
                if (status != NERR_Success || infoPtr == IntPtr.Zero)
                    return result;

                DOMAIN_CONTROLLER_INFO info = (DOMAIN_CONTROLLER_INFO)Marshal.PtrToStructure(infoPtr, typeof(DOMAIN_CONTROLLER_INFO));
                result.Success = true;
                result.DnsDomainName = PtrToString(info.DomainName);
                result.DomainControllerName = PtrToString(info.DomainControllerName);
                result.ForestName = PtrToString(info.DnsForestName);
                return result;
            }
            finally
            {
                if (infoPtr != IntPtr.Zero)
                    NetApiBufferFree(infoPtr);
            }
        }

        internal static string GetPhysicalDnsDomain()
        {
            uint size = 256;
            StringBuilder buffer = new StringBuilder((int)size);
            if (GetComputerNameEx(ComputerNameFormat.ComputerNamePhysicalDnsDomain, buffer, ref size))
                return buffer.ToString().Trim();

            if (Marshal.GetLastWin32Error() == 234 && size > 0)
            {
                buffer = new StringBuilder((int)size + 1);
                uint retrySize = (uint)buffer.Capacity;
                if (GetComputerNameEx(ComputerNameFormat.ComputerNamePhysicalDnsDomain, buffer, ref retrySize))
                    return buffer.ToString().Trim();
            }

            return String.Empty;
        }

        internal static TrustCheckResult VerifySecureChannel(string domain)
        {
            if (String.IsNullOrWhiteSpace(domain))
                return new TrustCheckResult(false, ERROR_NO_SUCH_DOMAIN, null);

            IntPtr buffer = IntPtr.Zero;
            IntPtr domainString = IntPtr.Zero;
            IntPtr data = IntPtr.Zero;

            try
            {
                domainString = Marshal.StringToHGlobalUni(domain);
                data = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(data, domainString);

                int apiStatus = I_NetLogonControl2(null, NETLOGON_CONTROL_TC_VERIFY, 2, data, out buffer);
                if (apiStatus != NERR_Success)
                    return new TrustCheckResult(false, apiStatus, null);

                if (buffer == IntPtr.Zero)
                    return new TrustCheckResult(false, 1, null);

                NETLOGON_INFO_2 info = (NETLOGON_INFO_2)Marshal.PtrToStructure(buffer, typeof(NETLOGON_INFO_2));
                string dc = info.netlog2_trusted_dc_name == IntPtr.Zero ? null : Marshal.PtrToStringUni(info.netlog2_trusted_dc_name);
                int tcStatus = unchecked((int)info.netlog2_tc_connection_status);
                return new TrustCheckResult(tcStatus == NERR_Success, tcStatus, dc);
            }
            catch (EntryPointNotFoundException)
            {
                return new TrustCheckResult(false, 127, null);
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    NetApiBufferFree(buffer);
                if (data != IntPtr.Zero)
                    Marshal.FreeHGlobal(data);
                if (domainString != IntPtr.Zero)
                    Marshal.FreeHGlobal(domainString);
            }
        }

        internal static int NetlogonControl(uint functionCode, uint queryLevel, string domain)
        {
            IntPtr buffer = IntPtr.Zero;
            IntPtr domainString = IntPtr.Zero;
            IntPtr data = IntPtr.Zero;

            try
            {
                domainString = Marshal.StringToHGlobalUni(domain);
                data = Marshal.AllocHGlobal(IntPtr.Size);
                Marshal.WriteIntPtr(data, domainString);
                return I_NetLogonControl2(null, functionCode, queryLevel, data, out buffer);
            }
            catch (EntryPointNotFoundException)
            {
                return 127;
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    NetApiBufferFree(buffer);
                if (data != IntPtr.Zero)
                    Marshal.FreeHGlobal(data);
                if (domainString != IntPtr.Zero)
                    Marshal.FreeHGlobal(domainString);
            }
        }

        internal static int JoinDomain(string domain, string account, string password, bool joinWithNewName)
        {
            uint flags = NETSETUP_JOIN_DOMAIN | NETSETUP_ACCT_CREATE | NETSETUP_DOMAIN_JOIN_IF_JOINED;
            if (joinWithNewName)
                flags |= NETSETUP_JOIN_WITH_NEW_NAME;

            return NetJoinDomain(null, domain, null, account, password, flags);
        }

        internal static bool SetPendingComputerName(string newName, out int errorCode)
        {
            bool ok = SetComputerNameEx(ComputerNameFormat.ComputerNamePhysicalDnsHostname, newName);
            errorCode = ok ? 0 : Marshal.GetLastWin32Error();
            return ok;
        }

        internal static string FormatError(int code)
        {
            if (code == 0)
                return "0 - Success";
            if (code == NERR_UserExists)
                return "2224 (0x8B0) - NERR_UserExists: the account already exists";
            if (code == NERR_AccountReuseBlockedByPolicy)
                return "2732 (0xAAC) - NERR_AccountReuseBlockedByPolicy: an account with the same name exists and reuse was blocked by security policy";
            if (code == ERROR_ACCESS_DENIED)
                return "5 - Access denied";
            if (code == ERROR_LOGON_FAILURE)
                return "1326 - Logon failure: unknown user name or bad password";
            if (code == ERROR_NO_SUCH_DOMAIN)
                return "1355 - The specified domain either does not exist or could not be contacted";
            if (code == ERROR_NO_LOGON_SERVERS)
                return "1311 - There are currently no logon servers available";

            try
            {
                return code + " (0x" + code.ToString("X") + ") - " + new Win32Exception(code).Message;
            }
            catch
            {
                return code + " (0x" + code.ToString("X") + ")";
            }
        }

        private static string PtrToString(IntPtr value)
        {
            return value == IntPtr.Zero ? String.Empty : (Marshal.PtrToStringUni(value) ?? String.Empty);
        }

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetGetJoinInformation(string lpServer, out IntPtr lpNameBuffer, out NetJoinStatus bufferType);

        [DllImport("Netapi32.dll")]
        internal static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int NetJoinDomain(string lpServer, string lpDomain, string lpMachineAccountOU, string lpAccount, string lpPassword, uint fJoinOptions);

        [DllImport("Netapi32.dll", CharSet = CharSet.Unicode)]
        private static extern int DsGetDcName(string ComputerName, string DomainName, IntPtr DomainGuid, string SiteName, uint Flags, out IntPtr DomainControllerInfo);

        [DllImport("Netapi32.dll", EntryPoint = "I_NetLogonControl2", CharSet = CharSet.Unicode)]
        private static extern int I_NetLogonControl2(string serverName, uint functionCode, uint queryLevel, IntPtr data, out IntPtr buffer);

        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetComputerNameEx(ComputerNameFormat nameType, string lpBuffer);

        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetComputerNameEx(ComputerNameFormat nameType, StringBuilder lpBuffer, ref uint nSize);

        [StructLayout(LayoutKind.Sequential)]
        private struct NETLOGON_INFO_2
        {
            public uint netlog2_flags;
            public uint netlog2_pdc_connection_status;
            public IntPtr netlog2_trusted_dc_name;
            public uint netlog2_tc_connection_status;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct DOMAIN_CONTROLLER_INFO
        {
            public IntPtr DomainControllerName;
            public IntPtr DomainControllerAddress;
            public uint DomainControllerAddressType;
            public Guid DomainGuid;
            public IntPtr DomainName;
            public IntPtr DnsForestName;
            public uint Flags;
            public IntPtr DcSiteName;
            public IntPtr ClientSiteName;
        }
    }
}
