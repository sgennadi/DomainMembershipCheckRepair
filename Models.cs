namespace DomainMembershipCheckRepair
{
    internal enum NetJoinStatus
    {
        NetSetupUnknownStatus = 0,
        NetSetupUnjoined = 1,
        NetSetupWorkgroupName = 2,
        NetSetupDomainName = 3
    }

    internal enum ComputerNameFormat
    {
        ComputerNameNetBIOS = 0,
        ComputerNameDnsHostname = 1,
        ComputerNameDnsDomain = 2,
        ComputerNameDnsFullyQualified = 3,
        ComputerNamePhysicalNetBIOS = 4,
        ComputerNamePhysicalDnsHostname = 5,
        ComputerNamePhysicalDnsDomain = 6,
        ComputerNamePhysicalDnsFullyQualified = 7,
        ComputerNameMax = 8
    }

    internal sealed class JoinInformation
    {
        public int StatusCode { get; set; }
        public string Name { get; set; }
        public NetJoinStatus Status { get; set; }
    }

    internal sealed class DomainDiscoveryResult
    {
        public bool Success { get; set; }
        public int StatusCode { get; set; }
        public string InputName { get; set; }
        public string DnsDomainName { get; set; }
        public string DomainControllerName { get; set; }
        public string ForestName { get; set; }
    }

    internal sealed class TrustCheckResult
    {
        public bool Healthy { get; private set; }
        public int StatusCode { get; private set; }
        public string TrustedDc { get; private set; }

        public TrustCheckResult(bool healthy, int statusCode, string trustedDc)
        {
            Healthy = healthy;
            StatusCode = statusCode;
            TrustedDc = trustedDc;
        }
    }

    internal sealed class AdComputerAccountInfo
    {
        public bool LookupSucceeded { get; set; }
        public bool Exists { get; set; }
        public string DistinguishedName { get; set; }
        public string LdapPath { get; set; }
        public string DnsHostName { get; set; }
        public string OperatingSystem { get; set; }
        public string Description { get; set; }
        public string ObjectGuid { get; set; }
        public string WhenCreated { get; set; }
        public string WhenChanged { get; set; }
        public bool? Enabled { get; set; }
        public string SamAccountName { get; set; }
        public int? UserAccountControl { get; set; }
        public string Owner { get; set; }
        public string PwdLastSet { get; set; }
        public string LastLogonTimestamp { get; set; }
        public string CanonicalName { get; set; }
        public string ServicePrincipalNames { get; set; }
        public int ServicePrincipalNameCount { get; set; }
        public int ChildObjectCount { get; set; }
        public int? SupportedEncryptionTypes { get; set; }
    }

    internal enum AccountConflictChoice
    {
        Cancel = 0,
        DeleteAndRetry = 1,
        RenameAndJoin = 2
    }
}
