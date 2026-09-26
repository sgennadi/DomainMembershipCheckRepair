using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;

namespace DomainMembershipCheckRepair
{
    internal sealed class LdapCompatibilityCheck
    {
        internal string Name = String.Empty;
        internal string Status = String.Empty;
        internal string Details = String.Empty;
        internal string CertificateSubject = String.Empty;
        internal string CertificateIssuer = String.Empty;
        internal string CertificateNotAfter = String.Empty;
    }

    internal sealed class LdapCompatibilityResult
    {
        internal string Dc = String.Empty;
        internal readonly List<LdapCompatibilityCheck> Checks = new List<LdapCompatibilityCheck>();
        internal readonly List<string> Findings = new List<string>();
    }

    internal static class LdapCompatibilityAnalyzer
    {
        internal static LdapCompatibilityResult Analyze(
            string domain,
            string dc,
            string user,
            string password,
            CancellationToken cancellationToken,
            Action<string> progress)
        {
            LdapCompatibilityResult result = new LdapCompatibilityResult();
            result.Dc = DomainValidation.NormalizeDirectoryServer(dc);

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                DomainDiscoveryResult discovered = NativeMethods.DiscoverDomain(domain, false);
                if (discovered.Success)
                    result.Dc = DomainValidation.NormalizeDirectoryServer(discovered.DomainControllerName);
            }

            if (String.IsNullOrWhiteSpace(result.Dc))
            {
                result.Findings.Add("CHECK: No DC is available for LDAP compatibility testing.");
                return result;
            }

            Report(progress, "LDAP Compatibility: signed SASL bind on 389");
            result.Checks.Add(TestBind(result.Dc, 389, false, true, user, password, cancellationToken));

            Report(progress, "LDAP Compatibility: LDAPS bind and certificate on 636");
            result.Checks.Add(TestBind(result.Dc, 636, true, true, user, password, cancellationToken));

            Report(progress, "LDAP Compatibility: unsigned Negotiate probe on 389");
            result.Checks.Add(TestBind(result.Dc, 389, false, false, user, password, cancellationToken));

            AnalyzeFindings(result);
            return result;
        }

        internal static string ToText(LdapCompatibilityResult result)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("LDAP Compatibility Analyzer");
            sb.AppendLine("===========================");
            sb.AppendLine("DC: " + First(result.Dc, "(none)"));

            foreach (LdapCompatibilityCheck check in result.Checks)
            {
                sb.AppendLine();
                sb.AppendLine(check.Name + ": " + First(check.Status, "(not tested)"));
                if (!String.IsNullOrWhiteSpace(check.Details))
                    sb.AppendLine("  " + check.Details);
                if (!String.IsNullOrWhiteSpace(check.CertificateSubject))
                {
                    sb.AppendLine("  Certificate subject:   " + check.CertificateSubject);
                    sb.AppendLine("  Certificate issuer:    " + check.CertificateIssuer);
                    sb.AppendLine("  Certificate not after: " + check.CertificateNotAfter);
                }
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

        internal static string ClassifyException(Exception ex)
        {
            if (ex == null)
                return "FAILED";

            string text = ex.ToString();
            if (text.IndexOf("The server cannot handle directory requests", StringComparison.OrdinalIgnoreCase) >= 0)
                return "FAILED / SERVER POLICY";
            if (text.IndexOf("stronger authentication required", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("strong auth required", StringComparison.OrdinalIgnoreCase) >= 0)
                return "FAILED / SIGNING REQUIRED";
            if (text.IndexOf("invalid credentials", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("logon failure", StringComparison.OrdinalIgnoreCase) >= 0)
                return "FAILED / CREDENTIALS";
            if (text.IndexOf("certificate", StringComparison.OrdinalIgnoreCase) >= 0 ||
                text.IndexOf("TLS", StringComparison.OrdinalIgnoreCase) >= 0)
                return "FAILED / TLS";
            return "FAILED";
        }

        private static LdapCompatibilityCheck TestBind(
            string dc,
            int port,
            bool ssl,
            bool signing,
            string user,
            string password,
            CancellationToken cancellationToken)
        {
            LdapCompatibilityCheck check = new LdapCompatibilityCheck();
            check.Name = ssl
                ? "LDAPS 636 / Negotiate"
                : (signing ? "LDAP 389 / Negotiate + signing" : "LDAP 389 / Negotiate unsigned probe");

            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                LdapDirectoryIdentifier id = new LdapDirectoryIdentifier(dc, port, true, false);
                using (LdapConnection connection = new LdapConnection(id))
                {
                    connection.Timeout = TimeSpan.FromSeconds(8);
                    connection.AuthType = AuthType.Negotiate;

                    NetworkCredential credential = BuildCredential(user, password);
                    if (credential != null)
                        connection.Credential = credential;

                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.SessionOptions.Signing = signing;
                    connection.SessionOptions.Sealing = signing;

                    X509Certificate certificate = null;
                    if (ssl)
                    {
                        connection.SessionOptions.SecureSocketLayer = true;
                        connection.SessionOptions.VerifyServerCertificate =
                            delegate(LdapConnection c, X509Certificate cert)
                            {
                                certificate = cert;
                                return true;
                            };
                    }

                    connection.Bind();
                    cancellationToken.ThrowIfCancellationRequested();

                    SearchRequest request = new SearchRequest(
                        null,
                        "(objectClass=*)",
                        SearchScope.Base,
                        "defaultNamingContext",
                        "dnsHostName");

                    SearchResponse response = (SearchResponse)connection.SendRequest(request);
                    check.Status = "OK";
                    check.Details = response != null
                        ? "Authenticated LDAP bind and RootDSE query succeeded."
                        : "Authenticated LDAP bind succeeded.";

                    if (certificate != null)
                    {
                        X509Certificate2 cert2 = new X509Certificate2(certificate);
                        check.CertificateSubject = cert2.Subject ?? String.Empty;
                        check.CertificateIssuer = cert2.Issuer ?? String.Empty;
                        check.CertificateNotAfter = cert2.NotAfter.ToString("yyyy-MM-dd HH:mm:ss");
                    }
                }
            }
            catch (Exception ex)
            {
                check.Status = ClassifyException(ex);
                check.Details = Collapse(ex.Message, 500);
            }

            return check;
        }

        private static NetworkCredential BuildCredential(string user, string password)
        {
            if (String.IsNullOrWhiteSpace(user) || password == null)
                return null;

            string account;
            string domain;
            if (!NetworkCredentialProcessRunner.TrySplitUser(user, out account, out domain))
                return null;

            if (String.IsNullOrWhiteSpace(domain))
                return new NetworkCredential(account, password);
            return new NetworkCredential(account, password, domain);
        }

        private static void AnalyzeFindings(LdapCompatibilityResult result)
        {
            LdapCompatibilityCheck signed = Find(result, "LDAP 389 / Negotiate + signing");
            LdapCompatibilityCheck ldaps = Find(result, "LDAPS 636 / Negotiate");
            LdapCompatibilityCheck unsigned = Find(result, "LDAP 389 / Negotiate unsigned probe");

            if (signed != null && !String.Equals(signed.Status, "OK", StringComparison.OrdinalIgnoreCase))
                result.Findings.Add("HIGH: Signed LDAP Negotiate bind to port 389 failed.");

            if (ldaps != null && !String.Equals(ldaps.Status, "OK", StringComparison.OrdinalIgnoreCase))
                result.Findings.Add("CHECK: LDAPS 636 bind/certificate test failed.");

            if (unsigned != null &&
                unsigned.Status.IndexOf("SIGNING REQUIRED", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                result.Findings.Add("INFO: The DC rejects the unsigned LDAP probe, consistent with LDAP signing enforcement.");
            }

            if (signed != null && String.Equals(signed.Status, "OK", StringComparison.OrdinalIgnoreCase) &&
                ldaps != null && String.Equals(ldaps.Status, "OK", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add("INFO: Signed LDAP and LDAPS authenticated binds both succeeded.");
            }
        }

        private static LdapCompatibilityCheck Find(LdapCompatibilityResult result, string name)
        {
            foreach (LdapCompatibilityCheck check in result.Checks)
            {
                if (String.Equals(check.Name, name, StringComparison.OrdinalIgnoreCase))
                    return check;
            }
            return null;
        }

        private static void Report(Action<string> progress, string text)
        {
            if (progress != null)
                progress(text);
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

        private static string First(string value, string fallback)
        {
            return String.IsNullOrWhiteSpace(value) ? fallback : value;
        }
    }
}
