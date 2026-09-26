using System;
using System.Collections.Generic;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
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

            Report(progress, "LDAP Compatibility: StartTLS 389 + Negotiate bind");
            result.Checks.Add(TestStartTlsBind(result.Dc, user, password, cancellationToken));

            Report(progress, "LDAP Compatibility: validating LDAPS TLS certificate and hostname");
            result.Checks.Add(TestLdapsTls(result.Dc, cancellationToken));

            Report(progress, "LDAP Compatibility: LDAPS authenticated bind on 636");
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

        private static LdapCompatibilityCheck TestStartTlsBind(
            string dc,
            string user,
            string password,
            CancellationToken cancellationToken)
        {
            LdapCompatibilityCheck check = new LdapCompatibilityCheck();
            check.Name = "LDAP 389 / StartTLS + Negotiate";

            try
            {
                cancellationToken.ThrowIfCancellationRequested();

                LdapDirectoryIdentifier id = new LdapDirectoryIdentifier(dc, 389, true, false);
                using (LdapConnection connection = new LdapConnection(id))
                {
                    connection.Timeout = TimeSpan.FromSeconds(8);
                    connection.AuthType = AuthType.Negotiate;

                    NetworkCredential credential = BuildCredential(user, password);
                    if (credential != null)
                        connection.Credential = credential;

                    connection.SessionOptions.ProtocolVersion = 3;
                    connection.SessionOptions.StartTransportLayerSecurity(null);
                    cancellationToken.ThrowIfCancellationRequested();

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
                    check.Details =
                        response != null
                            ? "StartTLS negotiation, Windows Negotiate authentication and RootDSE query succeeded. " +
                              "This exercises the TLS-protected SSPI path used by CBT-capable Windows LDAP clients."
                            : "StartTLS negotiation and Windows Negotiate authentication succeeded.";
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                check.Status = ClassifyException(ex);
                check.Details = Collapse(ex.Message, 500);
            }

            return check;
        }

        private static LdapCompatibilityCheck TestLdapsTls(
            string dc,
            CancellationToken cancellationToken)
        {
            LdapCompatibilityCheck check = new LdapCompatibilityCheck();
            check.Name = "LDAPS 636 / TLS certificate + hostname";
            TcpClient client = null;
            SslStream ssl = null;
            X509Certificate2 capturedCertificate = null;
            SslPolicyErrors validationErrors = SslPolicyErrors.None;

            try
            {
                cancellationToken.ThrowIfCancellationRequested();
                client = new TcpClient();

                IAsyncResult connect = client.BeginConnect(dc, 636, null, null);
                WaitWithCancellation(connect.AsyncWaitHandle, 8000, cancellationToken);
                client.EndConnect(connect);

                ssl = new SslStream(
                    client.GetStream(),
                    false,
                    delegate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors errors)
                    {
                        validationErrors = errors;
                        if (certificate != null)
                            capturedCertificate = new X509Certificate2(certificate);
                        return errors == SslPolicyErrors.None;
                    });

                IAsyncResult auth = ssl.BeginAuthenticateAsClient(dc, null, null);
                WaitWithCancellation(auth.AsyncWaitHandle, 8000, cancellationToken);
                ssl.EndAuthenticateAsClient(auth);

                check.Status = "OK";
                check.Details =
                    "TLS handshake succeeded; certificate chain and server-name validation passed. " +
                    "Protocol=" + ssl.SslProtocol +
                    ", cipher=" + ssl.CipherAlgorithm + "/" + ssl.CipherStrength + ".";
            }
            catch (TimeoutException ex)
            {
                check.Status = "FAILED / TIMEOUT";
                check.Details = ex.Message;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                check.Status = validationErrors == SslPolicyErrors.None
                    ? ClassifyException(ex)
                    : "FAILED / CERTIFICATE";
                check.Details = validationErrors == SslPolicyErrors.None
                    ? Collapse(ex.Message, 500)
                    : "TLS certificate validation failed: " + validationErrors + ". " + Collapse(ex.Message, 360);
            }
            finally
            {
                if (capturedCertificate != null)
                {
                    check.CertificateSubject = capturedCertificate.Subject ?? String.Empty;
                    check.CertificateIssuer = capturedCertificate.Issuer ?? String.Empty;
                    check.CertificateNotAfter = capturedCertificate.NotAfter.ToString("yyyy-MM-dd HH:mm:ss");
                    capturedCertificate.Dispose();
                }

                if (ssl != null)
                    ssl.Dispose();
                if (client != null)
                    client.Close();
            }

            return check;
        }

        private static void WaitWithCancellation(
            WaitHandle waitHandle,
            int timeoutMs,
            CancellationToken cancellationToken)
        {
            int elapsed = 0;
            while (elapsed < timeoutMs)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (waitHandle.WaitOne(100))
                    return;
                elapsed += 100;
            }

            throw new TimeoutException("The TLS operation timed out.");
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

                    if (ssl)
                        connection.SessionOptions.SecureSocketLayer = true;

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
            LdapCompatibilityCheck startTls = Find(result, "LDAP 389 / StartTLS + Negotiate");
            LdapCompatibilityCheck tls = Find(result, "LDAPS 636 / TLS certificate + hostname");
            LdapCompatibilityCheck ldaps = Find(result, "LDAPS 636 / Negotiate");
            LdapCompatibilityCheck unsigned = Find(result, "LDAP 389 / Negotiate unsigned probe");

            if (signed != null && !String.Equals(signed.Status, "OK", StringComparison.OrdinalIgnoreCase))
                result.Findings.Add("HIGH: Signed LDAP Negotiate bind to port 389 failed.");

            if (startTls != null && !String.Equals(startTls.Status, "OK", StringComparison.OrdinalIgnoreCase))
                result.Findings.Add("CHECK: LDAP StartTLS 389 + Negotiate bind failed; review StartTLS/TLS/CBT compatibility separately from normal signed LDAP.");

            if (tls != null && !String.Equals(tls.Status, "OK", StringComparison.OrdinalIgnoreCase))
                result.Findings.Add("HIGH: LDAPS TLS certificate/hostname validation failed.");

            if (ldaps != null && !String.Equals(ldaps.Status, "OK", StringComparison.OrdinalIgnoreCase))
                result.Findings.Add("CHECK: LDAPS 636 authenticated bind failed.");

            if (unsigned != null &&
                unsigned.Status.IndexOf("SIGNING REQUIRED", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                result.Findings.Add("INFO: The DC rejects the unsigned LDAP probe, consistent with LDAP signing enforcement.");
            }

            if (signed != null && String.Equals(signed.Status, "OK", StringComparison.OrdinalIgnoreCase) &&
                startTls != null && String.Equals(startTls.Status, "OK", StringComparison.OrdinalIgnoreCase) &&
                tls != null && String.Equals(tls.Status, "OK", StringComparison.OrdinalIgnoreCase) &&
                ldaps != null && String.Equals(ldaps.Status, "OK", StringComparison.OrdinalIgnoreCase))
            {
                result.Findings.Add("INFO: Signed LDAP, StartTLS Negotiate and LDAPS authenticated binds all succeeded.");
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
