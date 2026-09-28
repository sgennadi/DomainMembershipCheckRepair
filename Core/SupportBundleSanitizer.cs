using System;
using System.Collections.Generic;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainMembershipCheckRepair
{
    internal sealed class SupportBundleSanitizer
    {
        private static readonly Regex SecretAssignmentRegex = new Regex(
            @"(?im)(?<prefix>[""']?\b(?:password|passwd|pwd|client_secret|refresh_token|access_token|authorization)\b[""']?\s*[:=]\s*[""']?)(?<value>[^""'\r\n,;]+)(?<suffix>[""']?)",
            RegexOptions.Compiled);

        private static readonly Regex BearerRegex = new Regex(
            @"(?i)\bBearer\s+[A-Za-z0-9._~+/\-:=]{8,}",
            RegexOptions.Compiled);

        private static readonly Regex DistinguishedNameRegex = new Regex(
            @"(?i)\b(?:CN|OU|DC)=[^,\r\n]+(?:,(?:CN|OU|DC)=[^,\r\n]+)+",
            RegexOptions.Compiled);

        private static readonly Regex DomainAccountRegex = new Regex(
            @"\b[A-Z0-9][A-Z0-9._-]{1,30}\\[A-Za-z0-9.$_-]+\b",
            RegexOptions.Compiled);

        private static readonly Regex UpnRegex = new Regex(
            @"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}\b",
            RegexOptions.Compiled);

        private static readonly Regex UncServerRegex = new Regex(
            @"\\\\(?<server>[A-Za-z0-9._-]+)",
            RegexOptions.Compiled);

        private static readonly Regex Ipv4Regex = new Regex(
            @"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])",
            RegexOptions.Compiled);

        private static readonly Regex Ipv6Regex = new Regex(
            @"(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{0,4}(?:%\d+)?(?![A-Fa-f0-9:])",
            RegexOptions.Compiled);

        private static readonly Regex MacRegex = new Regex(
            @"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            RegexOptions.Compiled);

        private static readonly Regex SidRegex = new Regex(
            @"\bS-\d-(?:\d+-){1,14}\d+\b",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex GuidRegex = new Regex(
            @"\{?\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b\}?",
            RegexOptions.Compiled);

        private static readonly Regex FqdnRegex = new Regex(
            @"\b(?:(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)\.)+(?<tld>[A-Za-z]{2,63})\b",
            RegexOptions.Compiled);

        private static readonly HashSet<string> FileLikeSuffixes =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "exe", "dll", "txt", "json", "xml", "log", "zip", "config",
                "ps1", "psm1", "bat", "cmd", "md", "pdb", "msi", "sys", "cab",
                "inf", "ini", "csv", "html", "htm", "cs", "sln", "csproj"
            };

        private readonly byte[] sessionKey;
        private readonly List<string> knownValues = new List<string>();
        private readonly Dictionary<string, int> replacementCounts =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        internal SupportBundleSanitizer(IEnumerable<string> values)
        {
            sessionKey = CreateSessionKey();

            if (values != null)
            {
                foreach (string value in values)
                    AddKnownValue(value);
            }

            knownValues.Sort(delegate(string left, string right)
            {
                return right.Length.CompareTo(left.Length);
            });
        }

        internal string Sanitize(string text)
        {
            string output = text ?? String.Empty;

            output = SecretAssignmentRegex.Replace(
                output,
                delegate(Match match)
                {
                    Increment("SECRET");
                    return match.Groups["prefix"].Value +
                           "[REDACTED]" +
                           match.Groups["suffix"].Value;
                });

            output = BearerRegex.Replace(
                output,
                delegate(Match match)
                {
                    Increment("SECRET");
                    return "Bearer [REDACTED]";
                });

            foreach (string value in knownValues)
                output = ReplaceKnownValue(output, value);

            output = DistinguishedNameRegex.Replace(
                output,
                delegate(Match match)
                {
                    return TokenAndCount("DN", match.Value);
                });

            output = UncServerRegex.Replace(
                output,
                delegate(Match match)
                {
                    return @"\\" + TokenAndCount("HOST", match.Groups["server"].Value);
                });

            output = DomainAccountRegex.Replace(
                output,
                delegate(Match match)
                {
                    return TokenAndCount("ACCOUNT", match.Value);
                });

            output = UpnRegex.Replace(
                output,
                delegate(Match match)
                {
                    return TokenAndCount("UPN", match.Value);
                });

            output = MacRegex.Replace(
                output,
                delegate(Match match)
                {
                    return TokenAndCount("MAC", match.Value);
                });

            output = SidRegex.Replace(
                output,
                delegate(Match match)
                {
                    return TokenAndCount("SID", match.Value);
                });

            output = GuidRegex.Replace(
                output,
                delegate(Match match)
                {
                    return TokenAndCount("GUID", match.Value);
                });

            output = Ipv4Regex.Replace(
                output,
                delegate(Match match)
                {
                    return TokenAndCount("IPV4", match.Value);
                });

            output = Ipv6Regex.Replace(
                output,
                delegate(Match match)
                {
                    return TokenAndCount("IPV6", match.Value);
                });

            output = FqdnRegex.Replace(
                output,
                delegate(Match match)
                {
                    string tld = match.Groups["tld"].Value;
                    if (FileLikeSuffixes.Contains(tld))
                        return match.Value;

                    return TokenAndCount("FQDN", match.Value);
                });

            return output;
        }

        internal string GetSummary()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("DomainMembershipCheckRepair support bundle redaction");
            sb.AppendLine("====================================================");
            sb.AppendLine("This bundle was sanitized before the ZIP archive was created.");
            sb.AppendLine("Detected environment identifiers are replaced with stable opaque tokens for this bundle only.");
            sb.AppendLine("Passwords, bearer tokens and other detected secrets are replaced with [REDACTED].");
            sb.AppendLine();

            if (replacementCounts.Count == 0)
            {
                sb.AppendLine("No redactable values were detected.");
                return sb.ToString();
            }

            List<string> keys = new List<string>(replacementCounts.Keys);
            keys.Sort(StringComparer.OrdinalIgnoreCase);

            sb.AppendLine("Replacement counts:");
            foreach (string key in keys)
                sb.AppendLine("  " + key + ": " + replacementCounts[key]);

            return sb.ToString();
        }

        private void AddKnownValue(string value)
        {
            string normalized = (value ?? String.Empty).Trim();
            if (normalized.Length < 2)
                return;

            foreach (string existing in knownValues)
            {
                if (String.Equals(existing, normalized, StringComparison.OrdinalIgnoreCase))
                    return;
            }

            knownValues.Add(normalized);
        }

        private string ReplaceKnownValue(string text, string value)
        {
            string category = ClassifyKnownValue(value);
            string output = ReplaceExact(text, value, category);

            string jsonEscaped = value.Replace(@"\", @"\\");
            if (!String.Equals(jsonEscaped, value, StringComparison.Ordinal))
                output = ReplaceExact(output, jsonEscaped, category);

            return output;
        }

        private string ReplaceExact(string text, string value, string category)
        {
            if (String.IsNullOrWhiteSpace(value))
                return text;

            string pattern =
                @"(?<![A-Za-z0-9])" +
                Regex.Escape(value) +
                @"(?![A-Za-z0-9])";

            return Regex.Replace(
                text,
                pattern,
                delegate(Match match)
                {
                    return TokenAndCount(category, value);
                },
                RegexOptions.IgnoreCase);
        }

        private static string ClassifyKnownValue(string value)
        {
            if (String.IsNullOrWhiteSpace(value))
                return "IDENTITY";

            IPAddress address;
            if (IPAddress.TryParse(value.Trim('[', ']'), out address))
            {
                return address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    ? "IPV4"
                    : "IPV6";
            }

            if (GuidRegex.IsMatch(value))
                return "GUID";

            if (value.IndexOf("DC=", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("OU=", StringComparison.OrdinalIgnoreCase) >= 0 ||
                value.IndexOf("CN=", StringComparison.OrdinalIgnoreCase) >= 0)
                return "DN";

            if (value.IndexOf('\') >= 0)
                return "ACCOUNT";

            if (value.IndexOf('.') >= 0)
                return "HOST";

            return "IDENTITY";
        }

        private string TokenAndCount(string category, string value)
        {
            Increment(category);
            return CreateOpaqueToken(category, value);
        }

        private void Increment(string category)
        {
            int count;
            if (!replacementCounts.TryGetValue(category, out count))
                count = 0;

            replacementCounts[category] = count + 1;
        }

        private string CreateOpaqueToken(string category, string value)
        {
            byte[] bytes = Encoding.UTF8.GetBytes((value ?? String.Empty).ToUpperInvariant());
            byte[] digest;

            using (HMACSHA256 hmac = new HMACSHA256(sessionKey))
                digest = hmac.ComputeHash(bytes);

            StringBuilder token = new StringBuilder();
            for (int i = 0; i < 5; i++)
                token.Append(digest[i].ToString("X2"));

            return "<" + category + ":" + token + ">";
        }

        private static byte[] CreateSessionKey()
        {
            byte[] key = new byte[32];
            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                rng.GetBytes(key);

            return key;
        }
    }
}
