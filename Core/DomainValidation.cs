using System;
using System.Text;
using System.Text.RegularExpressions;

namespace DomainMembershipCheckRepair
{
    internal static class DomainValidation
    {
        internal static string ExtractDomainHintFromUser(string user)
        {
            if (String.IsNullOrWhiteSpace(user))
                return String.Empty;

            string value = user.Trim();
            int slash = value.IndexOf('\\');
            int at = value.LastIndexOf('@');

            if (slash > 0)
                return value.Substring(0, slash).Trim();
            if (at > 0 && at < value.Length - 1)
                return value.Substring(at + 1).Trim();

            return String.Empty;
        }

        internal static bool TryValidateUserName(string input, out string normalized, out string error)
        {
            normalized = String.Empty;
            error = null;

            if (String.IsNullOrWhiteSpace(input))
            {
                error = "Enter a domain user.";
                return false;
            }

            string value = input.Trim();
            int slash = value.IndexOf('\\');
            int at = value.IndexOf('@');

            if (slash > 0 && slash < value.Length - 1 && at < 0)
            {
                string domainPart = value.Substring(0, slash).Trim();
                string userPart = value.Substring(slash + 1).Trim();
                if (domainPart.Length == 0 || userPart.Length == 0 || userPart.IndexOf('\\') >= 0)
                {
                    error = @"The DOMAIN\username value is not valid.";
                    return false;
                }

                normalized = domainPart + "\\" + userPart;
                return true;
            }

            if (at > 0 && at < value.Length - 1 && slash < 0 && value.IndexOf('@', at + 1) < 0)
            {
                string userPart = value.Substring(0, at).Trim();
                string domainPart = value.Substring(at + 1).Trim();
                if (userPart.Length == 0 || domainPart.Length == 0)
                {
                    error = "The username@domain value is not valid.";
                    return false;
                }

                normalized = userPart + "@" + domainPart;
                return true;
            }

            error = "Do not enter only a short username.";
            return false;
        }

        internal static string EscapeLdapFilterValue(string value)
        {
            if (value == null)
                return String.Empty;

            StringBuilder sb = new StringBuilder(value.Length);
            foreach (char c in value)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\5c"); break;
                    case '*': sb.Append("\\2a"); break;
                    case '(': sb.Append("\\28"); break;
                    case ')': sb.Append("\\29"); break;
                    case '\0': sb.Append("\\00"); break;
                    default: sb.Append(c); break;
                }
            }
            return sb.ToString();
        }

        internal static string ValidateComputerName(string name)
        {
            if (String.IsNullOrWhiteSpace(name))
                return "Computer name cannot be empty.";

            name = name.Trim();
            if (name.Length > 15)
                return "Use 15 characters or fewer for maximum NetBIOS/Active Directory compatibility.";

            if (!Regex.IsMatch(name, "^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$|^[A-Za-z0-9]$"))
                return "Use only letters, numbers and hyphens. The name cannot start or end with a hyphen.";

            if (Regex.IsMatch(name, "^[0-9]+$"))
                return "The computer name cannot contain only numbers.";

            return null;
        }

        internal static string CreateSuggestedName(string currentName)
        {
            string suffix = "-2";
            string baseName = currentName == null ? "PC" : currentName.Trim();
            int maxBase = 15 - suffix.Length;
            if (baseName.Length > maxBase)
                baseName = baseName.Substring(0, maxBase);
            baseName = baseName.TrimEnd('-');
            if (baseName.Length == 0)
                baseName = "PC";
            return baseName + suffix;
        }

        internal static string DnToDns(string distinguishedName)
        {
            if (String.IsNullOrWhiteSpace(distinguishedName))
                return String.Empty;

            string[] parts = distinguishedName.Split(',');
            StringBuilder dns = new StringBuilder();

            foreach (string rawPart in parts)
            {
                string part = (rawPart ?? String.Empty).Trim();
                if (!part.StartsWith("DC=", StringComparison.OrdinalIgnoreCase))
                    continue;

                string label = part.Substring(3).Trim();
                if (label.Length == 0)
                    continue;

                label = label.Replace(@"\\,", ",")
                             .Replace(@"\\=", "=")
                             .Replace(@"\\\\", @"\\");

                if (dns.Length > 0)
                    dns.Append('.');
                dns.Append(label);
            }

            return dns.ToString();
        }

        internal static string NormalizeDirectoryServer(string value)
        {
            if (String.IsNullOrWhiteSpace(value))
                return String.Empty;

            string server = value.Trim();
            if (server.StartsWith("LDAP://", StringComparison.OrdinalIgnoreCase))
                server = server.Substring(7);
            while (server.StartsWith(@"\\", StringComparison.Ordinal))
                server = server.Substring(2);
            server = server.Trim().Trim('/');
            return server;
        }
    }
}
