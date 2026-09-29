using System;
using System.Collections.Generic;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal static class WindowsCommandLine
    {
        internal static string BuildArguments(IEnumerable<string> arguments)
        {
            if (arguments == null)
                return String.Empty;

            StringBuilder result = new StringBuilder();
            foreach (string argument in arguments)
            {
                if (result.Length > 0)
                    result.Append(' ');

                result.Append(QuoteArgument(argument));
            }

            return result.ToString();
        }

        internal static string BuildArguments(params string[] arguments)
        {
            return BuildArguments((IEnumerable<string>)arguments);
        }

        internal static string QuoteArgument(string value)
        {
            string input = value ?? String.Empty;

            if (input.Length > 0 &&
                input.IndexOfAny(new char[] { ' ', '\t', '\n', '\v', '"' }) < 0)
            {
                return input;
            }

            StringBuilder result = new StringBuilder();
            result.Append('"');

            int backslashes = 0;
            foreach (char c in input)
            {
                if (c == '\\')
                {
                    backslashes++;
                    continue;
                }

                if (c == '"')
                {
                    result.Append('\\', backslashes * 2 + 1);
                    result.Append('"');
                    backslashes = 0;
                    continue;
                }

                if (backslashes > 0)
                {
                    result.Append('\\', backslashes);
                    backslashes = 0;
                }

                result.Append(c);
            }

            if (backslashes > 0)
                result.Append('\\', backslashes * 2);

            result.Append('"');
            return result.ToString();
        }
    }
}
