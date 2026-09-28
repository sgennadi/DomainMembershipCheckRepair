using System;
using System.Collections.Generic;

namespace DomainMembershipCheckRepair.Tools
{
    internal sealed class CommandLine
    {
        private readonly Dictionary<string, List<string>> values =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        internal static CommandLine Parse(string[] args, int startIndex)
        {
            CommandLine result = new CommandLine();

            for (int i = startIndex; i < args.Length; i++)
            {
                string arg = args[i] ?? String.Empty;
                if (!arg.StartsWith("--", StringComparison.Ordinal))
                    throw new ArgumentException("Expected option name, got: " + arg);

                string name = arg.Substring(2);
                string value = "true";

                if (i + 1 < args.Length &&
                    !(args[i + 1] ?? String.Empty).StartsWith("--", StringComparison.Ordinal))
                {
                    value = args[++i] ?? String.Empty;
                }

                List<string> list;
                if (!result.values.TryGetValue(name, out list))
                {
                    list = new List<string>();
                    result.values[name] = list;
                }

                list.Add(value);
            }

            return result;
        }

        internal string Get(string name, string defaultValue)
        {
            List<string> list;
            if (!values.TryGetValue(name, out list) || list.Count == 0)
                return defaultValue;

            return list[list.Count - 1];
        }

        internal string Require(string name)
        {
            string value = Get(name, null);
            if (String.IsNullOrWhiteSpace(value))
                throw new ArgumentException("--" + name + " is required.");

            return value;
        }

        internal bool GetBool(string name, bool defaultValue)
        {
            string value = Get(name, null);
            if (value == null)
                return defaultValue;

            bool parsed;
            if (Boolean.TryParse(value, out parsed))
                return parsed;

            if (String.Equals(value, "1", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "yes", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "on", StringComparison.OrdinalIgnoreCase))
                return true;

            if (String.Equals(value, "0", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "no", StringComparison.OrdinalIgnoreCase) ||
                String.Equals(value, "off", StringComparison.OrdinalIgnoreCase))
                return false;

            throw new ArgumentException("--" + name + " expects true/false.");
        }

        internal int GetInt(string name, int defaultValue)
        {
            string value = Get(name, null);
            if (value == null)
                return defaultValue;

            int parsed;
            if (!Int32.TryParse(value, out parsed))
                throw new ArgumentException("--" + name + " expects an integer.");

            return parsed;
        }

        internal IList<string> GetAll(string name)
        {
            List<string> list;
            if (!values.TryGetValue(name, out list))
                return new string[0];

            return list.AsReadOnly();
        }
    }
}
