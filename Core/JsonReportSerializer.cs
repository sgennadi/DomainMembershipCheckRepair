using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Text;

namespace DomainMembershipCheckRepair
{
    internal sealed class DiagnosticJsonEnvelope
    {
        internal string Action = String.Empty;
        internal int ExitCode;
        internal string ExitMeaning = String.Empty;
        internal object Result;
    }

    internal static class JsonReportSerializer
    {
        internal static string Serialize(object value)
        {
            StringBuilder sb = new StringBuilder();
            HashSet<object> stack = new HashSet<object>(ReferenceComparer.Instance);
            WriteValue(sb, value, stack);
            return sb.ToString();
        }

        internal static string SerializeAction(string action, int exitCode, object result)
        {
            DiagnosticJsonEnvelope envelope = new DiagnosticJsonEnvelope();
            envelope.Action = action ?? String.Empty;
            envelope.ExitCode = exitCode;
            envelope.ExitMeaning = DiagnosticExitCodes.Describe(exitCode);
            envelope.Result = result;
            return Serialize(envelope);
        }

        private static void WriteValue(StringBuilder sb, object value, HashSet<object> stack)
        {
            if (value == null)
            {
                sb.Append("null");
                return;
            }

            Type type = value.GetType();

            if (type == typeof(string) || type == typeof(char) || type == typeof(Guid))
            {
                WriteString(sb, Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }

            if (type == typeof(bool))
            {
                sb.Append((bool)value ? "true" : "false");
                return;
            }

            if (type.IsEnum)
            {
                WriteString(sb, value.ToString());
                return;
            }

            if (type == typeof(DateTime))
            {
                WriteString(sb, ((DateTime)value).ToString("o", CultureInfo.InvariantCulture));
                return;
            }

            if (type == typeof(DateTimeOffset))
            {
                WriteString(sb, ((DateTimeOffset)value).ToString("o", CultureInfo.InvariantCulture));
                return;
            }

            if (type == typeof(TimeSpan))
            {
                WriteString(sb, ((TimeSpan)value).ToString());
                return;
            }

            if (IsNumber(type))
            {
                sb.Append(Convert.ToString(value, CultureInfo.InvariantCulture));
                return;
            }

            IDictionary dictionary = value as IDictionary;
            if (dictionary != null)
            {
                WriteDictionary(sb, dictionary, stack);
                return;
            }

            IEnumerable enumerable = value as IEnumerable;
            if (enumerable != null)
            {
                WriteArray(sb, enumerable, stack);
                return;
            }

            if (!type.IsValueType)
            {
                if (stack.Contains(value))
                {
                    WriteString(sb, "[circular reference]");
                    return;
                }
                stack.Add(value);
            }

            try
            {
                WriteObject(sb, value, type, stack);
            }
            finally
            {
                if (!type.IsValueType)
                    stack.Remove(value);
            }
        }

        private static void WriteDictionary(StringBuilder sb, IDictionary dictionary, HashSet<object> stack)
        {
            sb.Append('{');
            bool first = true;
            foreach (DictionaryEntry entry in dictionary)
            {
                if (!first)
                    sb.Append(',');
                first = false;
                WriteString(sb, Convert.ToString(entry.Key, CultureInfo.InvariantCulture));
                sb.Append(':');
                WriteValue(sb, entry.Value, stack);
            }
            sb.Append('}');
        }

        private static void WriteArray(StringBuilder sb, IEnumerable values, HashSet<object> stack)
        {
            sb.Append('[');
            bool first = true;
            foreach (object value in values)
            {
                if (!first)
                    sb.Append(',');
                first = false;
                WriteValue(sb, value, stack);
            }
            sb.Append(']');
        }

        private static void WriteObject(StringBuilder sb, object value, Type type, HashSet<object> stack)
        {
            SortedDictionary<string, object> members =
                new SortedDictionary<string, object>(StringComparer.OrdinalIgnoreCase);

            PropertyInfo[] properties = type.GetProperties(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

            foreach (PropertyInfo property in properties)
            {
                if (!property.CanRead || property.GetIndexParameters().Length != 0)
                    continue;

                MethodInfo getter = property.GetGetMethod(true);
                if (getter == null || getter.IsStatic)
                    continue;

                try
                {
                    members[ToCamelCase(property.Name)] = property.GetValue(value, null);
                }
                catch
                {
                }
            }

            FieldInfo[] fields = type.GetFields(
                BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic);

            foreach (FieldInfo field in fields)
            {
                if (field.IsStatic || field.IsDefined(typeof(CompilerGeneratedAttribute), false) ||
                    field.Name.IndexOf("k__BackingField", StringComparison.Ordinal) >= 0)
                    continue;

                try
                {
                    string name = ToCamelCase(field.Name);
                    if (!members.ContainsKey(name))
                        members[name] = field.GetValue(value);
                }
                catch
                {
                }
            }

            sb.Append('{');
            bool first = true;
            foreach (KeyValuePair<string, object> item in members)
            {
                if (!first)
                    sb.Append(',');
                first = false;
                WriteString(sb, item.Key);
                sb.Append(':');
                WriteValue(sb, item.Value, stack);
            }
            sb.Append('}');
        }

        private static bool IsNumber(Type type)
        {
            return type == typeof(byte) || type == typeof(sbyte) ||
                   type == typeof(short) || type == typeof(ushort) ||
                   type == typeof(int) || type == typeof(uint) ||
                   type == typeof(long) || type == typeof(ulong) ||
                   type == typeof(float) || type == typeof(double) ||
                   type == typeof(decimal);
        }

        private static string ToCamelCase(string value)
        {
            if (String.IsNullOrEmpty(value) || Char.IsLower(value[0]))
                return value ?? String.Empty;
            if (value.Length == 1)
                return value.ToLowerInvariant();
            return Char.ToLowerInvariant(value[0]) + value.Substring(1);
        }

        private static void WriteString(StringBuilder sb, string value)
        {
            sb.Append('"');
            string text = value ?? String.Empty;
            foreach (char c in text)
            {
                switch (c)
                {
                    case '"': sb.Append("\\\""); break;
                    case '\\': sb.Append("\\\\"); break;
                    case '\b': sb.Append("\\b"); break;
                    case '\f': sb.Append("\\f"); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 32)
                            sb.Append("\\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture));
                        else
                            sb.Append(c);
                        break;
                }
            }
            sb.Append('"');
        }

        private sealed class ReferenceComparer : IEqualityComparer<object>
        {
            internal static readonly ReferenceComparer Instance = new ReferenceComparer();

            public new bool Equals(object x, object y)
            {
                return Object.ReferenceEquals(x, y);
            }

            public int GetHashCode(object obj)
            {
                return RuntimeHelpers.GetHashCode(obj);
            }
        }
    }
}
