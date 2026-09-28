using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Web.Script.Serialization;

namespace DomainMembershipCheckRepair.Tools
{
    internal static class ReleaseTool
    {
        private sealed class ReleaseBinary
        {
            internal string Name;
            internal string BuildPath;
            internal string ConfigPath;
            internal ushort Machine;
        }

        private static readonly ReleaseBinary[] Binaries =
        {
            new ReleaseBinary
            {
                Name = "DomainMembershipCheckRepair-x86.exe",
                BuildPath = @"bin\Release\x86\DomainMembershipCheckRepair.exe",
                ConfigPath = @"bin\Release\x86\DomainMembershipCheckRepair.exe.config",
                Machine = 0x014c
            },
            new ReleaseBinary
            {
                Name = "DomainMembershipCheckRepair-x64.exe",
                BuildPath = @"bin\Release\x64\DomainMembershipCheckRepair.exe",
                ConfigPath = @"bin\Release\x64\DomainMembershipCheckRepair.exe.config",
                Machine = 0x8664
            },
            new ReleaseBinary
            {
                Name = "DomainMembershipCheckRepair-arm64.exe",
                BuildPath = @"bin\Release\ARM64\DomainMembershipCheckRepair.exe",
                ConfigPath = @"bin\Release\ARM64\DomainMembershipCheckRepair.exe.config",
                Machine = 0xaa64
            }
        };

        internal static int ValidateTag(CommandLine options)
        {
            string root = Path.GetFullPath(options.Get("root", Environment.CurrentDirectory));
            string refName = options.Get("tag", Environment.GetEnvironmentVariable("GITHUB_REF_NAME") ?? String.Empty);
            string version = ReadSourceVersion(root);
            string expected = "v" + version;

            if (!String.Equals(refName, expected, StringComparison.Ordinal))
                throw new InvalidOperationException("Release tag '" + refName + "' does not match VersionInfo.cs ('" + expected + "').");

            Console.WriteLine("Release tag validated: " + refName);
            return 0;
        }

        internal static int ValidateOrigin(CommandLine options)
        {
            string repository = options.Get(
                "repository",
                Environment.GetEnvironmentVariable("GITHUB_REPOSITORY") ?? String.Empty);
            string sha = options.Get(
                "sha",
                Environment.GetEnvironmentVariable("GITHUB_SHA") ?? String.Empty);
            string token = Environment.GetEnvironmentVariable("GITHUB_TOKEN") ?? String.Empty;

            if (!Regex.IsMatch(repository, @"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$"))
                throw new InvalidOperationException("A valid owner/repository value is required.");

            if (!Regex.IsMatch(sha, @"^[0-9a-fA-F]{40}$"))
                throw new InvalidOperationException("A full 40-character release commit SHA is required.");

            if (String.IsNullOrWhiteSpace(token))
                throw new InvalidOperationException("GITHUB_TOKEN is required to validate release origin and required checks.");

            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;

            Dictionary<string, object> branch =
                GetGitHubJson(
                    "https://api.github.com/repos/" + repository + "/branches/main",
                    token);

            string mainSha = GetNestedString(branch, "commit", "sha");
            if (!Regex.IsMatch(mainSha ?? String.Empty, @"^[0-9a-fA-F]{40}$"))
                throw new InvalidOperationException("Unable to determine the protected main branch commit.");

            if (!String.Equals(sha, mainSha, StringComparison.OrdinalIgnoreCase))
            {
                Dictionary<string, object> compare =
                    GetGitHubJson(
                        "https://api.github.com/repos/" + repository +
                        "/compare/" + sha + "..." + mainSha,
                        token);

                string mergeBaseSha =
                    GetNestedString(compare, "merge_base_commit", "sha");

                if (!String.Equals(sha, mergeBaseSha, StringComparison.OrdinalIgnoreCase))
                {
                    throw new InvalidOperationException(
                        "Release commit is not contained in the protected main branch history.");
                }
            }

            IList<string> requestedChecks = options.GetAll("required-check");
            List<string> requiredChecks = new List<string>();

            if (requestedChecks.Count == 0)
            {
                requiredChecks.Add("build");
                requiredChecks.Add("Analyze C#");
            }
            else
            {
                foreach (string check in requestedChecks)
                {
                    if (!String.IsNullOrWhiteSpace(check))
                        requiredChecks.Add(check.Trim());
                }
            }

            if (requiredChecks.Count == 0)
                throw new InvalidOperationException("At least one required check context must be configured.");

            Dictionary<string, object> workflowRuns =
                GetGitHubJson(
                    "https://api.github.com/repos/" + repository +
                    "/actions/runs?head_sha=" + sha + "&per_page=100",
                    token);

            HashSet<long> eligibleMainPushRuns =
                GetEligibleMainPushWorkflowRunIds(workflowRuns, sha);

            if (eligibleMainPushRuns.Count == 0)
            {
                throw new InvalidOperationException(
                    "No GitHub Actions push workflow runs on protected main were found for the release commit.");
            }

            Dictionary<string, object> checks =
                GetGitHubJson(
                    "https://api.github.com/repos/" + repository +
                    "/commits/" + sha + "/check-runs?per_page=100",
                    token);

            string checkError;
            if (!ValidateRequiredCheckRuns(
                checks,
                requiredChecks,
                eligibleMainPushRuns,
                out checkError))
            {
                throw new InvalidOperationException(checkError);
            }

            Console.WriteLine("Release origin validated against protected main.");
            Console.WriteLine("Release commit: " + sha);
            foreach (string check in requiredChecks)
                Console.WriteLine("Required check passed: " + check);

            return 0;
        }

        internal static int SelfTestOriginValidation(CommandLine options)
        {
            string workflowRuns =
                "{\"workflow_runs\":[" +
                "{\"id\":5001,\"head_sha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"head_branch\":\"main\",\"event\":\"push\"}," +
                "{\"id\":5002,\"head_sha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"head_branch\":\"main\",\"event\":\"push\"}," +
                "{\"id\":5999,\"head_sha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"head_branch\":\"feature-copy\",\"event\":\"push\"}," +
                "{\"id\":6000,\"head_sha\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"head_branch\":\"main\",\"event\":\"schedule\"}" +
                "]}";

            HashSet<long> eligible =
                GetEligibleMainPushWorkflowRunIds(
                    ParseJsonObject(workflowRuns),
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

            if (!eligible.Contains(5001) ||
                !eligible.Contains(5002) ||
                eligible.Contains(5999) ||
                eligible.Contains(6000))
            {
                throw new InvalidOperationException(
                    "Main-push workflow-run filtering regression.");
            }

            string passing =
                "{\"check_runs\":[" +
                "{\"id\":101,\"name\":\"build\",\"status\":\"completed\",\"conclusion\":\"success\",\"details_url\":\"https://github.com/o/r/actions/runs/5001/job/101\",\"app\":{\"slug\":\"github-actions\"}}," +
                "{\"id\":999,\"name\":\"build\",\"status\":\"completed\",\"conclusion\":\"cancelled\",\"details_url\":\"https://github.com/o/r/actions/runs/5999/job/999\",\"app\":{\"slug\":\"github-actions\"}}," +
                "{\"id\":103,\"name\":\"Analyze C#\",\"status\":\"completed\",\"conclusion\":\"success\",\"details_url\":\"https://github.com/o/r/actions/runs/5002/job/103\",\"app\":{\"slug\":\"github-actions\"}}" +
                "]}";

            string failing =
                "{\"check_runs\":[" +
                "{\"id\":201,\"name\":\"build\",\"status\":\"completed\",\"conclusion\":\"success\",\"details_url\":\"https://github.com/o/r/actions/runs/5001/job/201\",\"app\":{\"slug\":\"github-actions\"}}," +
                "{\"id\":202,\"name\":\"build\",\"status\":\"completed\",\"conclusion\":\"failure\",\"details_url\":\"https://github.com/o/r/actions/runs/5001/job/202\",\"app\":{\"slug\":\"github-actions\"}}," +
                "{\"id\":203,\"name\":\"Analyze C#\",\"status\":\"completed\",\"conclusion\":\"success\",\"details_url\":\"https://github.com/o/r/actions/runs/5002/job/203\",\"app\":{\"slug\":\"github-actions\"}}" +
                "]}";

            string wrongApp =
                "{\"check_runs\":[" +
                "{\"id\":301,\"name\":\"build\",\"status\":\"completed\",\"conclusion\":\"success\",\"details_url\":\"https://github.com/o/r/actions/runs/5001/job/301\",\"app\":{\"slug\":\"other-app\"}}," +
                "{\"id\":302,\"name\":\"Analyze C#\",\"status\":\"completed\",\"conclusion\":\"success\",\"details_url\":\"https://github.com/o/r/actions/runs/5002/job/302\",\"app\":{\"slug\":\"github-actions\"}}" +
                "]}";

            List<string> required =
                new List<string> { "build", "Analyze C#" };
            string error;

            if (!ValidateRequiredCheckRuns(
                ParseJsonObject(passing),
                required,
                eligible,
                out error))
            {
                throw new InvalidOperationException(
                    "Passing release-check fixture was rejected: " + error);
            }

            if (ValidateRequiredCheckRuns(
                ParseJsonObject(failing),
                required,
                eligible,
                out error))
            {
                throw new InvalidOperationException(
                    "Latest failing main-push required check was incorrectly accepted.");
            }

            if (ValidateRequiredCheckRuns(
                ParseJsonObject(wrongApp),
                required,
                eligible,
                out error))
            {
                throw new InvalidOperationException(
                    "Required check from a non-GitHub-Actions app was incorrectly accepted.");
            }

            Console.WriteLine(
                "Release origin/check-run context self-test passed.");
            return 0;
        }

        internal static int Prepare(CommandLine options)
        {
            string root = Path.GetFullPath(options.Get("root", Environment.CurrentDirectory));
            string unsignedDirectory = Path.GetFullPath(options.Get("unsigned", Path.Combine(root, "unsigned")));
            string configDirectory = Path.GetFullPath(options.Get("configs", Path.Combine(root, "release-configs")));
            string githubOutput = options.Get("github-output", Environment.GetEnvironmentVariable("GITHUB_OUTPUT") ?? String.Empty);

            RecreateDirectory(unsignedDirectory);
            RecreateDirectory(configDirectory);

            foreach (ReleaseBinary binary in Binaries)
            {
                string exe = Path.Combine(root, binary.BuildPath);
                string config = Path.Combine(root, binary.ConfigPath);

                RequireFile(exe);
                RequireFile(config);
                RequirePerMonitorV2(config);

                File.Copy(exe, Path.Combine(unsignedDirectory, binary.Name), true);
                File.Copy(config, Path.Combine(configDirectory, binary.Name + ".config"), true);
            }

            string x64 = Path.Combine(root, Binaries[1].BuildPath);
            string builtVersion = FileVersionInfo.GetVersionInfo(x64).ProductVersion ?? String.Empty;
            string sourceVersion = ReadSourceVersion(root);

            if (String.IsNullOrWhiteSpace(builtVersion))
                throw new InvalidOperationException("Unable to read ProductVersion from the built x64 executable.");

            if (!String.Equals(builtVersion, sourceVersion, StringComparison.Ordinal))
                throw new InvalidOperationException("Built ProductVersion does not match VersionInfo.cs.");

            if (!String.IsNullOrWhiteSpace(githubOutput))
                File.AppendAllText(githubOutput, "product_version=" + builtVersion + Environment.NewLine, new UTF8Encoding(false));

            Console.WriteLine("Prepared unsigned release binaries.");
            Console.WriteLine("ProductVersion: " + builtVersion);
            return 0;
        }

        internal static int ValidateSignPathConfiguration(CommandLine options)
        {
            string organizationId = Environment.GetEnvironmentVariable("SIGNPATH_ORGANIZATION_ID");
            string apiToken = Environment.GetEnvironmentVariable("SIGNPATH_API_TOKEN");

            if (String.IsNullOrWhiteSpace(organizationId))
                throw new InvalidOperationException("SIGNPATH_ORGANIZATION_ID repository variable is required.");
            if (String.IsNullOrWhiteSpace(apiToken))
                throw new InvalidOperationException("SIGNPATH_API_TOKEN repository secret is required.");

            Console.WriteLine("Mandatory SignPath configuration is present.");
            return 0;
        }

        internal static int ValidateSigned(CommandLine options)
        {
            string signedDirectory = Path.GetFullPath(options.Get("signed", "signed"));
            string expectedVersion = options.Require("expected-version");
            string expectedSigner = options.Get(
                "expected-signer",
                Environment.GetEnvironmentVariable("SIGNPATH_EXPECTED_SIGNER_SUBJECT") ?? String.Empty);

            string signtool = FindSignTool();

            foreach (ReleaseBinary binary in Binaries)
            {
                string file = FindUniqueFile(signedDirectory, binary.Name);

                ProcessResult verify = ProcessHelper.Run(
                    signtool,
                    new string[] { "verify", "/pa", "/v", file },
                    180000);
                if (verify.TimedOut || verify.ExitCode != 0)
                    throw new InvalidOperationException("Authenticode verification failed for " + binary.Name + ".");

                string verificationText = (verify.StandardOutput ?? String.Empty) + Environment.NewLine + (verify.StandardError ?? String.Empty);
                bool timestamped =
                    verificationText.IndexOf("The signature is timestamped", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    verificationText.IndexOf("Timestamp Verified by", StringComparison.OrdinalIgnoreCase) >= 0;
                if (!timestamped)
                    throw new InvalidOperationException("Trusted timestamp evidence is missing for " + binary.Name + ".");

                X509Certificate2 signer;
                try
                {
                    signer = new X509Certificate2(X509Certificate.CreateFromSignedFile(file));
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("Unable to read signer certificate for " + binary.Name + ": " + ex.Message);
                }

                using (signer)
                {
                    if (!String.IsNullOrWhiteSpace(expectedSigner) &&
                        signer.Subject.IndexOf(expectedSigner, StringComparison.OrdinalIgnoreCase) < 0)
                    {
                        throw new InvalidOperationException("Signer subject does not match the configured expected signer for " + binary.Name + ".");
                    }

                    Console.WriteLine(binary.Name + " signer: " + signer.Subject);
                }

                string version = FileVersionInfo.GetVersionInfo(file).ProductVersion ?? String.Empty;
                if (!String.Equals(version, expectedVersion, StringComparison.Ordinal))
                    throw new InvalidOperationException(binary.Name + " ProductVersion does not match the expected release version.");

                ushort machine = ReadPeMachine(file);
                if (machine != binary.Machine)
                    throw new InvalidOperationException(binary.Name + " has an unexpected PE architecture.");
            }

            Console.WriteLine("All SignPath-signed executables passed Authenticode, timestamp, version and architecture validation.");
            return 0;
        }

        internal static int FinalizeFiles(CommandLine options)
        {
            string signedDirectory = Path.GetFullPath(options.Get("signed", "signed"));
            string configDirectory = Path.GetFullPath(options.Get("configs", "release-configs"));
            string outputDirectory = Path.GetFullPath(options.Get("output", "release-files"));
            string tag = options.Get("tag", Environment.GetEnvironmentVariable("GITHUB_REF_NAME") ?? String.Empty);

            RecreateDirectory(outputDirectory);

            foreach (ReleaseBinary binary in Binaries)
            {
                string signed = FindUniqueFile(signedDirectory, binary.Name);
                string config = Path.Combine(configDirectory, binary.Name + ".config");
                RequireFile(config);

                File.Copy(signed, Path.Combine(outputDirectory, binary.Name), true);
                File.Copy(config, Path.Combine(outputDirectory, binary.Name + ".config"), true);
            }

            WriteChecksums(outputDirectory);
            WriteReleaseNotes(outputDirectory, tag);

            Console.WriteLine("Final release files prepared.");
            return 0;
        }

        internal static int Smoke(CommandLine options)
        {
            string directory = Path.GetFullPath(options.Get("directory", "release-files"));

            string[] runnable =
            {
                "DomainMembershipCheckRepair-x86.exe",
                "DomainMembershipCheckRepair-x64.exe"
            };

            foreach (string name in runnable)
            {
                string file = Path.Combine(directory, name);
                RequireFile(file);

                ProcessResult result = ProcessHelper.Run(
                    file,
                    new string[] { "--cli", "--action", "ui-smoke", "--json" },
                    180000);

                if (result.TimedOut || result.ExitCode != 0)
                    throw new InvalidOperationException(name + " GUI/DPI smoke test failed.");

                Console.WriteLine("GUI/DPI smoke passed: " + name);
            }

            VerifyChecksums(directory);
            Console.WriteLine("Release checksum self-verification passed.");
            return 0;
        }

        private static Dictionary<string, object> GetGitHubJson(
            string url,
            string token)
        {
            try
            {
                HttpWebRequest request = (HttpWebRequest)WebRequest.Create(url);
                request.Method = "GET";
                request.Accept = "application/vnd.github+json";
                request.UserAgent = "DomainMembershipCheckRepair-ReleaseValidator/1.0";
                request.Timeout = 30000;
                request.ReadWriteTimeout = 30000;
                request.Headers["Authorization"] = "Bearer " + token;
                request.Headers["X-GitHub-Api-Version"] = "2022-11-28";

                using (HttpWebResponse response = (HttpWebResponse)request.GetResponse())
                using (Stream stream = response.GetResponseStream())
                using (StreamReader reader = new StreamReader(stream, Encoding.UTF8))
                {
                    return ParseJsonObject(reader.ReadToEnd());
                }
            }
            catch (WebException ex)
            {
                HttpWebResponse response = ex.Response as HttpWebResponse;
                string status = response == null
                    ? "network error"
                    : ((int)response.StatusCode).ToString() + " " + response.StatusDescription;

                if (response != null)
                    response.Dispose();

                throw new InvalidOperationException(
                    "GitHub API validation request failed (" + status + ").");
            }
        }

        private static Dictionary<string, object> ParseJsonObject(string json)
        {
            object parsed = new JavaScriptSerializer().DeserializeObject(json ?? String.Empty);
            Dictionary<string, object> result = parsed as Dictionary<string, object>;
            if (result == null)
                throw new InvalidOperationException("GitHub API returned an unexpected JSON document.");

            return result;
        }

        private static string GetNestedString(
            Dictionary<string, object> root,
            string objectName,
            string propertyName)
        {
            if (root == null)
                return String.Empty;

            object nestedValue;
            if (!root.TryGetValue(objectName, out nestedValue))
                return String.Empty;

            Dictionary<string, object> nested =
                nestedValue as Dictionary<string, object>;
            if (nested == null)
                return String.Empty;

            object value;
            if (!nested.TryGetValue(propertyName, out value))
                return String.Empty;

            return Convert.ToString(value) ?? String.Empty;
        }

        private static HashSet<long> GetEligibleMainPushWorkflowRunIds(
            Dictionary<string, object> payload,
            string expectedSha)
        {
            HashSet<long> result = new HashSet<long>();

            object rawRuns;
            if (payload == null ||
                !payload.TryGetValue("workflow_runs", out rawRuns))
            {
                return result;
            }

            object[] runs = rawRuns as object[];
            if (runs == null)
                return result;

            foreach (object raw in runs)
            {
                Dictionary<string, object> run =
                    raw as Dictionary<string, object>;
                if (run == null)
                    continue;

                if (!String.Equals(
                    GetString(run, "head_sha"),
                    expectedSha,
                    StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!String.Equals(
                    GetString(run, "head_branch"),
                    "main",
                    StringComparison.Ordinal))
                {
                    continue;
                }

                if (!String.Equals(
                    GetString(run, "event"),
                    "push",
                    StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                long id;
                if (Int64.TryParse(GetString(run, "id"), out id) &&
                    id > 0)
                {
                    result.Add(id);
                }
            }

            return result;
        }

        private static long ExtractWorkflowRunId(
            Dictionary<string, object> checkRun)
        {
            string detailsUrl = GetString(checkRun, "details_url");
            if (String.IsNullOrWhiteSpace(detailsUrl))
                return 0;

            Match match = Regex.Match(
                detailsUrl,
                @"/actions/runs/(\d+)(?:/|$)",
                RegexOptions.IgnoreCase);

            long id;
            if (!match.Success ||
                !Int64.TryParse(match.Groups[1].Value, out id))
            {
                return 0;
            }

            return id;
        }

        private static bool ValidateRequiredCheckRuns(
            Dictionary<string, object> payload,
            IList<string> requiredChecks,
            ISet<long> eligibleWorkflowRunIds,
            out string error)
        {
            error = String.Empty;

            object rawRuns;
            if (payload == null ||
                !payload.TryGetValue("check_runs", out rawRuns))
            {
                error = "GitHub check-run response does not contain check_runs.";
                return false;
            }

            object[] runs = rawRuns as object[];
            if (runs == null)
            {
                error = "GitHub check-run response has an unexpected check_runs format.";
                return false;
            }

            foreach (string required in requiredChecks)
            {
                Dictionary<string, object> latest = null;
                long latestId = -1;

                foreach (object raw in runs)
                {
                    Dictionary<string, object> run =
                        raw as Dictionary<string, object>;
                    if (run == null)
                        continue;

                    object nameValue;
                    if (!run.TryGetValue("name", out nameValue) ||
                        !String.Equals(
                            Convert.ToString(nameValue),
                            required,
                            StringComparison.Ordinal))
                    {
                        continue;
                    }

                    object appValue;
                    Dictionary<string, object> app = null;
                    if (run.TryGetValue("app", out appValue))
                        app = appValue as Dictionary<string, object>;

                    object slugValue;
                    string slug =
                        app != null && app.TryGetValue("slug", out slugValue)
                            ? Convert.ToString(slugValue)
                            : String.Empty;

                    if (!String.Equals(
                        slug,
                        "github-actions",
                        StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    long workflowRunId = ExtractWorkflowRunId(run);
                    if (workflowRunId <= 0 ||
                        eligibleWorkflowRunIds == null ||
                        !eligibleWorkflowRunIds.Contains(workflowRunId))
                    {
                        continue;
                    }

                    long id = 0;
                    object idValue;
                    if (run.TryGetValue("id", out idValue))
                        Int64.TryParse(Convert.ToString(idValue), out id);

                    if (latest == null || id > latestId)
                    {
                        latest = run;
                        latestId = id;
                    }
                }

                if (latest == null)
                {
                    error =
                        "Required GitHub Actions check '" + required +
                        "' was not found on an eligible protected-main push workflow run for the release commit.";
                    return false;
                }

                string status = GetString(latest, "status");
                string conclusion = GetString(latest, "conclusion");

                if (!String.Equals(status, "completed", StringComparison.OrdinalIgnoreCase) ||
                    !String.Equals(conclusion, "success", StringComparison.OrdinalIgnoreCase))
                {
                    error =
                        "Latest required check '" + required +
                        "' is not successful (status=" + status +
                        ", conclusion=" + conclusion + ").";
                    return false;
                }
            }

            return true;
        }

        private static string GetString(
            Dictionary<string, object> values,
            string key)
        {
            if (values == null)
                return String.Empty;

            object value;
            if (!values.TryGetValue(key, out value))
                return String.Empty;

            return Convert.ToString(value) ?? String.Empty;
        }

        private static string ReadSourceVersion(string root)
        {
            string path = Path.Combine(root, "VersionInfo.cs");
            RequireFile(path);
            string source = File.ReadAllText(path);
            Match match = Regex.Match(source, @"ProductVersion\s*=\s*""([^""]+)""");
            if (!match.Success)
                throw new InvalidOperationException("Could not read ProductVersion from VersionInfo.cs.");
            return match.Groups[1].Value;
        }

        private static void RequirePerMonitorV2(string config)
        {
            string text = File.ReadAllText(config);
            if (text.IndexOf("PerMonitorV2", StringComparison.OrdinalIgnoreCase) < 0)
                throw new InvalidOperationException("PerMonitorV2 is missing from release config: " + Path.GetFileName(config));
        }

        private static string FindUniqueFile(string root, string name)
        {
            if (!Directory.Exists(root))
                throw new DirectoryNotFoundException("Directory not found: " + root);

            string[] matches = Directory.GetFiles(root, name, SearchOption.AllDirectories);
            if (matches.Length == 0)
                throw new FileNotFoundException("Required signed artifact is missing: " + name);
            if (matches.Length != 1)
                throw new InvalidOperationException("Expected exactly one signed artifact named " + name + ".");

            return matches[0];
        }

        private static ushort ReadPeMachine(string path)
        {
            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length < 0x40)
                throw new InvalidOperationException("Invalid PE file: " + Path.GetFileName(path));

            int peOffset = BitConverter.ToInt32(bytes, 0x3c);
            if (peOffset < 0 || peOffset + 6 >= bytes.Length)
                throw new InvalidOperationException("Invalid PE header: " + Path.GetFileName(path));

            return BitConverter.ToUInt16(bytes, peOffset + 4);
        }

        private static void WriteChecksums(string directory)
        {
            List<string> files = new List<string>();
            foreach (string file in Directory.GetFiles(directory, "DomainMembershipCheckRepair-*", SearchOption.TopDirectoryOnly))
                files.Add(file);

            files.Sort(StringComparer.OrdinalIgnoreCase);

            using (StreamWriter writer = new StreamWriter(
                Path.Combine(directory, "SHA256SUMS.txt"),
                false,
                new ASCIIEncoding()))
            {
                foreach (string file in files)
                    writer.WriteLine(ComputeSha256(file) + "  " + Path.GetFileName(file));
            }
        }

        private static void VerifyChecksums(string directory)
        {
            string checksumPath = Path.Combine(directory, "SHA256SUMS.txt");
            RequireFile(checksumPath);

            foreach (string raw in File.ReadAllLines(checksumPath))
            {
                if (String.IsNullOrWhiteSpace(raw))
                    continue;
                if (raw.Length < 67 || raw[64] != ' ' || raw[65] != ' ')
                    throw new InvalidOperationException("Invalid SHA256SUMS line.");

                string expected = raw.Substring(0, 64).ToLowerInvariant();
                string name = raw.Substring(66);
                string file = Path.Combine(directory, name);
                RequireFile(file);

                string actual = ComputeSha256(file);
                if (!String.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException("Checksum verification failed for " + name + ".");
            }
        }

        private static string ComputeSha256(string path)
        {
            using (SHA256 sha = SHA256.Create())
            using (FileStream stream = File.OpenRead(path))
            {
                byte[] hash = sha.ComputeHash(stream);
                StringBuilder output = new StringBuilder(hash.Length * 2);
                foreach (byte value in hash)
                    output.Append(value.ToString("x2"));
                return output.ToString();
            }
        }

        private static void WriteReleaseNotes(string directory, string tag)
        {
            StringBuilder text = new StringBuilder();
            text.AppendLine("## Code signing policy");
            text.AppendLine();
            text.AppendLine("Free code signing provided by [SignPath.io](https://signpath.io/), certificate by [SignPath Foundation](https://signpath.org/).");
            text.AppendLine();
            text.AppendLine("These release executables are Authenticode-signed using SignPath.io with a certificate provided by SignPath Foundation. The workflow refuses to publish unsigned release binaries.");
            text.AppendLine();
            text.AppendLine("See the repository [Code signing policy](https://github.com/sgennadi/DomainMembershipCheckRepair/blob/main/SIGNING.md) for build, approval, privacy, and verification details.");
            text.AppendLine();
            text.AppendLine("## Supply-chain verification");
            text.AppendLine();
            text.AppendLine("SHA-256 checksums are attached to this release. GitHub build-provenance attestations are generated for the final release files.");
            text.AppendLine();
            text.AppendLine("Keep the matching .exe.config file next to the executable. It contains the required WinForms PerMonitorV2/high-DPI configuration.");
            text.AppendLine();
            text.AppendLine("## Source");
            text.AppendLine();
            text.AppendLine("Tag: " + tag);
            text.AppendLine();
            text.AppendLine("Full changelog: https://github.com/sgennadi/DomainMembershipCheckRepair/commits/" + tag);

            File.WriteAllText(
                Path.Combine(directory, "RELEASE_NOTES.md"),
                text.ToString(),
                new UTF8Encoding(false));
        }

        private static void RecreateDirectory(string path)
        {
            if (Directory.Exists(path))
                Directory.Delete(path, true);
            Directory.CreateDirectory(path);
        }

        private static void RequireFile(string path)
        {
            if (!File.Exists(path))
                throw new FileNotFoundException("Required file is missing.", path);
        }

        private static string FindSignTool()
        {
            string[] roots =
            {
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Windows Kits", "10", "bin"),
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Kits", "10", "bin")
            };

            foreach (string root in roots)
            {
                if (!Directory.Exists(root))
                    continue;

                string[] candidates = Directory.GetFiles(root, "signtool.exe", SearchOption.AllDirectories);
                Array.Sort(candidates, StringComparer.OrdinalIgnoreCase);
                if (candidates.Length > 0)
                    return candidates[candidates.Length - 1];
            }

            throw new FileNotFoundException("signtool.exe was not found.");
        }
    }
}
