using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace DomainMembershipCheckRepair
{
    internal static class OfflineDomainJoinPreflightTests
    {
        private const string SimulatedBlob = "NON-SECRET-SIMULATED-ODJ-BLOB";
        private static int failures;
        private static int cases;

        private sealed class FakeProvisioner
        {
            internal int Calls;
            internal int ExitCode;
            internal bool WriteBlob = true;
            internal bool Throw;
            internal bool ExpectedReuse;
            internal string StagedBlob;
            internal Action AfterWrite;

            internal int Run(IEnumerable<string> arguments, out string output)
            {
                Calls++;
                output = "Simulated djoin result; no domain operation was performed.";
                List<string> args = new List<string>(arguments);
                Check(args.Count == (ExpectedReuse ? 8 : 7), "unexpected argument count");
                Check(args[0] == "/provision", "wrong operation");
                Check(args[1] == "/domain" && args[2] == "example.test", "wrong domain arguments");
                Check(args[3] == "/machine" && args[4] == "PC-TEST", "wrong machine arguments");
                Check(args[5] == "/savefile", "missing staged savefile argument");
                if (ExpectedReuse)
                    Check(args[7] == "/reuse", "missing reuse argument");
                StagedBlob = args[6];
                string trustError;
                Check(PrivateStagingService.IsPrivateDirectoryTrusted(
                    Path.GetDirectoryName(StagedBlob), out trustError),
                    "simulated provisioning did not use private staging: " + trustError);
                if (Throw)
                    throw new IOException("simulated command failure");
                if (WriteBlob)
                    File.WriteAllText(StagedBlob, SimulatedBlob);
                if (AfterWrite != null)
                    AfterWrite();
                return ExitCode;
            }
        }

        private static int Main()
        {
            RunCase("invalid tokens never invoke provisioning", InvalidTokens);
            RunCase("existing file and directory are preserved", ExistingTargets);
            RunCase("missing parent is rejected without creation", MissingParent);
            RunCase("device and alternate-stream paths are rejected", UnsafeNames);
            RunCase("untrusted parent writer blocks provisioning", UntrustedWriter);
            RunCase("denied file creation blocks provisioning", DeniedCreate);
            RunCase("junction parent blocks provisioning", JunctionParent);
            RunCase("preflight leaves no file and does not alter parent ACL", PreflightOnly);
            RunCase("successful private commit preserves data and reuse arguments", SuccessfulCommit);
            RunCase("read-only third-party parent access does not get hardened", ReadOnlyParentAccess);
            RunCase("post-preflight name collision preserves competing file", LateCollision);
            RunCase("post-preflight parent ACL change is rejected at commit", LateAclChange);
            RunCase("reported success without blob is not called unstarted", MissingResult);
            RunCase("command error is reported as attempted", CommandError);
            RunCase("command exception reports unknown domain outcome", CommandException);
            Console.WriteLine("ODJ preflight regression cases: " + cases + "; failures: " + failures + ".");
            Console.WriteLine("Provisioning commands were simulated; no real djoin or AD mutation was run.");
            return failures == 0 ? 0 : 1;
        }

        private static void RunCase(string name, Action<string> test)
        {
            cases++;
            string root = String.Empty;
            try
            {
                root = PrivateStagingService.CreateSession("odj-preflight-regression");
                test(root);
                Console.WriteLine("PASS: " + name);
            }
            catch (Exception ex)
            {
                failures++;
                Console.Error.WriteLine("FAIL: " + name + ": " + ex.Message);
            }
            finally
            {
                PrivateStagingService.DeleteSession(root);
                if (!String.IsNullOrWhiteSpace(root) && Directory.Exists(root))
                {
                    failures++;
                    Console.Error.WriteLine("FAIL: test session cleanup: " + name);
                }
            }
        }

        private static void InvalidTokens(string root)
        {
            FakeProvisioner fake = new FakeProvisioner();
            string output;
            string destination = Path.Combine(root, "output.txt");
            Check(OfflineDomainJoinService.ProvisionBlob("example.test /reuse", "PC-TEST", destination,
                false, fake.Run, out output) == 3, "unsafe domain accepted");
            Check(OfflineDomainJoinService.ProvisionBlob("example.test", "BAD_NAME", destination,
                false, fake.Run, out output) == 3, "unsafe computer name accepted");
            Check(OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", String.Empty,
                false, fake.Run, out output) == 3, "empty output accepted");
            Check(fake.Calls == 0, "runner invoked for invalid input");
            Check(Contains(output, "not started"), "pre-command outcome is unclear");
        }

        private static void ExistingTargets(string root)
        {
            string file = Path.Combine(root, "existing.txt");
            File.WriteAllText(file, "KEEP-EXISTING-CONTENT");
            Reject(file);
            Check(File.ReadAllText(file) == "KEEP-EXISTING-CONTENT", "existing file changed");
            string folder = Path.Combine(root, "existing-folder");
            Directory.CreateDirectory(folder);
            Reject(folder);
            Check(Directory.Exists(folder), "existing folder removed");
        }

        private static void MissingParent(string root)
        {
            string parent = Path.Combine(root, "not-created");
            Reject(Path.Combine(parent, "output.txt"));
            Check(!Directory.Exists(parent), "preflight created an arbitrary parent");
        }

        private static void UnsafeNames(string root)
        {
            foreach (string name in new string[] { "NUL", "con.txt", "COM1.dat", "LPT9.txt", "blob.txt:stream" })
                Reject(Path.Combine(root, name));
            Reject(@"\\?\" + Path.Combine(root, "output.txt"));
            Reject(@"\\.\NUL");
        }

        private static void UntrustedWriter(string root)
        {
            string parent = Child(root, "writer");
            AddRule(parent, new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.WriteData, AccessControlType.Allow);
            string before = DirectorySddl(parent);
            Reject(Path.Combine(parent, "output.txt"));
            Check(DirectorySddl(parent) == before, "untrusted parent ACL was silently changed");
            Check(Directory.GetFiles(parent).Length == 0, "untrusted parent was probed or written");
        }

        private static void DeniedCreate(string root)
        {
            string parent = Child(root, "no-create");
            AddRule(parent, new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.CreateFiles, AccessControlType.Deny);
            Reject(Path.Combine(parent, "output.txt"));
            Check(Directory.GetFiles(parent).Length == 0, "failed capability probe leaked a file");
        }

        private static void JunctionParent(string root)
        {
            string target = Child(root, "real-parent");
            string link = Path.Combine(root, "redirected-parent");
            CreateJunction(link, target);
            try
            {
                Check((File.GetAttributes(link) & FileAttributes.ReparsePoint) != 0,
                    "test junction was not a reparse point");
                Reject(Path.Combine(link, "output.txt"));
                Check(Directory.GetFiles(target).Length == 0, "redirected target was written");
            }
            finally
            {
                // Delete the junction itself, never recursively traverse it.
                if (Directory.Exists(link))
                    Directory.Delete(link);
            }
            Check(Directory.Exists(target), "junction cleanup deleted its target");
        }

        private static void PreflightOnly(string root)
        {
            string destination = Path.Combine(root, "output.txt");
            string before = DirectorySddl(root);
            string normalized;
            string error;
            Check(OfflineDomainJoinService.PreflightProvisioningOutput(destination, out normalized, out error),
                "valid preflight failed: " + error);
            Check(normalized == Path.GetFullPath(destination), "wrong normalized destination");
            Check(!File.Exists(destination), "preflight created the final output");
            Check(Directory.GetFiles(root).Length == 0, "capability probe was not removed");
            Check(DirectorySddl(root) == before, "preflight modified parent ACL");
        }

        private static void SuccessfulCommit(string root)
        {
            string destination = Path.Combine(root, "output.txt");
            FakeProvisioner fake = new FakeProvisioner();
            fake.ExpectedReuse = true;
            fake.AfterWrite = delegate
            {
                Check(!File.Exists(destination), "output exists before simulated command finishes");
                Check(Directory.GetFiles(root).Length == 0, "preflight probe remains when command begins");
            };
            string output;
            int code = OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", destination,
                true, fake.Run, out output);
            Check(code == 0, "valid commit failed: " + output);
            Check(fake.Calls == 1, "provisioning was not invoked exactly once");
            Check(File.ReadAllText(destination) == SimulatedBlob, "blob content changed");
            Check(!String.Equals(destination, fake.StagedBlob, StringComparison.OrdinalIgnoreCase),
                "runner received the unprotected final output path");
            CheckPrivateFile(destination);
            CheckCleaned(fake, root);
        }

        private static void ReadOnlyParentAccess(string root)
        {
            string parent = Child(root, "readonly-parent");
            AddRule(parent, new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                FileSystemRights.ReadAndExecute, AccessControlType.Allow);
            string before = DirectorySddl(parent);
            string destination = Path.Combine(parent, "output.txt");
            FakeProvisioner fake = new FakeProvisioner();
            string output;
            Check(OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", destination,
                false, fake.Run, out output) == 0, "read-only parent grant incorrectly blocked: " + output);
            Check(DirectorySddl(parent) == before, "parent ownership or ACL changed");
            CheckPrivateFile(destination);
            CheckCleaned(fake, parent);
        }

        private static void LateCollision(string root)
        {
            string destination = Path.Combine(root, "output.txt");
            FakeProvisioner fake = new FakeProvisioner();
            fake.AfterWrite = delegate { File.WriteAllText(destination, "COMPETING-FILE"); };
            string output;
            int code = OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", destination,
                false, fake.Run, out output);
            Check(code != 0 && fake.Calls == 1, "late collision was accepted or retried");
            Check(File.ReadAllText(destination) == "COMPETING-FILE", "late competing file was replaced");
            Check(Contains(output, "reported successful provisioning"), "successful provisioning outcome lost");
            Check(Contains(output, "already have changed"), "possible AD change was not explained");
            CheckCleaned(fake, root);
        }

        private static void LateAclChange(string root)
        {
            string parent = Child(root, "late-acl");
            string destination = Path.Combine(parent, "output.txt");
            FakeProvisioner fake = new FakeProvisioner();
            fake.AfterWrite = delegate
            {
                AddRule(parent, new SecurityIdentifier(WellKnownSidType.WorldSid, null),
                    FileSystemRights.WriteData, AccessControlType.Allow);
            };
            string output;
            int code = OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", destination,
                false, fake.Run, out output);
            Check(code != 0 && fake.Calls == 1, "late ACL change was ignored or retried");
            Check(!File.Exists(destination), "untrusted output was committed");
            Check(Contains(output, "reported successful provisioning"), "late failure reported as unstarted");
            CheckCleaned(fake, parent);
        }

        private static void MissingResult(string root)
        {
            FakeProvisioner fake = new FakeProvisioner();
            fake.WriteBlob = false;
            string output;
            Check(OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", Path.Combine(root, "output.txt"),
                false, fake.Run, out output) != 0, "empty command result accepted");
            Check(fake.Calls == 1 && Contains(output, "reported successful provisioning"),
                "missing-result outcome was not explained");
            CheckCleaned(fake, root);
        }

        private static void CommandError(string root)
        {
            FakeProvisioner fake = new FakeProvisioner();
            fake.ExitCode = 5;
            fake.WriteBlob = false;
            string destination = Path.Combine(root, "output.txt");
            string output;
            Check(OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", destination,
                false, fake.Run, out output) == 5, "command exit code not preserved");
            Check(fake.Calls == 1 && Contains(output, "was attempted"), "command failure misclassified");
            Check(!File.Exists(destination), "failed command created final output");
            CheckCleaned(fake, root);
        }

        private static void CommandException(string root)
        {
            FakeProvisioner fake = new FakeProvisioner();
            fake.Throw = true;
            string output;
            Check(OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", Path.Combine(root, "output.txt"),
                false, fake.Run, out output) != 0, "command exception accepted");
            Check(fake.Calls == 1 && Contains(output, "outcome is unknown"), "exception outcome misclassified");
            CheckCleaned(fake, root);
        }

        private static void Reject(string destination)
        {
            FakeProvisioner fake = new FakeProvisioner();
            string output;
            int code = OfflineDomainJoinService.ProvisionBlob("example.test", "PC-TEST", destination,
                false, fake.Run, out output);
            Check(code == 3, "expected preflight refusal: " + output);
            Check(fake.Calls == 0, "runner was invoked for rejected output");
            Check(Contains(output, "not started"), "refusal did not explain that no command ran");
        }

        private static void CheckCleaned(FakeProvisioner fake, string outputFolder)
        {
            if (!String.IsNullOrWhiteSpace(fake.StagedBlob))
                Check(!Directory.Exists(Path.GetDirectoryName(fake.StagedBlob)), "private staging was not removed");
            Check(Directory.GetFiles(outputFolder, "*.tmp-*", SearchOption.TopDirectoryOnly).Length == 0,
                "temporary output or capability probe leaked");
        }

        private static void CheckPrivateFile(string path)
        {
            FileSecurity security = File.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access);
            Check(security.AreAccessRulesProtected, "result file inherited ACLs");
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                SecurityIdentifier owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
                Check(owner != null && (owner.Equals(identity.User) || ProtectedStorageAcl.IsTrustedOwner(owner)),
                    "result file owner is untrusted");
                foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                    Check(!OfflineDomainJoinService.IsUntrustedProvisioningBlobAllowRule(
                        rule.IdentityReference as SecurityIdentifier, identity.User, rule.AccessControlType),
                        "result file contains a third-party allow grant");
            }
        }

        private static string Child(string root, string name)
        {
            string child = Path.Combine(root, name);
            Directory.CreateDirectory(child);
            return child;
        }

        private static void AddRule(string path, SecurityIdentifier sid, FileSystemRights rights, AccessControlType type)
        {
            DirectorySecurity security = Directory.GetAccessControl(path);
            security.AddAccessRule(new FileSystemAccessRule(sid, rights, type));
            Directory.SetAccessControl(path, security);
        }

        private static string DirectorySddl(string path)
        {
            return Directory.GetAccessControl(path, AccessControlSections.Owner | AccessControlSections.Access)
                .GetSecurityDescriptorSddlForm(AccessControlSections.Owner | AccessControlSections.Access);
        }

        private static void CreateJunction(string link, string target)
        {
            char[] unsafeChars = new char[] { '"', '&', '|', '<', '>', '^', '%', '!', '\r', '\n' };
            Check(link.IndexOfAny(unsafeChars) < 0 && target.IndexOfAny(unsafeChars) < 0,
                "test paths cannot be represented safely by mklink");
            ProcessStartInfo start = new ProcessStartInfo();
            start.FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            start.Arguments = "/d /c mklink /J \"" + link + "\" \"" + target + "\"";
            start.UseShellExecute = false;
            start.CreateNoWindow = true;
            start.RedirectStandardOutput = true;
            start.RedirectStandardError = true;
            using (Process process = Process.Start(start))
            {
                Check(process != null, "could not start test junction creation");
                if (!process.WaitForExit(10000))
                {
                    try { process.Kill(); } catch { }
                    throw new IOException("test junction creation timed out");
                }
                Check(process.ExitCode == 0, "test junction creation failed: " + process.StandardError.ReadToEnd());
            }
        }

        private static bool Contains(string text, string value)
        {
            return (text ?? String.Empty).IndexOf(value, StringComparison.OrdinalIgnoreCase) >= 0;
        }

        private static void Check(bool condition, string message)
        {
            if (!condition)
                throw new InvalidOperationException(message);
        }
    }
}
