# Offline Domain Join provisioning: output safety

## 1.6.0 change notes

ODJ provisioning now checks the selected output destination before invoking `djoin.exe`. The GUI and CLI both use this service. The existing protected final commit remains in place; preflight does not replace the final validation.

The output-preflight Build regression suite has 15 cases. Provisioning is simulated in every case, while Windows file creation, owner/DACL handling and directory-junction rejection are exercised on the runner. No real domain join, provisioning or Active Directory change is performed by these tests.

The GUI now resumes an elevated `odj-apply` directly in Apply mode without reopening the Apply/Provision selector. The ordinary Offline Join button still offers both modes and defaults to Cancel. Apply and Provision require explicit default-No confirmations. Provision displays the current Windows account, domain, computer name, output path and `/reuse` selection before proceeding. A shared, testable GUI controller stops on cancellation and prevents reentrant execution while a workflow is active.

## Choosing an output directory

Select an existing directory owned by the current Windows user, LocalSystem or Builtin Administrators. The directory must not grant another identity write/delete/ACL-change capability. Read-only grants on the parent do not by themselves reject the destination; the resulting blob still has its own protected private DACL.

The output must be a new ordinary file. Existing files, directories and reparse-point targets are refused. Device namespace paths, reserved device filenames and alternate data streams are not accepted. The entire existing parent path is checked for reparse-point redirection.

**Compatibility change:** the provisioning service now requires the parent directory to exist before the command starts. It does not create an arbitrary selected parent or take ownership/change permissions of that directory during preflight. Prepare an appropriate private directory separately, then choose a new output name.

Preflight creates a randomly named, non-secret capability probe with the same private file security policy used for the final blob. It writes one byte, flushes it, verifies the owner/DACL through the open file stream and closes the delete-on-close handle. It verifies removal before allowing provisioning. The probe never contains provisioning material and does not reserve the final output name.

Successful preflight cannot guarantee that disk space, ACLs, the output name or the filesystem will remain unchanged. The final protected commit and no-overwrite checks therefore still run after provisioning.

## Identity used by provisioning

The current implementation invokes `djoin.exe` under the current Windows process identity. The main-window domain username/password fields and CLI `--user` do not switch the provisioning helper to another identity. Use a Windows session with the intended permissions. Provisioning does not automatically request local elevation or copy a password to another process.

The GUI's final confirmation explicitly states that the main-window Domain user and Password fields are not used for this operation. It rechecks the account name after confirmation and stops if it changed or could not be obtained. The confirmed request contains no password. This identity-name consistency check is not a guarantee against every process-level impersonation or filesystem race.

The `/reuse` option is explicit. It is not an automatic retry or a workaround for an existing-output-file refusal. Choosing No in the reuse dialog means provision without `/reuse`; it is not the final authorization to provision. The separate final confirmation defaults to No.

## Reading failures correctly

- **Not started:** input or destination preflight failed, or private staging could not be prepared before the runner was invoked. No provisioning command was issued by this call.
- **Attempted, unsuccessful or unknown:** the runner was invoked but did not report success, or raised an exception. Do not infer that Active Directory is unchanged.
- **Reported success, output finalization failed:** the helper returned success but produced no non-empty blob, or the protected final commit failed. Active Directory may already have changed. Inspect the target computer account before retrying.

The application does not automatically retry provisioning, delete/recreate an AD account, or roll back an AD change. Private staging continues to be cleaned on exit, including output-finalization failures; there is no new persistent recovery copy of the blob in this change.

## Regression tests

Run from the repository root on Windows with the .NET Framework 4.8 targeting pack and MSBuild:

```bat
msbuild Tests\DomainMembershipCheckRepair.OdjPreflight.Tests.csproj /m /t:Rebuild /p:Configuration=Release /p:Platform=AnyCPU
Tests\bin\Release\OdjPreflight\DomainMembershipCheckRepair.OdjPreflight.Tests.exe
msbuild Tests\DomainMembershipCheckRepair.OdjGui.Tests.csproj /m /t:Rebuild /p:Configuration=Release /p:Platform=AnyCPU
Tests\bin\Release\OdjGui\DomainMembershipCheckRepair.OdjGui.Tests.exe --root .
```

The preflight tests cover invalid tokens, existing file/directory destinations, missing parents, device/stream names, untrusted parent writers, denied file creation, a real directory junction, probe removal and unchanged parent ACLs, valid private output, read-only parent access, post-preflight name/ACL changes, missing output after simulated success, nonzero command results and command exceptions. They also check temporary-file/private-staging cleanup and the absence of automatic retries.

The GUI tests execute the same orchestration used by MainForm with simulated dialog results and terminal operations. They cover cancellation at each chooser and confirmation, denied elevation, Apply-only resume, validation failures, identity changes, immutable confirmed requests, safe defaults, reentrant calls and exceptions without automatic retry. Additional source-contract checks verify that MainForm's actual resume case, button wrappers and adapter are wired to this controller. These checks are not real UAC or native dialog automation.

## Scope and validation limits

Issue #44's preflight, GUI resume, identity disclosure and cancellation-regression requirements are implemented in the source. A passing hosted build does not validate an actual UAC/CyberArk handoff, a live-domain provisioning/apply cycle, or native ARM64 execution. Those require a separately authorized Windows lab. The existing x86/x64 GUI/DPI smoke suite remains enabled. Release signing and protected-main origin requirements are unchanged.
