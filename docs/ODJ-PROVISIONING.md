# Offline Domain Join provisioning: output safety

## 1.6.0 change notes

ODJ provisioning now checks the selected output destination before invoking `djoin.exe`. The GUI and CLI both use this service. The existing protected final commit remains in place; preflight does not replace the final validation.

The new Build regression suite has 15 cases. Provisioning is simulated in every case, while Windows file creation, owner/DACL handling and directory-junction rejection are exercised on the runner. No real domain join, provisioning or Active Directory change is performed by these tests.

## Choosing an output directory

Select an existing directory owned by the current Windows user, LocalSystem or Builtin Administrators. The directory must not grant another identity write/delete/ACL-change capability. Read-only grants on the parent do not by themselves reject the destination; the resulting blob still has its own protected private DACL.

The output must be a new ordinary file. Existing files, directories and reparse-point targets are refused. Device namespace paths, reserved device filenames and alternate data streams are not accepted. The entire existing parent path is checked for reparse-point redirection.

**Compatibility change:** the provisioning service now requires the parent directory to exist before the command starts. It does not create an arbitrary selected parent or take ownership/change permissions of that directory during preflight. Prepare an appropriate private directory separately, then choose a new output name.

Preflight creates a randomly named, non-secret capability probe with the same private file security policy used for the final blob. It writes one byte, flushes it, verifies the owner/DACL through the open file stream and closes the delete-on-close handle. It verifies removal before allowing provisioning. The probe never contains provisioning material and does not reserve the final output name.

Successful preflight cannot guarantee that disk space, ACLs, the output name or the filesystem will remain unchanged. The final protected commit and no-overwrite checks therefore still run after provisioning.

## Identity used by provisioning

The current implementation invokes `djoin.exe` under the current Windows process identity. The main-window domain username/password fields and CLI `--user` do not switch the provisioning helper to another identity. Use a Windows session with the intended permissions. Provisioning does not automatically request local elevation or copy a password to another process.

The `/reuse` option is explicit. It is not an automatic retry or a workaround for an existing-output-file refusal.

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
```

The tests cover invalid tokens, existing file/directory destinations, missing parents, device/stream names, untrusted parent writers, denied file creation, a real directory junction, probe removal and unchanged parent ACLs, valid private output, read-only parent access, post-preflight name/ACL changes, missing output after simulated success, nonzero command results and command exceptions. They also check temporary-file/private-staging cleanup and the absence of automatic retries.

## Scope remaining from issue #44

This change addresses provisioning destination preflight and outcome reporting. The GUI's elevated Apply resume dispatch and interactive cancellation/confirmation regression coverage are not changed by this implementation. Build success is not a live-domain integration test or native ARM64 runtime validation. Release signing and protected-main origin requirements are unchanged.
