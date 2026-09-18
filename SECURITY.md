# Security Policy

## Supported versions

Security fixes are applied to the latest published release.

## Reporting a vulnerability

Please use GitHub's private security advisory feature for this repository rather than opening a public issue with exploit details.

When reporting a problem, include:

- the affected release and architecture;
- Windows version;
- the operation involved (trust repair, join/rejoin, AD lookup, rename, or deletion);
- steps to reproduce;
- whether the issue could expose credentials, delete the wrong AD object, or modify domain membership unexpectedly.

Do not include real passwords, recovery keys, or other secrets in a report.

## Credential handling

DomainMembershipCheckRepair intentionally does not persist entered domain usernames or passwords. Passwords are not accepted as CLI arguments. File logging is disabled by default.

## Destructive AD operations

Deleting an Active Directory computer object is destructive and always requires explicit confirmation. The program re-reads the object and verifies its class, sAMAccountName, and object GUID immediately before deletion.
