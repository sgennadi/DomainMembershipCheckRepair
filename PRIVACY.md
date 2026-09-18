# Privacy Policy

Effective date: 2026-09-18

DomainMembershipCheckRepair is an open-source Windows utility for diagnosing and repairing Active Directory domain membership. This policy describes what the application does with information while it is running.

## Summary

DomainMembershipCheckRepair does **not** send telemetry, analytics, usage statistics, crash reports, advertising identifiers, or entered credentials to the project maintainer.

The program communicates with networked systems only when required for an action explicitly initiated by the operator, such as discovering a domain controller, checking or repairing a secure channel, looking up an Active Directory computer account, joining or rejoining a domain, or performing another requested domain operation.

## Credentials

The application can ask for Active Directory credentials when an operation requires them.

- Passwords are never accepted as command-line arguments.
- Entered passwords are not written to the application log.
- Entered passwords are not stored in the Windows Registry, configuration files, or other persistent application settings.
- Entered usernames are not intentionally persisted by the application.
- Credentials are used only for the requested operation and remain in process memory only for as long as needed by the running application and Windows APIs.

Operators should use accounts with only the permissions required for the requested task.

## Network communications

Depending on the requested operation, the application may communicate with infrastructure such as:

- Active Directory domain controllers
- DNS services
- LDAP / Active Directory services
- Windows Netlogon and domain-join services

These communications are necessary to perform the operator's requested domain-management task. The project does not operate a backend service and the application does not send this information to the maintainer.

The project itself does not include analytics, telemetry, advertising, or remote tracking code.

## Local logging

Application file logging is **disabled by default** and is not remembered between runs.

If the operator explicitly enables file logging, the application can write to:

```text
C:\Windows\Logs\DomainMembershipRepair.log
```

The application does not intentionally record entered passwords in this log.

Windows itself may also maintain operating-system logs related to domain operations, including:

```text
C:\Windows\Debug\NetSetup.log
```

Those Windows logs are produced by the operating system and are outside the direct control of DomainMembershipCheckRepair.

## Diagnostic exports

The operator can explicitly export a diagnostic ZIP package. Depending on availability and the options selected, it may contain:

- `diagnostics.txt`
- `diagnostics.json`
- `NetSetup.log`
- the optional application log, but only when explicitly requested

The generated diagnostic report does not intentionally include the entered domain username or password. Windows logs or environment-specific diagnostic data may still contain machine names, domain names, server names, paths, IP addresses, account identifiers, or other administrative information.

Diagnostic packages are created locally. The application does not automatically upload or transmit them anywhere.

Operators should review diagnostic files before sharing them.

## Active Directory data

Read-only account checks may retrieve Active Directory computer-object properties required for display or troubleshooting, such as:

- computer name
- distinguished name
- DNS host name
- enabled/disabled state
- operating system description
- object GUID
- created/modified timestamps

This information is queried from the operator's own Active Directory environment and is not transmitted to the project maintainer.

## Data retention

The project maintainer does not receive application telemetry or user data from the application and therefore does not maintain an application-side retention database.

Locally generated files remain on the operator's computer until the operator or system administrator deletes them. This can include optional application logs and exported diagnostic ZIP files.

## Third-party services

The application itself does not depend on a project-operated cloud service.

The source code and releases are hosted on GitHub. Release code signing may be performed through SignPath.io / SignPath Foundation as part of the project's build and release pipeline. Use of the GitHub or SignPath websites is governed by those services' own privacy policies.

The end-user application does not contact SignPath as part of normal runtime operation.

## Security and destructive operations

Some operations can modify the local computer or Active Directory. Such operations are initiated explicitly by the operator.

Deletion of an Active Directory computer object requires explicit confirmation and performs identity checks immediately before deletion. This behavior is described in the project's documentation and is not performed silently.

## Children

This software is an administrative utility intended for system administration. It is not designed to collect personal information from children.

## Changes to this policy

Material changes to this policy will be committed to the public repository so that the policy history remains visible through Git.

## Contact

Project repository:

https://github.com/sgennadi/DomainMembershipCheckRepair

For privacy questions, use the repository's GitHub issue tracker without posting passwords, access tokens, recovery keys, or other secrets.

For security vulnerabilities, follow:

https://github.com/sgennadi/DomainMembershipCheckRepair/blob/main/SECURITY.md
