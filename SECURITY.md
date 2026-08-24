# Security policy

## Supported versions

Before the first tagged release, security fixes target `main`. After releases begin, fixes target `main` and the latest released version. Older releases are not supported unless a security advisory states otherwise.

## Reporting a vulnerability

Do not open a public issue or discussion containing vulnerability details.

Use GitHub Private Vulnerability Reporting:

<https://github.com/Sukitly/gitveil/security/advisories/new>

If the private reporting form is unavailable, open a public issue with no technical details and request a private contact channel. Do not include secret values, private identities, decrypted files, exploit payloads, repository URLs, or other sensitive material in that issue.

A useful private report includes:

- The affected Gitveil version or commit.
- The operating system and architecture.
- The security boundary that was crossed.
- Minimal reproduction steps using generated test identities and non-sensitive canaries.
- Expected and observed behavior.
- Whether the issue is already public or known to another project.

Please allow time for confirmation, impact assessment, remediation, and coordinated disclosure. Gitveil does not promise a fixed response or release timeline.

## Security-sensitive areas

Reports are especially valuable when they involve:

- Plaintext, private identity, or decrypted comment disclosure through output, argv, temporary files, baselines, Git state, or release artifacts.
- Workspace escape through path handling, symlinks, submodules, case folding, or filesystem races.
- Unauthorized decryption after recipient removal or incorrect recipient-policy enforcement.
- Failure to rotate the data key when a recipient is removed.
- Modification of the Git index, configuration, hooks, attributes, or state outside `.git/gitveil/`.
- SOPS or age-keygen sidecar substitution, checksum bypass, version confusion, or repository configuration injection.
- Identity generation that overwrites an existing path, leaves partial private material, uses unsafe permissions, or reveals a private identity.
- Local IPC authentication, permissions, process cleanup, or lock isolation failures.
- Ciphertext integrity, MAC, merge, or rollback behavior that can expose or silently replace secret data.

Vulnerabilities in upstream SOPS or age should normally be reported to those projects. If Gitveil's integration makes an upstream issue exploitable in a Gitveil-specific way, report it privately to Gitveil as well.
