# Security policy

## Supported versions

The latest public `main` branch and the latest published minor release are supported with security fixes. Older release lines are not maintained unless a release note explicitly says otherwise.

| Version | Supported |
| --- | --- |
| 1.x current minor | yes |
| Older minors | no |

## Reporting a vulnerability

Report suspected vulnerabilities privately through GitHub Security Advisories:

https://github.com/draarivpatel-ui/pypromptcage/security/advisories/new

Do not include real credentials, tokens, cookies, private keys, session data, real personal data, exploit material against a third-party production system, or large prompt-injection corpus files that contain private data. Use synthetic examples only. Redact file paths, account names, hostnames, and exact secret values.

Please include:

- the affected version and runtime
- the smallest input that reproduces the issue
- whether the issue is a detection bypass, resource-consumption problem, incorrect redaction, or incorrect package behavior
- the expected security property and the observed result
- any relevant rule IDs from the report

## Disclosure timeline

The maintainer will try to acknowledge a private report within 14 days, triage severity within 30 days, and coordinate a fix and disclosure date with the reporter. Critical fixes are prioritized over feature work. These are goals, not contractual commitments. After a fix is available, the reporter and maintainer should agree before public disclosure details are published.

## Scope

In scope:

- deterministic resource-limit bypasses in this package
- incorrect redaction that leaves a detected dangerous span intact
- decoding recursion or memory growth beyond documented caps
- regex or parser behavior with superlinear runtime on bounded input
- Unicode canonicalization bugs that hide already-covered attack classes
- package or workflow supply-chain integrity issues

Out of scope:

- the general fact that prompt injection cannot be solved perfectly with deterministic string rules
- attacks requiring control of the host process, dependency cache, package registry account, or repository
- model behavior after text leaves this library
- missing detection for a paraphrase that has no stable syntactic signal
- reports that require real vendor credentials or real personal data to reproduce

## Design constraints for fixes

Security fixes must preserve:

- zero runtime dependencies
- Python 3.9 compatibility unless a major release changes it
- hard-capped input, recursion, decoded-byte, candidate, and finding limits
- deterministic behavior across supported operating systems
- stable rule IDs within a major version
