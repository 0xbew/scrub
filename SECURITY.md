# Security policy

scrub exists to keep secrets and identities from leaving a machine, so a way past it is a security bug:
a credential, token, address, phone number or denylisted name that comes out of `Scrub` or `ScrubDiff`, a
credential or token that comes out of `Redact`, or any of these that `Audit` / `AuditBody` passes.

## Reporting

Report it privately through GitHub's **Report a vulnerability** button on this repository's Security
tab. Please do not open a public issue or pull request for it. If that button is not there, open an issue
that says only that you have a security report and asks for a private contact, with no details.

Send the smallest input that shows it, with a made-up value in place of any real secret. Never send a
real credential.

## What happens next

- We acknowledge every report within **7 days**.
- We confirm or rule out the bug, and tell you which, as soon as we can.
- A confirmed bug is fixed in a new release, and the advisory credits you unless you ask us not to.

## Scope

In scope: anything the README lists under "What it guarantees" that does not hold.

Out of scope: the limits the README lists under "What it does not do" (for example base64 or gzip
payloads, look-alike letters other than fullwidth forms, or a plain word after a name that is not a
credential's). Reports that one of these matters in practice are welcome as ordinary issues.

Supported versions: the latest release only.
