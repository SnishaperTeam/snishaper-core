# Security Policy

## Supported Versions

We provide security fixes for the actively maintained release lines:

| Version | Supported |
| ------- | --------- |
| Latest v0.x release | ✅ |
| Older v0.x | ❌ — upgrade to the latest release first |

## Reporting a Vulnerability

**Do not open a public issue, pull request, or public Matrix message for
security problems.** Report privately via either channel:

1. **GitHub private vulnerability reporting** (preferred):
   open the repository's **Security** tab and click **Report a vulnerability**
   (<https://github.com/SnishaperTeam/snishaper-core/security/advisories/new>)
2. **Email**: [SniShaper@proton.me](mailto:SniShaper@proton.me)

Include as much of the following as you can:

- Affected version(s) — the module version from `go.mod` or the release tag
- Component or file(s) involved
- Step-by-step reproduction or a proof of concept
- Assessed impact (crash, RCE, privilege escalation, data exposure, ...)

### What to expect

- We aim to acknowledge reports within **72 hours**.
- You will receive status updates while the issue is investigated and fixed.
- Accepted reports are fixed in a patch release and, where applicable,
  published as a GitHub Security Advisory with credit to the reporter
  (anonymous credit on request).
- Please allow time for a coordinated fix and release before any public
  disclosure.

## Scope

- **In scope**: everything in this repository — the proxy engine (ECH
  injection, TLS fragmentation, QUIC connection rebuilding, TUN flow, MITM
  certificate handling), DNS resolution, subscription storage, and the Go
  library API surface consumed by the SniShaper app.
- **App-level vulnerabilities** (GUI, updater, packaging, CI) live in the
  [SniShaper](https://github.com/SnishaperTeam/SniShaper) repository. Report
  them there, or by email — we will route them.
- **Dependency CVEs** in third-party modules are tracked via Dependabot and
  patched in routine dependency updates. Unpatched upstream issues belong to
  the upstream project.
- **Embedder configuration** — functional options can override secure
  defaults (listen address, TLS verification, certificate handling). The
  library documents these trade-offs; vulnerabilities arising from an
  embedder deliberately choosing a weaker option are the embedder's call.

### By design, not a vulnerability

snishaper-core deliberately rewrites, fragments and rebuilds TLS/QUIC traffic
to adapt to network middleboxes. This behavior is the product's intended
function; reports that it "bypasses DPI" or "evades censorship" will be
declined.

## Safe Harbor

We consider good-faith security research to be in the public interest. We
will not pursue legal action against researchers who act with respect for
user privacy and avoid service degradation, data destruction, and data
exposure.
