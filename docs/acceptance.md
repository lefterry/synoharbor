# Acceptance log

Status: development and live validation in progress (2026-10-29).

- Existing DNSACME authentication prerequisite: fixed in upstream PR #114,
  commit 5fd54c2. Package 1.0.9-18 / UI120 installed on DS918+ after private backup.
  Native-helper authenticated bootstrap/read passed, invalid CSRF and anonymous
  calls were rejected; real anonymous HTTP config request returns 401. Settings,
  trusted device, ACME account key and certificate/key checksums were preserved.
- React/TypeScript checks and production UI build: passed for initial UI.
- Initial Go compile and focused tests: passed for API access denial, encrypted
  restart persistence, edit conflicts, interrupted operations, advanced rules,
  snippet isolation, Basic Auth compatibility and invalid-nginx rollback.
- Full race/vet and final SPK checks: pending latest revision.
- Native SynoHarbor install/browser workflow: pending.
- Four independent profiles and direct-NAS HTTPS migration: pending.
- Live native edits/deletes, renewal/retry, all Advanced settings, restart and
  upgrade/backup preservation: pending.
- ARM64 SPK build planned; live ARM64 validation not claimed.

Initial migration targets:

| Host | Target | Certificate action |
| --- | --- | --- |
| syno.example.net | HTTPS 127.0.0.1:5001 | Adopt existing native certificate |
| kp.syno.example.net | HTTPS 127.0.0.1:51515 | Issue independent certificate |
| plex.syno.example.net | HTTP 127.0.0.1:32400 | Issue independent certificate |
| qbit.syno.example.net | HTTP 127.0.0.1:8095 | Issue independent certificate |

The Kopia upstream requires explicit trust for its self-signed certificate. The
DSM upstream uses its certificate hostname for verification. DNSACME must keep
managing syno until SynoHarbor renewal adoption and deployment are verified.
