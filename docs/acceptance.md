# Acceptance log

Status: development preview, validated on DS918+ / DSM 7.3.2-86009 Update 5,
2026-10-29, installed preview 0.1.0-16. AMD64 live; ARM64 builds only. Do not interpret this log as live
coverage of every DSM model or a completed stable v0.1 release.

## Passed

- Authentication prerequisite fixed in DNSACME PR #114 (5fd54c2, 6844d62),
  package 1.0.9-19 / UI121. Anonymous config returns 401. Original settings,
  trusted device, ACME account and certificate/key checksums survived upgrade.
- Independent repository/history, React/TypeScript production build,
  light/dark UI, native DSM AppWindow and transparent native icons.
- Full Go race tests, vet, TypeScript check and native-token → package CSRF API
  client checks. Management routes, including backup/restore, reject anonymous,
  non-admin and invalid/missing CSRF before dispatch in the denial matrix.
- Real native-token CGI bootstrap and authenticated overview as package user
  passed using SynoHarbor's own trusted device. Real anonymous and invalid-CSRF
  overview/backups/recovery reads were rejected. No credentials were emitted.
- Fresh independent production certificates for DSM, Plex and qBittorrent.
  Root certificate replaced with a fresh key/profile/native ID, SSL assignments
  and system default transferred, old unused native object removed. DNSACME
  stopped only after the new routes were verified.
- Three HTTPS services directly on NAS: DSM 200, Plex /web/index.html 200,
  qBittorrent 200, all with successful certificate verification. HTTP → HTTPS
  returned 308. No Ubuntu NPM dependency is used for these probes.
- Real temporary loopback-only nginx validation passed: Basic Auth, IP all/any,
  Authorization stripping/forwarding, HSTS with custom response headers, custom
  locations, URI blocking, invalid-config rollback including auth-file ownership,
  static cache hits and cookie bypass, Force SSL, WebSockets, body-size limit and
  explicitly trusted upstream TLS. Test cleanup restored the production bundle.
  DSM's global buffering-off default required an explicit cache-location override.
- Complete private backup restored into an isolated NAS directory; SQLite
  integrity, credential decryption, all three profiles/hosts and the credential
  were verified.
- After explicit user approval, a fresh current-state backup was restored through
  the protected endpoint used by the DSM UI. Native proxy/certificate inventory
  and IDs were preserved, the worker restarted and native authorization passed.
  During that restore, 120 direct HTTPS probes across the three URLs had zero
  failures and zero certificate verification failures.
- Upgrades to the installed preview preserved the encryption key and settings.
  The broker binary is root-owned outside mutable package payloads. CGI/worker
  remain package-user processes; payload and activation hashes were checked.
- Recovery tests cover shared certificates, unrelated native objects, stale
  confirmation, external edits, interrupted rollback/resume, invalid archives,
  traversal/links, failed native reads and old backups without ownership records.
  Failed rollback cannot authorize private-data erasure. A native alias sharing
  a managed loopback listener blocks app deletion and retains its access rules
  if the original native proxy disappears; final dependency removal retires it.
- Token/password metadata and encrypted values commit atomically. Rejected stale
  credential edits cannot alter the current token.
- Local browser inspection verified contextual help and a closeable recovery
  preview with typed confirmation. Native permanent DNS records were untouched.

## Remaining validation before a stable v0.1 label

- Force renewal / simulated native import failure and retry without reissuance
  across multiple concurrently active profiles; existing storage and deployment
  paths are implemented, but no expiry-cycle claim is made from today's issuance.
- Full on-device native rollback + Package Center uninstall/reinstall/erase
  matrix. Real private settings recovery passed; native rollback/erase safety has
  fixture coverage and fresh-state guards. Production routes were not intentionally
  removed for an uninstall test.
- Broader native edits/deletion coverage and global HTTP/2 toggle/restore on the
  live NAS. Native HTTP/2 state was read successfully; actual changes affect all
  NAS web services and were not toggled for this check.
- Live ARM64 and additional DSM models/versions.

## Validated service roles

Deployment hostnames and custom management ports are omitted from this public-facing
log. These are roles from the live test deployment, not bundled application defaults.

| Service | Target type | State |
| --- | --- | --- |
| DSM desktop | Local native HTTPS management endpoint | Ready; new SynoHarbor certificate |
| Media service | Local HTTP upstream | Ready |
| Torrent service | Local HTTP upstream | Ready |
| SynoHarbor standalone | Fixed local package paths through native HTTPS | Ready; independent certificate and proxy |

## Standalone access validation (2026-10-29)

- Fresh production certificate and native proxy for the standalone hostname
  deployed through the shared Settings/CLI service workflow. Four HTTPS routes
  returned 200 with successful TLS verification; standalone HTTP returned 308.
  No permanent DNS records were changed.
- Real package-user integration through the new public hostname passed: fixed
  package routing, raw native `/webapi` 404, anonymous management 401, opaque
  browser-session lookup, actual native administrator validation, authenticated
  overview, missing CSRF 403 and signout followed by session rejection. The test
  used an isolated temporary native proof; no human password or OTP was collected.
- Interactive login contract tests verify user-supplied credentials/OTP only,
  no worker trusted-device reuse, no new device registration, current role checks,
  expiry and forged/duplicate cookie rejection. Persistent rate budget and exact
  HTTPS Origin checks passed. Browser sessions are excluded from private backups.
- Retry reuses certificate/proxy IDs; a new hostname preserves previous access;
  failed native reads cannot create resources. The management renderer rejects
  arbitrary targets and forwards only package paths.
- Local WebKit visual checks covered Settings and the sign-in form. The user also confirmed successful interactive DSM administrator/OTP login and
  the Certificates list.

## Standalone/DSM TLS regression and upgrade repair

The new standalone route initially exposed an nginx upstream-session collision:
both routes used the same local native HTTPS endpoint with different
SNI/verification policies.
Some DSM requests resumed the default certificate and returned 502, leaving a
partially loaded desktop. Verification was kept enabled. Owned HTTPS upstreams
now disable session reuse; the permanent fix is installed in preview 0.1.0-16.
After deployment, 50 alternating standalone/DSM HTTPS requests passed with zero
upstream or certificate failures. All four services and a DSM application asset
returned 200 with successful TLS verification. The user confirmed the standalone
interactive login before this regression was reported.

The old preupgrade tar also raced active browser CGI writes and aborted safely.
The corrected package replaces live-directory tar with the existing consistent
full-backup workflow. A brief package CGI maintenance window let the old script
finish without editing installed lifecycle scripts. Upgrade completed, the
private encryption key checksum matched, and the worker is running.

## Shared Settings interface refinement

- Settings is organized into General, DSM connection, Cloudflare, Standalone
  access and Backup & recovery. Readable labels, descriptions and consistent
  spacing replace the mixed-size card grid. Configured standalone access shows
  an address/status summary; editing opens explicitly and Cancel discards drafts.
- Local browser checks passed in light/dark themes at desktop and narrow
  viewports. Category keyboard navigation, connection-dialog access, theme save,
  older backup visibility and both typed restore guards were checked with mock
  data. No live restore or credential mutation was performed for this UI change.
- Shared frontend files were backed up and deployed without restarting services.
  Backend binary and owned nginx configuration checksums were unchanged. The DSM
  package path and standalone path returned identical HTML/JavaScript checksums.
  All four service URLs returned 200 with valid TLS; anonymous management remains
  401. The shared HTML also declares the existing SVG logo as its tab favicon.
