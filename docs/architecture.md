# Architecture

The native DSM AppWindow loads an isolated React application. It calls the
same-origin package CGI with its DSM cookie and a package CSRF HMAC bound to the
verified account/session. DSM authenticate.cgi validates every request; actual
administrator group membership is required. The deployment account's trusted
device is separate from browser authorization.

Go CGI and the worker run as `sc-synoharbor`. SQLite WAL stores versioned objects,
durable operations, successful DSM snapshots and reserved loopback ports.
Credentials are encrypted with AES-GCM using a package-private 0600 master key.
ACME account/certificate files are held in private per-profile storage.

Unsigned DSM 7.3 packages cannot declare root lifecycle privileges at install.
The SPK installs as its package account; the administrator explicitly runs
`scripts/activate` once after installation/upgrade (sudo or DSM Task Scheduler).
Activation copies the checked broker into a root-owned libexec directory and
installs a package-specific systemd dependency/drop-in. DSM starts the
immutable broker with the package; it remains available during uninstall checks
and exits when package INFO disappears; SPK lifecycle scripts stay unprivileged. The UI displays activation status and the exact command.

The root broker listens only on a 0660 Unix socket and checks the connecting
process UID using SO_PEERCRED. It renders typed, validated host configurations;
there is no arbitrary shell or file API. The broker binary in `/usr/local/libexec/synoharbor` and its systemd unit/drop-in
are root-owned and not writable by the package account. DSM may reset package
payload ownership at start; privileged execution never uses that mutable path.

```text
client HTTPS → native DSM proxy/certificate → loopback Advanced listener
                                               → real service IP:port
```

The broker owns only `/usr/local/etc/nginx/sites-enabled/synoharbor.conf` and its
credential/trust files in `/usr/local/etc/synoharbor`. It never edits generated
DSM proxy files or the global nginx configuration. Every change is atomically
written, tested with nginx -t, and gracefully reloaded; failed validation or
reload restores the previous configuration. Pending host edits cannot replace
other hosts' last successfully applied rules.

Native objects are read/written through DSM API adapters. Certificate imports
target stable native IDs; service binding passes the original native service
descriptor and old certificate ID. New proxies point to allocated loopback ports
18080–18999. Access enforcement uses only the X-Real-IP header set by the native
DSM proxy; external forwarded-for chains are not trusted.

Each profile has its own CertMagic cache, credentials, storage and renewal gate.
Issued material is stored before DSM import. Deployment failures remain pending
and retry the stored material. Terminal DSM authentication failures freeze
unattended login attempts and request explicit reauthentication. Deleting a
native certificate stops management; a failed read is never treated as deletion.

Management API route is `api.cgi?route=...`; bootstrap is GET session. Other reads
and writes require X-SynoHarbor-CSRF. Mutations accept application/json only.
Long certificate/proxy tasks return durable operation IDs. Secrets and operation
request payloads never appear in overview or history responses.

When stopped or uninstalled, the native nginx continues serving the last valid
rules. Automatic renewal stops. Keep-services is the default uninstall policy. Full backups live outside package
storage. Explicit scoped native rollback must be reviewed and completed before
choosing restore/erase in Package Center. See recovery.md for checks, before-images,
conflicts and immutable offline recovery.

## Optional standalone access

Settings creates an independently addressed certificate and native DSM proxy for
the full-page UI. The same broker-owned loopback listener forwards only the fixed
package HTML/assets, management CGI and sign-in CGI to the native HTTPS port,
using literal 127.0.0.1 as the internal Host. There is no dependency on the DSM
desktop proxy hostname and no raw `/webapi` route or new management TCP server.
HTTP redirect is enabled only after the new certificate and route verify.
Changing the hostname retains the previous route until explicitly deleted.

Standalone sign-in posts interactive DSM administrator credentials and optional
OTP to a separate public CGI. It never reads the worker password/trusted device
and never registers a browser trusted device. Exact HTTPS Origin checking,
bounded JSON and persistent per-IP/account attempt budgets protect sign-in.
An opaque host-only `__Host-` Secure/HttpOnly/SameSite=Strict cookie references an
encrypted native proof, capped at eight hours. Every protected request validates
that proof through DSM authenticate.cgi and current administrator membership;
the management CGI retains its session-bound CSRF checks. Native SIDs/tokens
never reach the browser. Signout revokes that proof. Backup snapshots exclude
browser sessions, and the UI stops polling when sign-in is required.

This page remains dependent on the NAS nginx, DSM authentication and package
installation. It survives deletion of the separate DSM desktop proxy, not a NAS
or DSM failure. The direct DSM IP/management port and SSH recovery remain useful
fallbacks; direct IP access may show a certificate-name warning.

Every owned HTTPS upstream disables `proxy_ssl_session_reuse`: nginx's implicit
upstream cache is shared by literal address/port across server blocks, independent
of SNI and verification policy. The desktop route and standalone route share the
native HTTPS port with different names/policies. Cross-route session reuse could
otherwise resume the default certificate and intermittently break verified DSM
requests. See [nginx ticket 1340](https://trac.nginx.org/nginx/ticket/1340).
