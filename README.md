<p align="center">
  <img src="web/logo.svg" width="88" height="88" alt="SynoHarbor logo">
</p>

# SynoHarbor

**Your NAS. Your services. One control panel.**

SSL certificates and reverse proxies for Synology DSM, with the familiar workflow
of Nginx Proxy Manager. Give a local service a hostname, issue its Let's Encrypt
certificate and configure its proxy in one place.

SynoHarbor works with **Synology's own certificates and reverse proxy**. Open it
inside DSM or at its own HTTPS address; both views share the same settings. Your
NAS services can stay on your NAS, without depending on a proxy on another server.

**Development preview — not yet a stable v0.1 release.** Live validation currently
covers a DS918+ running DSM 7.3.2. AMD64 and ARM64 packages build, but ARM64 has
not been tested on a NAS. See the [acceptance log](docs/acceptance.md) for verified
results and remaining checks.

## One place to manage your services

| Area | What you can do |
| --- | --- |
| **Certificates** | Issue separate domain or wildcard certificates through Cloudflare DNS-01, enable independent renewal, or adopt an existing DSM certificate. |
| **Proxy Hosts** | Connect a hostname to an IP and port, choose a certificate, and manage HTTPS and routing together. |
| **Access Lists** | Add IP allow/deny rules and Basic Auth, with control over how they combine. |
| **Activity** | Follow certificate issuance, deployment and synchronization, with retry for pending deployments. |
| **Settings** | Manage the DSM connection, Cloudflare credentials, appearance, standalone access and recovery. |

### Familiar proxy controls, native DSM integration

- **HTTPS:** Force SSL, HSTS, WebSockets and certificate assignment.
- **Routing:** custom headers, locations, timeouts and request body limits.
- **Advanced:** static asset caching, common exploit URI blocking and scoped
  nginx snippets, with syntax validation and rollback on failure.
- **Upstream TLS:** certificate verification, server name and explicit trust for
  a selected self-signed certificate.
- **DSM synchronization:** detect native edits and deletions without silently
  recreating objects you removed. Existing objects require explicit adoption.
- **Recovery:** full private backups, settings restore and a reviewed DSM rollback
  workflow before uninstalling.

SynoHarbor uses the NAS nginx with owned loopback extensions; it does not run a
second nginx container. HTTP/2 is shown as a global DSM setting, not a per-host
switch. Read the [architecture](docs/architecture.md) for the integration details.

## Start with a hostname and a local service

For example, route `media.nas.example.net` to `http://127.0.0.1:32400`:

1. Point the hostname at your NAS using your existing DNS setup.
2. In **Settings**, add a Cloudflare credential and connect your DSM administrator
   account, registering a separate trusted device for background certificate work.
3. Choose **New certificate**, enter the hostname and enable **Create a proxy host**.
4. Set the target protocol, address and port, review the changes and deploy.

Cloudflare is used only for the temporary DNS-01 challenges. Permanent DNS records
and token rotation remain under your control. Each new certificate profile covers
one domain or wildcard; issuing multi-domain/SAN certificates is outside this preview.

For full-page access, open **Settings → Standalone access** and enter a hostname
that already resolves to the NAS. SynoHarbor sets up its certificate and proxy.
The DSM app remains available, and both interfaces use DSM administrator
authentication. Browser sign-in and background renewal credentials stay separate.

## Build and install

Requires Go 1.27+, Node 22.12+ and npm. All direct dependencies are pinned.

```sh
cd web
npm ci --ignore-scripts
npm run check
cd ..
go test -race ./...
go vet ./...
sh packaging/build.sh ./build
```

Builds `synoharbor-amd64.spk` and `synoharbor-arm64.spk`. Initial live validation
targets AMD64 only. Install through DSM Package Center, then open SynoHarbor from
the DSM desktop using an administrator session.

DSM 7.3 unsigned packages need a one-time administrator activation after each
install/upgrade. Run this as root via SSH or DSM Task Scheduler:

```sh
/var/packages/synoharbor/scripts/activate
```

The CGI and worker remain unprivileged. Only the restricted broker runs as root.
Settings shows whether activation is complete.

The interface uses React and TypeScript; the backend is Go with SQLite storage.
Passwords, tokens and private keys remain in private storage on the NAS.

## Recovery and lifecycle

Stopping the package leaves the last valid nginx configuration serving traffic.
Renewal requires the worker to run. Uninstall defaults to keeping services and
settings. Settings → Backup & Recovery previews a scoped DSM restore before the
other uninstall choices become available. Full private backups survive removal;
see [recovery and uninstall](docs/recovery.md).

## License and provenance

Apache-2.0. Selected DSM authentication, import and ACME patterns are adapted from
[DNSACME](https://github.com/mritd/dnsacme); see [NOTICE](NOTICE). This repository
has independent Git history. Inspired by the workflow of
[Nginx Proxy Manager](https://github.com/NginxProxyManager/nginx-proxy-manager),
with no NPM source or branding included. SynoHarbor is an independent community
project, not affiliated with Synology, DNSACME or Nginx Proxy Manager. No
proprietary Synology assets are distributed.
