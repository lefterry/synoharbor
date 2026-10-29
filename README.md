# SynoHarbor

Independent SSL certificate and reverse proxy management inside Synology DSM.
English React/TypeScript UI, Go worker, SQLite state and native DSM integration.

**Development preview.** Native installation and end-to-end acceptance are being
validated on a DS918+ with DSM 7.3.2. See [acceptance](docs/acceptance.md) for the
actual verification state; this is not yet a completed v0.1 release.

## Features

- Independent Cloudflare DNS-01 certificates and automatic renewal.
- Certificates, Proxy Hosts, Access Lists, Activity and Settings.
- Create a certificate and optional proxy in the same flow; adopt existing DSM
  certificates without reissuance.
- Native DSM certificates, proxies and SSL service bindings.
- Force SSL, HSTS, WebSockets, custom headers, timeouts, body limits, locations,
  scoped nginx snippets, static asset caching, URI blocking and upstream TLS.
- IP allow/deny plus SHA512-crypt Basic Auth; global native DSM HTTP/2 setting.
- Native change/deletion synchronization and durable retryable deployments.
- Explicit browser-session, administrator and session-bound CSRF validation.

Permanent DNS records and Cloudflare token rotation are outside the scope.

## Build

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

Start in Settings: add a Cloudflare credential, then connect the DSM administrator account and register a SynoHarbor trusted
device with a current OTP. Passwords, tokens and keys remain on the NAS.

Stopping the package leaves the last valid nginx configuration serving traffic.
Renewal requires the worker to run. Uninstall preserves native services and
private state; remove managed services in the app before uninstalling if desired.

## License and provenance

Apache-2.0. Selected DSM authentication, import and ACME patterns are adapted from
[DNSACME](https://github.com/mritd/dnsacme); see [NOTICE](NOTICE). This repository
has independent Git history. No proprietary Synology assets or NPM source are
distributed.
