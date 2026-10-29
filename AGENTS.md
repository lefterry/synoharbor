# SynoHarbor

- Read docs/architecture.md before changing native DSM integration.
- Keep browser authentication separate from worker trusted-device credentials.
- Never expose secrets or native API sessions in responses, logs or git.
- Native DSM objects are identified by IDs and certificate fingerprints.
- A failed DSM read is never evidence of deletion. External deletion must not
  trigger recreation or renewal.
- Never edit DSM-generated nginx files. Broker changes only owned extensions.
- Tests: go test -race ./..., go vet ./..., npm run check and npm run build in web.
- Live NAS changes use Faro MCP. Preserve a private backup before migration.
- Do not mark v0.1 complete until docs/acceptance.md records actual results.
