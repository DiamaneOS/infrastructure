# infrastructure

Endpoint contracts and deployment design for DiamaneOS.

## Status (endpoint contract design)

Planned roles only: `config/services.json` selects EU primary, independent
non-EU mirror, and conditional community separation with candidate providers.
No provisioning, no signup, no device result claimed. `deploy/`, `systemd/`,
`tests/` arrive with infrastructure staging. The [operations design](docs/OPERATIONS.md) records
provider evidence, quotas, authority boundaries and activation requirements now.

## Privacy

Never commit: host addresses, account names, tokens, secrets, private keys,
tester data, raw logs. Redact before staging. `.gitignore` is a last guard,
not permission.

## Licence

Original DiamaneOS code, configuration and documentation in this repository
are licensed under [Apache-2.0](LICENSE), except where another licence is
identified. See [NOTICE](NOTICE) for attribution. Referenced upstream software
retains its own licences; this repository's licence does not relicense those works.
