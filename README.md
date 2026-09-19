# infrastructure

Endpoint contracts and deployment design for DiamaneOS.

## Status (endpoint contract design)

Planned roles only: `config/services.json` selects EU primary, independent
non-EU mirror, and conditional community separation with candidate providers.
No provisioning, no signup, no device result claimed. `deploy/`, `systemd/`,
`tests/` arrive with infrastructure staging. The [operations design](docs/OPERATIONS.md) records
provider evidence, quotas, authority boundaries and activation requirements now.

The contracts are provider-neutral even though the current design records
dated provider candidates. Another operator may substitute infrastructure that
meets the same jurisdiction, authority separation, recovery, capacity and
monitoring requirements. This repository does not yet claim a reproducible
live deployment because it contains no provisioning implementation.

Validate the standalone JSON syntax with Python:

```sh
python3 -m json.tool config/services.json >/dev/null
```

For cross-repository validation, check out `diamaneos-tools` beside this
repository under any chosen `WORK_ROOT`, prepare its documented development
environment, and run:

```sh
"$WORK_ROOT/tools/bin/diamaneos" endpoints validate \
  --services "$WORK_ROOT/infrastructure/config/services.json"
```

## Privacy

Never commit: host addresses, account names, tokens, secrets, private keys,
tester data, raw logs. Redact before staging. `.gitignore` is a last guard,
not permission.

## Licence

Original DiamaneOS code, configuration and documentation in this repository
are licensed under [Apache-2.0](LICENSE), except where another licence is
identified. See [NOTICE](NOTICE) for attribution. Referenced upstream software
retains its own licences; this repository's licence does not relicense those works.
