# Debian server deployment

Debian 13 adapters for DiamaneOS’s GrapheneOS-derived network, artifact and
attestation services. These scripts configure hosts and sandbox existing
services; they do not replace the upstream HTTP, SUPL or attestation protocols.

## Supported roles

| Role | Services |
| --- | --- |
| `primary` | Network relays, connectivity checks, HTTPS time and artifact serving |
| `mirror` | Artifact serving |
| `attestation` | Attestation backend and its HTTPS frontend |

Authoritative DNS is external. Website content and a hosted geocoder are outside
this deployment path. The inherited Arch installation scripts are not supported
on Debian.

## Inputs and staging

Keep the `infrastructure`, `network-services`, `releases.diamaneos.de`,
`apps.diamaneos.de` and `AttestationServer` clones together at reviewed revisions.
Keep host inventories, SSH profiles, credentials and signing material outside
these repositories.

```sh
./debian/stage-web-sources /path/to/clones /path/to/new-stage
```

Staging exports committed configuration and records its source revisions.
`host/host.example.json` describes the private `/etc/diamaneos/host.json` input;
replace its deliberately invalid placeholders before use.

## Host and web setup

Verify the host key and a fresh non-root key login first. `host/configure-host`
prepares WireGuard; `host/apply` installs host policy with a timed firewall
rollback. Confirm a fresh connection before cancelling that rollback.

SSH management is restricted to WireGuard. The client must support the
ML-KEM/X25519 hybrid exchange.

Install the staged infrastructure root-owned at `/opt/diamaneos-infrastructure`.
On a new host:

```sh
sudo ./debian/configure-nginx-repository
sudo ./debian/install-nginx
sudo ./debian/install-web-runtime ROLE
./debian/assemble-nginx ROLE /path/to/stage /path/to/new-config
```

Install the assembled configuration, then activate the role firewall and
services. `install-nginx` requires nginx to be stopped; configuration changes retain a
rollback.

Validate and reload nginx through its systemd unit, which runs as the serving
user. A bare root `nginx -t` can leave incorrectly owned PID/cache files.

Primary downloads use `releases.diamaneos.de` and `apps.diamaneos.de`; the mirror
uses `releases-na.diamaneos.de` and `apps-na.diamaneos.de`. Each host obtains its
own ACME certificates and answers its own challenges. Use webroot renewal once
nginx occupies the HTTP port.

## Attestation and publication

Build AttestationServer with Java 25 and strict dependency verification. Deploy
root-owned runtime files under `/opt/attestation/deploy_{a,b}` with the supplied
portable unit and `attestation-debian.conf`.

The application requires its configured encrypted state mount. The service cannot
create a plaintext fallback or administer its storage. SMTP destinations come from
an external root-owned egress configuration; credentials remain in application state.
Backups contain encrypted database state and matching filesystem metadata.

Enrollment is controlled by `service-state.conf`. Attestation verifies the
configured application signer and verified-boot key allowlists.

Release and Apps tooling produces signed artifacts and catalogs separately
from the serving hosts. Publication installs verified files in read-only roots;
release-signing keys are excluded from serving hosts.

## Security boundaries

- Serving accounts cannot write code, configuration, publication data or ACME
  account keys. Nginx has only the low-port binding capability.
- Service sandboxes and UID firewall rules restrict host IPC and outbound access.
  Primary relays share nginx’s UID; attestation has a separate service account.
- Request logs are disabled. TLS-terminating relays process request payloads;
  attestation retains account, device and verification-history state.
- HTTPS time requires authenticated clock readiness. A watchdog failure removes
  its readiness marker and affects only the time endpoint.
- The download hosts have fixed names and publication roots. Canonical DNS
  resolves to primary; regional download names resolve to the mirror.
