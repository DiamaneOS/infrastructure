# Debian server deployment

Debian 13 adapters for DiamaneOS’s GrapheneOS-derived network, artifact and
attestation services. These scripts configure hosts and sandbox existing
services. They do not replace the upstream HTTP, SUPL or attestation protocols.

## Supported roles

| Role | Services |
| --- | --- |
| `primary` | Network relays, connectivity checks, HTTPS time and artifact serving |
| `mirror` | Artifact serving and the status page |
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
`host/host.example.json` describes the private `/etc/diamaneos/host.json` input.
Replace its deliberately invalid placeholders before use.

## Host and web setup

Verify the host key and a fresh non-root key login first. `host/configure-host`
prepares WireGuard. `host/apply` installs host policy with a timed firewall
rollback. Confirm a fresh connection before cancelling that rollback.

SSH management is restricted to WireGuard. The client must support the
ML-KEM/X25519 hybrid exchange.

Host policy configures volatile journald storage with `RuntimeMaxUse=160M` and
`MaxRetentionSec=1day` with a new file every hour (`MaxFileSec=1h`, since
journald deletes whole files), and disables syslog forwarding.
The final `zz-diamaneos.conf` drop-in overrides vendor `syslog.conf` and
`99-syslog.conf`. `host/apply` verifies the merged policy, masks the syslog
socket, rsyslog, syslog-ng and its discovered instances. These receivers must be
stopped with no pending jobs or remaining conventional syslog daemon processes
before restarting journald. Conflicts with the four checked journal settings or
unsuccessful stops fail deployment. Existing persistent logs are preserved.
Inspect their metadata and handle any removal separately.
These controls do not set retention for application state or package-manager logs.

A host can keep its system journal on disk instead: `system_journal` set to
`persistent` in `host.json`. `configure-logging` then writes
`zzz-diamaneos-persistent.conf` (`Storage=persistent`, `SystemMaxUse=2G`,
`MaxRetentionSec=14day`, a new file every day), so the cause of a restart can
be read after it. It removes that file on a host without the setting. Service
journal namespaces stay volatile on every host: `journald@attestation.conf`
has the volatile policy above and `configure-logging` checks it. The
attestation service logs to that namespace (`LogNamespace=attestation` in
`attestation-debian.conf`), so its output never reaches the disk. Run
`journalctl --flush` after the switch so journald writes to `/var/log/journal`.

Install the staged infrastructure root-owned at `/opt/diamaneos-infrastructure`.
On a new host:

```sh
sudo ./debian/configure-nginx-repository
sudo ./debian/install-nginx
sudo ./debian/install-web-runtime ROLE
./debian/assemble-nginx ROLE /path/to/stage /path/to/new-config
```

Install the assembled configuration, then activate the role firewall and
services. `install-nginx` requires nginx to be stopped. Configuration changes retain a
rollback.

Validate and reload nginx through its systemd unit, which runs as the serving
user. A bare root `nginx -t` can leave incorrectly owned PID/cache files.

The primary configuration accepts an optional local `website.conf` include.
Website content, its certificate and contact handler are supplied by the
website deployment. This repository does not stage them. The website deployment
also supplies the web installer at `/install/web/` and its headers.

`mta-sts.diamaneos.de` serves the MTA-STS policy for mail to diamaneos.de
(`mta-sts/mta-sts.conf`, RFC 8461) with its own `diamaneos-mta-sts`
certificate. Every other path answers 404. Its first certificate works the same
way, with `--before-mta-sts-certificate`. A changed policy needs a new `id` in
the `_mta-sts` TXT record.

Primary downloads use `releases.diamaneos.de` and `apps.diamaneos.de`. The mirror
uses `releases-na.diamaneos.de` and `apps-na.diamaneos.de`. Each host obtains its
own ACME certificates and answers its own challenges. Use webroot renewal once
nginx occupies the HTTP port.

The primary's download names can have their own address, so a flood on them
leaves the other services' address alone. List it in `download_addresses` in
`host.json` (one IPv4 and at most one IPv6 address). `configure-host` adds it to
the interface and a networkd drop-in, without reconfiguring the link. An empty
list removes them. Without the field they are left as they are.
`assemble-nginx primary` reads the same field from `/etc/diamaneos/host.json`
(run it as root, or pass `--host-json PATH`): releases and apps then also answer
there, and every other name and SUPL closes the connection there. Once DNS points
the download names at their address, set `downloads_moved` to `true`, so they no
longer answer on the shared address of that family. `--download-address` and
`--downloads-moved` give the same settings without host.json and must agree with it.

A monitoring host's health collector can reach a host over WireGuard as a
restricted peer. `health_peer` in `host.json` lists its `name`, `public_key`,
tunnel `address`, the `tcp_ports` it may reach and the `reporter` account it may
log in as. `configure-host` adds the peer to `wg-mgmt.conf`, a rule for those
ports to the management firewall, the account to `AllowUsers`, and
`sshd_config.d/01-diamaneos-health.conf`: from the peer's address only the
reporter may log in, with a forced command and no forwarding. The reporter
account and its key restriction come from the monitoring deployment.

The monitoring host itself lists `health_collector`: its `reporter` and the
`peers` it dials, each with `name`, `public_key`, tunnel `address`, `endpoint`
(HOST:PORT) and `keepalive`. `configure-host` adds those peers to `wg-mgmt.conf`
and writes the same SSH files, with the host's own tunnel address, so the
collector can check this host too. These peers get no firewall rule, only their
replies come back. A host has one of the two fields. Without either the
reporter's SSH file is left as it is.

`unlock_peer` lets one phone reach SSH over WireGuard to run a single command,
such as unlocking encrypted state after a restart. It lists the peer's `name`,
`public_key` and tunnel `address`, the `account` it logs in as, the SSH
`key_algorithm` of its key and the forced `command` (a program in
`/usr/local/sbin`). `configure-host` adds the peer and its SSH rule, the account
to `AllowUsers` and `sshd_config.d/02-diamaneos-unlock.conf`: from the peer's
address only that account may log in, with a terminal, the forced command, one
session, no forwarding and keys from
`/etc/diamaneos/ACCOUNT.authorized_keys`. Without the field that file is
removed. The account, its key and its sudo rule come from the private
deployment.

The mirror also serves the unlisted `status.diamaneos.de` from
`/var/lib/diamaneos-status-page`. A separate monitoring deployment writes that
page and the heartbeat `mirror.diamaneos.de/monitor-heartbeat`, the time of
its last completed run, which the primary's monitor checks. This repository
does not stage them. Before the `diamaneos-status`
certificate exists, assemble with `--before-status-certificate` so only its
HTTP server is live. Request the certificate, then assemble and install again
without the option.

## Attestation and publication

Build AttestationServer with Java 25 and strict dependency verification. Deploy
root-owned runtime files under `/opt/attestation/deploy_{a,b}` with the supplied
portable unit and `attestation-debian.conf`.

The application requires its configured encrypted state mount. The service cannot
create a plaintext fallback or administer its storage. SMTP destinations come from
an external root-owned egress configuration. Credentials remain in application state.
Backups contain encrypted database state and matching filesystem metadata.

Enrollment is controlled by `service-state.conf`. Attestation verifies the
configured application signer and verified-boot key allowlists.

Release and Apps tooling produces signed artifacts and catalogs separately
from the serving hosts. Publication installs verified files in read-only roots.
Release-signing keys are excluded from serving hosts.

## Security boundaries

- Serving accounts cannot write code, configuration, publication data or ACME
  account keys. Nginx has only the low-port binding capability.
- Service sandboxes and UID firewall rules restrict host IPC and outbound access.
  Primary relays share nginx’s UID. Attestation has a separate service account.
- The role firewall allows each IPv4 address or IPv6 /64 32 connections to the
  web ports, and to SUPL on the primary. Further connections get a TCP reset.
  New connections above `nf_conntrack_max`/64 per second go through synproxy.
  Both follow GrapheneOS's network firewall, as do the conntrack and TCP timeouts.
- Management WireGuard packets are not connection-tracked. `bandwidth_mbit` in
  `host.json` sets CAKE at 99.75 % of the provisioned rate.
- Request logs are disabled. TLS-terminating relays process request payloads.
  Attestation retains account, device and verification-history state.
- HTTPS time requires authenticated clock readiness. A watchdog failure removes
  its readiness marker and affects only the time endpoint.
- The download hosts have fixed names and publication roots. Canonical DNS
  resolves to primary. Regional download names resolve to the mirror.
