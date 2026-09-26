# Endpoint operations design

This runbook defines endpoint operations requirements. There is no deployment automation or running infrastructure here yet. Infrastructure staging supplies reproducible host configuration; endpoint owners supply protocol implementations and acceptance evidence. The canonical network contract is `tools:config/endpoints.json`; this repository's [service map](../config/services.json) assigns roles without publishing host addresses or credentials.

## Reviewed provider selection — 2026-09-11

Retain **Hetzner Cloud in Germany** as primary candidate and **1984 Hosting in Iceland** as the independent non-EU mirror candidate. Selection is a planning decision, not an order. Public tariffs and a sized comparison were reviewed on this date; deployment budgeting remains an operator decision. No additional storage product, CDN or community server is selected. Storage Box is not an S3 object origin and is not assumed to be one.

Hetzner's [Cloud capabilities](https://www.hetzner.com/cloud/cost-optimized/) include root-managed VMs, API and firewalls. The page returned unavailable labels for the cost-optimized SKUs during review, so capacity cannot be promised. Use the [current tariff notice](https://docs.hetzner.com/general/infrastructure-and-availability/price-adjustment/) rather than older tariffs. The [terms](https://www.hetzner.com/legal/terms-and-conditions/) put independent backups on the customer; its [backup documentation](https://docs.hetzner.com/cloud/servers/backups-snapshots/overview/) excludes attached volumes from server backups. Neither local snapshots nor the mirror replace source reconstruction and offline custody of signing material.

Hetzner documents [multiple MFA methods and recovery-key/manual recovery](https://docs.hetzner.com/general/security-and-identify/two-factor-authentication/). The documented methods do not establish FIDO2 support or verify any particular account. Infrastructure staging verifies a working primary and independent recovery path before relying on the account.

1984's [VPS tariff](https://management.1984.hosting/product/pricelist/) has disk/traffic tiers suitable for sizing a static mirror. Its [terms](https://1984.hosting/tos/) apply Icelandic law and do not give us a reliable backup guarantee for an unmanaged VPS. Its [dashboard guide](https://management.1984.hosting/knowledge-base/dashboard/) documents email password recovery and service sharing, but only says to enable MFA “if available.” **Public documentation does not establish MFA availability or granular scope of service sharing.** Infrastructure staging must establish both account protection and console/recovery access before approving this candidate for deployment. If unavailable, reject the candidate and review an alternative; do not weaken the access requirement or pretend this research verified a logged-in account.

INWX is the selected registrar/DNS provider; mailbox.org is the selected mailbox provider. INWX [documents DNSSEC signing](https://kb.inwx.com/en-us/3-nameserver/104-can-i-use-dnssec) and [global Anycast DNS](https://www.inwx.de/de/hosting/anycast-dns): a German operator is not a claim that every authoritative query stays in Germany. Keep real account state private. Provider capability documentation does not prove actual account protection or live DNS configuration.

The direct-device Private DNS default is the Swiss [Quad9](https://docs.quad9.net/) service under its [privacy policy](https://www.quad9.net/privacy/policy/). Server-side NTS capability is documented by Swedish [Netnod](https://www.netnod.se/nts/network-time-security); multiple Netnod nodes are one operator. PTB authenticated capability/source diversity and live fresh-device behavior remain the `TIME-SOURCES` implementation gate. No optional resolver was selected without verified availability.

## Portability and reproducibility

The role, authority, capacity, failure and activation requirements in this
document are the portable contract. Named providers are dated candidates, not
dependencies embedded in an implementation. A substitute is acceptable only
when its jurisdiction, recovery path, account separation, quotas, monitoring
and outage behavior are verified against the same contract.

Public automation must accept deployment-specific addresses, account IDs and
credentials as external private inputs. It must not contain a maintainer's
home paths, LAN topology, provider tokens or captured production state. Until
the repository contains provisioning code, tests and an operator runbook, a
reader can reproduce the contract validation but not a live deployment; the
status must continue to say so.

## Authority and deployment boundaries

| Role | Capability | Credentials / reachability |
| --- | --- | --- |
| release-primary | Read-only public serving; narrow fixed-upstream relays; separate staging and publishing processes | Host-scoped release admin, protected operator VPN/SSH; independent provider-console recovery |
| artifact-mirror-non-eu | Static verified artifacts, recovery/site copy and independent monitoring | Different provider account and host-scoped mirror admin; no primary admin credential |
| authoritative-dns | Canonical DNS and probe wildcard records at INWX | Separate DNS administration; no DNS management secret on public serving hosts |
| community-future | Conditional support/federation only, separate VM if ever justified | Separate provider account/project, host, admin identities and backups; no release provider console, VPN peer, DNS write or signing access |

These are identities/authority classes, not actual private usernames. Even if both future VMs use the same vendor, community administrators must have no rights over the release provider project or its recovery account. The management path must work with federation and the community host offline. Provider-console recovery is out-of-band; do not make it depend on a mailbox hosted on the failed VM. No provider token, deployment key or signing key is inherited from a git/CI read credential. Release private keys remain offline.

Within the primary, use separate unprivileged OS users and filesystem ACLs for serving, fixed-egress relays, acquisition/staging, publication and monitoring. Serving identities cannot write publication or access staging/admin credentials. The publisher consumes an explicitly approved verified candidate; it cannot sign a release. A compromise of a public relay may affect availability on this shared host but must not confer publication or signing authority. Apply host aggregate limits of 128 active operations, zero waiting requests, 240 new requests/s and a 4096-entry rate table in addition to endpoint ceilings. Store at most 10 MiB of aggregate service logs per endpoint and 160 MiB in total, expiring at 24 hours; access/header/body/query logs stay disabled. Rate table entries expire within 60 seconds and never become persistent analytics.

The network-location, geocoder and attestation contracts were added 2026-09-26. Network location and attestation are assigned to the primary only so the map covers every hosted contract; both stay blocked. The network-location relay is one of three opt-in choices, with network location off by default (owner decision 2026-09-26); the others connect the device to Apple directly or to Apple's service for China directly and need no host here. The relay forwards Wi-Fi and cell lists to Apple, hides the device IP from Apple and must keep no cache and no per-request logs. DiamaneOS hosts no geocoder for now, so the geocoder contract has no service entry and the validator rejects one: geocoding is off by default, and an opt-in goes directly from the device to OpenStreetMap's public Nominatim within its [usage policy](https://operations.osmfoundation.org/policies/nominatim/). Self-hosting can be revisited if people use it. Attestation is the one stateful service (paired accounts and verification history): it must not run on the read-only release host, and needs its own host role and credentials in this map before activation.

The CLI statically rejects wrong service/host references, mismatched owner tasks, community serving assignments, shared admin identity classes, a missing management path and invalid mirror roles. Infrastructure staging still has to demonstrate actual denied credentials, process isolation, recovery and firewall behavior. A boolean in a JSON document is not runtime proof.

## Network boundary

Expose only the ports required by each implemented service: TLS/HTTPS 443; 80 solely for connectivity probes and deliberately configured certificate validation; SUPL TLS/TCP 7275. DNS is provider-hosted. Do not add arbitrary TCP forwarding or a client-controlled URL fetcher. Unimplemented endpoints are not routed.

Each relay/acquisition worker has a default-deny egress policy. Resolve only the exact `upstreams[].host` and allowed route family for its endpoint. Validate destination after DNS resolution; reject loopback, private, link-local, multicast and reserved destinations on both IPv4 and IPv6. Pin the validated address for the connection while using the allowlisted hostname for TLS/SNI; a re-resolution requires revalidation. HTTP redirects are disabled. Strip userinfo, fragments and unexpected query fields before accepting a route; reject encoded path traversal, duplicate path separators, encoded delimiters and arbitrary absolute URLs. Component path families are not a general proxy: full native path grammar must be frozen under `COMPONENT-BIND` before enabling them. Do not resolve a URL returned in metadata merely because its string starts with an approved hostname.

For upstream HTTPS, construct headers from an allowlist: correct Host and protocol Content-Type; permitted Range/If-Range/If-None-Match only where the pinned protocol uses them. Never forward device User-Agent, Forwarded/X-Forwarded-For, cookies or authorization. RKP request_id and any approved Widevine query fields are protocol data and remain unlogged. PSDS, CT and app acquisition are scheduler-only and do not inherit device headers. Time-source NTS egress is independent of user requests and remains off until the source set is qualified. TLS verification stays enabled; no inherited legacy-cipher exception is copied without its owning compatibility decision.

HTTP quotas return 429 (Retry-After: 60); unavailable/stale service 503; missing immutable object 404; forbidden method 405; oversized body 413; oversized target/header 414/431. Upstream timeout returns 504, malformed/oversized upstream response 502. Buffer small live protocol responses only within their cap before returning success, so truncation is not emitted as a valid complete response. Artifact streaming may terminate mid-transfer but partial bytes must never be promoted or installed without complete verification. SUPL quota/failure closes the stream; it has no HTTP error body. The server does not retry stateful provisioning POSTs. Endpoint-specific behavior takes precedence over generic HTTP handling where the native protocol requires it.

## Cache, activation and recovery

Use one non-overlapping 64 GiB artifact store for OS and app artifacts (both profiles reference this shared ceiling), a 2 GiB component store, a 64 MiB CT store and an 8 MB PSDS store. These are maxima, not promises to populate every byte. Reserve space for the largest allowed temporary transfer, previous verified generation, OS and operational headroom. Begin no provisioning order until a sized disk tier can hold those reservations. Keep at least 20% disk headroom; stop acquisition/promotion before exhausting it, alert, and retain referenced known-good objects. No unbounded queue or automatic storage purchase.

The scheduled acquirer writes a temporary object with bounded bytes/time; verifies source, exact bytes and required signatures; fsyncs file and parent; and exposes an immutable object only after verification. Publish activation metadata by a same-filesystem atomic rename after all referenced objects and proofs exist and match. Publish a CT list/signature pair as one generation; never mix cached versions. Crash/cancel/verification failure cleans incomplete staging on restart and leaves the prior verified generation. Mirror synchronization repeats verification, checks canonical selection independently and never supplies a private signing root. No stale or partial selection is promoted just to make health green.

A no-change upstream check can renew observation freshness only against the already verified object. A local rehash, user cache hit or failed upstream request cannot. The endpoint table defines exactly when to retain old verified state and when to return an error. Long outages do not justify clearing rollback protection, skipping APK/OTA/CT verification, inventing current time or rerouting devices to undisclosed upstreams.

The mirror carries independently published recovery instructions and installer/static content. Independent mirror recovery proves synchronization, outage recovery and first-install verification using an independently obtained trust root; the mirror alone cannot authenticate first install. Monitor the primary from the mirror so primary failure can still be detected. An outage that also takes down canonical DNS needs an independently advertised mirror location and recovery instructions; do not claim that a second VM behind the same domain automatically solves that failure.

## Activation evidence required

Infrastructure staging binds actual addresses, provider accounts, firewall rules, host/process quotas and recovery inputs privately, and validates both JSON documents using the tools CLI with an explicit path. Before exposing an endpoint, its owner closes the relevant `implementation_blockers`, provides native valid/corrupt/oversized fixtures and real timeout/stale/outage results, and records the implementation revision. Service monitoring supplies checks for freshness, TLS/DNS, saturating quotas, restore and independent alerts. Independent mirror recovery covers mirror drills; release signing and publication remain separate responsibilities. Domain management and third-party account changes remain owner actions.

The validator documented in tools `docs/TESTING.md` is implemented. Provisioning and service commands require their corresponding implementations and acceptance evidence.

## Build-host boundary

The online build host synchronizes reviewed source inputs and produces
unsigned build outputs. It uses a dedicated, non-SSH, non-sudo build identity;
routine administration remains a separate key-only account with
password-gated `sudo`. Production signing keys, signer tokens and recovery
material are prohibited on the builder. An output becomes a release candidate
only after the separate verification and offline-signing workflow accepts it.

System package changes occur in an explicit maintenance window, not during a
long or reproducibility-sensitive build. Wake-on-LAN and firmware power-loss
recovery support availability, but neither bypasses authenticated management
or authorizes a build, publication or signing operation.

Treat remote-power mechanisms as independent evidence. A configured NIC is
not a Wake-on-LAN result, a successful magic-packet boot is not an AC-loss
recovery result, and either mechanism still requires post-boot health checks
before a build lease is issued. Allow for the measured firmware and boot
latency rather than declaring failure on an arbitrarily short SSH timeout.
