# Server deployment boundaries

Upstream provenance is recorded in [UPSTREAM.json](UPSTREAM.json). The upstream MIT license and the Debian adapters' Apache-2.0 license are retained in [LICENSE](LICENSE) and [LICENSES/DiamaneOS-Apache-2.0.txt](LICENSES/DiamaneOS-Apache-2.0.txt).

The Debian adapters sandbox the existing upstream service implementations. Host configuration, SSH targets and credentials are supplied as deployment inputs. No upstream production fleet is selected by default.

Nginx configuration is assembled from the active vhosts and their local includes. Website content, donation assets and signing identities are excluded from source staging. Authoritative DNS and website hosting are separate services.

The inherited Arch installation scripts are outside the Debian deployment path. Use [debian/README.md](debian/README.md) for host, TLS, publication and encrypted-state commands.
