# Staging configuration

The renderer assembles the existing mirror or attestation configuration, then
maps allowlisted hostname, certificate, include and serving-root directives.
Unknown bindings and remaining production references refuse output.

`web` serves the website, Releases and Apps from separate read-only publication
roots beneath `/srv/diamaneos-staging`. Contact submission returns 503. No backend
or mail service is connected. `--with-attestation` also renders a closed-response
frontend for `attestation.staging.diamaneos.de`. Its DNS records and the certificate
must then name it too. Noindex headers apply to the configuration; website robots
disallow crawling.

`attestation-disabled` is a separate configuration. Every HTTPS request returns
503; its backend definition remains loopback-only. Runtime activation requires a
separate service account, isolated encrypted state and explicit application trust
configuration supplied outside the renderer.

The staging crawler policy merges into nested responses. Request logs remain
disabled, and unknown hosts retain the inherited refusal behavior.

All names use the `diamaneos-staging` certificate lineage. HTTP serves challenges
from `/srv/diamaneos-staging/acme`. The renderer writes only a fresh local output
directory; it does not install dependencies, obtain certificates or start services.

```sh
python3 debian/staging/render.py web SOURCE OUTPUT --website-headers WEBSITE_HEADERS [--with-attestation]
python3 debian/staging/render.py attestation-disabled SOURCE SEPARATE_OUTPUT
python3 -B -m unittest discover -s debian/staging -p 'test_*.py'
```

`SOURCE` is an export produced by `debian/stage-web-sources`. Website headers come
from the website source. `rendered.json` records input and output hashes. Validate
the generated configuration through the serving service before activation.

Use root-owned publication directories with serving accounts limited to reading.
Keep credentials, certificates and application state separate from production.
The two configuration entry points remain separate; combining host roles is not
supported by this renderer.
