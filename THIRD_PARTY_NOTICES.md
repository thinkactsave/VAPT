# Third-party notices

ProofVAPT packages and runs third-party scanner tools. Versions are pinned in the Dockerfile and should be reviewed before changing.

- **ffuf 2.3.0** — https://github.com/ffuf/ffuf — MIT license. The upstream release archive is downloaded during the Docker build and verified against its published SHA-256 checksum. The matching upstream license notice is retained under `bin/LICENSE`.
- **OWASP ZAP 2.17.0** — https://github.com/zaproxy/zaproxy — Apache License 2.0. The Linux release archive is downloaded during the Docker build and verified against the checksum published by the ZAP project.
- **OWASP Juice Shop 20.3.0** — https://github.com/juice-shop/juice-shop — intentionally vulnerable training target; container is used only for lab benchmarking and is not published to the host.

The frontend dependencies are listed in `package.json`. Review the license terms of those packages before redistributing a modified build.
