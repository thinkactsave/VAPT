# Security policy

## Supported use

ProofVAPT is designed for authorized web-application testing and isolated lab training. Only assess targets for which you have written permission and an agreed scope.

## Reporting a vulnerability in ProofVAPT

Do not publish API tokens, production URLs, customer data, scan artifacts, or exploit details that could affect a third party in a public issue. Contact the repository maintainer through a private channel first and include a minimal reproduction, affected commit, expected impact, and any relevant logs with secrets redacted.

## Operator deployment checklist

- Run behind HTTPS and restrict inbound traffic to the intended operators.
- Set a strong `PROOFVAPT_API_TOKEN` in your secret manager.
- Use persistent storage with access limited to the application operator.
- Do not mount unrelated host directories into the scanner container.
- Keep Juice Shop isolated; it is intentionally vulnerable and must not be published to the internet.
- Limit outbound network access at the infrastructure layer where possible. The application-level proxy is not a substitute for network isolation.
- Back up runtime findings before upgrades. Do not commit runtime data or secrets.
- Do not treat an automated report as a replacement for manual testing or authorization review.
