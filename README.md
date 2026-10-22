# ProofVAPT

ProofVAPT is a single-operator web application assessment workbench. It combines a React/Vite interface with an Express API, scoped HTTP proxy, `ffuf`, OWASP ZAP Automation Framework, evidence records, and a Juice Shop benchmark.

The project is an assessment tool, not a certification that a target is secure. Test only assets for which you have explicit authorization. Active scans can send traffic to a target and should be run against a known scope with conservative limits.

## What's included

- A React interface for target registration, scan stages, findings, endpoints, verification, and reports.
- Server-side target/port validation and an egress proxy with exact-host scope checks.
- Scan request/rate budgets and one-at-a-time worker execution.
- Target-specific Juice Shop metrics; comparative metrics remain undefined until measured baseline data is supplied.
- A Docker image with pinned versions of ffuf and OWASP ZAP, plus a private Juice Shop service for lab assessments.
- CI checks for TypeScript, safety-policy unit tests, and a production build.

## Run the container stack

Requirements: Docker Engine with the Compose plugin, outbound access to download pinned scanner release archives and container images, and a host with roughly 2 GB or more available memory.

1. Copy the example environment file and create a fresh shared API token:

   ```sh
   cp .env.example .env
   openssl rand -base64 48
   ```

2. Paste the generated value into `.env` as `PROOFVAPT_API_TOKEN=...`. Do not commit this file.

3. Build and launch:

   ```sh
   docker compose up --build -d
   docker compose ps
   docker compose logs -f proofvapt
   ```

4. Open [http://127.0.0.1:3000](http://127.0.0.1:3000) on the host running Docker and enter the token. The app's host port is bound to loopback by default. For remote use, put it behind a TLS-terminating reverse proxy and restrict access at the network edge; do not expose the shared token over plain HTTP.

5. Use **Start Lab Scan** to run the configured Juice Shop benchmark. The lab container is not published on a host port; it is reachable over the Compose network. The benchmark uses `JUICE_SHOP_URL=http://juice-shop:3000`.

Stop services with `docker compose down`. The named `proofvapt-data` volume holds scan records and artifacts and remains after `down`. To intentionally remove the data volume, use `docker compose down -v` only after exporting anything you need.

### Deploying on a host or platform

The production server requires:
- `NODE_ENV=production`
- `PROOFVAPT_API_TOKEN` with at least 32 bytes of entropy
- `PROOFVAPT_DATA_DIR` pointing to writable persistent storage
- `PORT` set to the port exposed by your service
- a TLS reverse proxy and edge access control for remote deployments

Generate a token with `openssl rand -base64 48`. Keep the token in the deployment secret manager, not in source control, build arguments, browser URLs, or logs. `TRUST_PROXY=1` should only be enabled when the service is reachable solely through a trusted reverse proxy.

## Local development

Requirements: Node.js 22+, npm, Java 17+, ffuf, and OWASP ZAP installed on the host. Put `ffuf` and `zap.sh` on `PATH` or use the deployment container above.

```sh
npm install
cp .env.example .env
# For local Juice Shop: expose it on 127.0.0.1:3001 and set JUICE_SHOP_URL.
npm run dev
```

Development mode does not enable the production token gate; do not expose the development server to an untrusted network.

## Commands

| Command | Purpose |
| --- | --- |
| `npm run dev` | Start the server with Vite middleware and watch mode |
| `npm run lint` | Type-check the TypeScript project |
| `npm test` | Run scope-policy and benchmark regression tests |
| `npm run build` | Build static assets and bundle the production server |
| `npm start` | Start the production bundle after building |

## Important product boundaries

- **Single operator / single application instance.** The token is a shared bearer credential; this is not a multi-user identity or tenant system. Add organization login/authorization before offering it to multiple independent customers.
- **File-backed database.** State is stored as JSON under `PROOFVAPT_DATA_DIR`. Use one running application instance and persistent storage. For multi-replica or higher-throughput operation, migrate persistence to a transactional database and move scan jobs to a durable queue.
- **Authenticated scanning is not implemented.** The UI intentionally offers passive and standard active profiles only; requests for the unsupported authenticated profile are rejected rather than pretending credentials are being used.
- **Scope is exact-host and allow-listed-port based.** Register one intended host and only the ports you have permission to test. Lab mode is not a wildcard scope exception. Keep a network-layer egress policy in front of scanners on shared or public infrastructure.
- **HTTPS request budgets are proxy tunnel counts.** HTTPS payloads are encrypted inside CONNECT tunnels, so the proxy can count tunnels but cannot accurately count every HTTP request inside one tunnel. The configured budgets should not be interpreted as a perfect count of all encrypted requests. Continue to use tool-specific limits and external network controls.
- **Verification is evidence-sensitive.** Generic endpoint reachability is not proof of a vulnerability. Generic retests remain inconclusive until test-specific evidence exists; the simulated-fix option is restricted to non-production lab work.
- **Research metrics require measured baselines.** False-positive reduction, overhead, and verification accuracy are not filled with invented values. Juice Shop ground truth is not applied to scans against unrelated hosts.
- **No browser or production smoke test has yet been recorded for this branch.** CI runs the type-check, regression tests, and build; deploy only after those checks pass and complete a staging scan against the isolated lab.

## Security hygiene

Runtime scan records and artifacts belong in persistent runtime storage, not in Git. The Docker build excludes `.data/`, secrets, build output, and the old bundled ffuf binary. If you have previously committed real credentials, target details, or sensitive evidence, removing a file in a later commit does not erase earlier Git history; rotate credentials and consider repository-history cleanup before making the repository public.

See [SECURITY.md](SECURITY.md) for the reporting and deployment policy.
