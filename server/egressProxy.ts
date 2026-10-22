import http from 'http';
import net from 'net';
import dns from 'dns/promises';
import { TargetProfile, ProxyAccessLog } from '../src/types/proofvapt.js';
import { db } from './db.js';

export interface EgressProxyConfig {
  scanId: string;
  target: TargetProfile;
  onBudgetExceeded?: (count: number) => void;
  onErrorThresholdExceeded?: (rate: number) => void;
}

export class ScopeEnforcingEgressProxy {
  private server: http.Server | null = null;
  private port: number = 0;
  private config: EgressProxyConfig;
  private requestCount: number = 0;
  private errorCount: number = 0;
  private isStopped: boolean = false;
  private readonly sockets = new Set<net.Socket>();

  constructor(config: EgressProxyConfig) {
    this.config = config;
  }

  public getPort(): number {
    return this.port;
  }

  public getRequestCount(): number {
    return this.requestCount;
  }

  private static isInCidr(ip: string, cidr: string): boolean {
    const [base, prefixText] = cidr.split("/");
    const prefix = Number(prefixText);
    const toNumber = (value: string) =>
      value.split(".").reduce((acc, octet) => ((acc << 8) | Number(octet)) >>> 0, 0);
    const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
    return (toNumber(ip) & mask) >>> 0 === (toNumber(base) & mask) >>> 0;
  }

  /**
   * Rejects special-use addresses. Private and loopback ranges are allowed only
   * for an explicitly configured lab target; the metadata/link-local ranges are
   * blocked in every mode.
   */
  public static isRestrictedIP(
    ip: string,
    allowPrivateLab: boolean,
    allowLoopbackLab = allowPrivateLab
  ): { restricted: boolean; reason?: string } {
    const address = ip.replace(/^\[|\]$/g, "").toLowerCase();
    const version = net.isIP(address);
    if (!version) return { restricted: true, reason: "Destination is not a valid IP address" };

    if (version === 4) {
      const alwaysBlocked = [
        "0.0.0.0/8", "169.254.0.0/16", "192.0.0.0/24", "192.0.2.0/24",
        "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24",
        "224.0.0.0/4", "240.0.0.0/4"
      ];
      if (alwaysBlocked.some((cidr) => this.isInCidr(address, cidr))) {
        return { restricted: true, reason: "Special-use, link-local, documentation, multicast or reserved IPv4 range blocked" };
      }
      if (this.isInCidr(address, "127.0.0.0/8")) {
        return allowLoopbackLab
          ? { restricted: false }
          : { restricted: true, reason: "Loopback is only permitted for an explicitly configured local lab target" };
      }
      const privateRanges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"];
      if (privateRanges.some((cidr) => this.isInCidr(address, cidr)) && !allowPrivateLab) {
        return { restricted: true, reason: "Private or shared-address range blocked outside explicitly enabled lab networking" };
      }
      return { restricted: false };
    }

    // Convert IPv4-mapped IPv6 addresses before applying IPv4 controls.
    if (address.startsWith("::ffff:")) {
      const suffix = address.slice("::ffff:".length);
      if (net.isIP(suffix) === 4) {
        return this.isRestrictedIP(suffix, allowPrivateLab, allowLoopbackLab);
      }
      const words = suffix.split(":");
      if (words.length === 2 && words.every((word) => /^[0-9a-f]{1,4}$/.test(word))) {
        const packed = (parseInt(words[0], 16) * 0x10000) + parseInt(words[1], 16);
        const ipv4 = [24, 16, 8, 0].map((shift) => (packed >>> shift) & 255).join(".");
        return this.isRestrictedIP(ipv4, allowPrivateLab, allowLoopbackLab);
      }
      return { restricted: true, reason: "Unrecognized IPv4-mapped IPv6 destination blocked" };
    }

    if (address === "::") return { restricted: true, reason: "Unspecified IPv6 destination blocked" };
    if (address === "::1") {
      return allowLoopbackLab
        ? { restricted: false }
        : { restricted: true, reason: "IPv6 loopback is only permitted for an explicitly configured local lab target" };
    }
    if (address.startsWith("fe80:") || address.startsWith("ff")) {
      return { restricted: true, reason: "IPv6 link-local or multicast destination blocked" };
    }
    if ((address.startsWith("fc") || address.startsWith("fd")) && !allowPrivateLab) {
      return { restricted: true, reason: "IPv6 unique-local destinations are blocked outside explicitly enabled lab networking" };
    }
    if (address.startsWith("2001:db8:")) {
      return { restricted: true, reason: "IPv6 documentation range blocked" };
    }
    return { restricted: false };
  }

  /**
   * Validates target host and resolved IP against authorized scope at connection time
   */
  public async validateDestination(
    hostname: string,
    port: number
  ): Promise<{ allowed: boolean; ip?: string; reason?: string }> {
    const { target } = this.config;
    const requestedHost = hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
    const authorizedHost = target.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();

    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { allowed: false, reason: "Invalid destination port" };
    }
    if (target.allowed_ports.length === 0 || !target.allowed_ports.includes(port)) {
      return { allowed: false, reason: `Port ${port} is not in the authorized port whitelist` };
    }

    // Intentionally exact-host matching. Lab mode is not a wildcard allowlist.
    if (requestedHost !== authorizedHost) {
      return { allowed: false, reason: `Host '${hostname}' is outside the exact authorized host '${target.hostname}'` };
    }

    const labConfirmed = target.mode === "lab" && target.is_isolated_lab_network_confirmed;
    const targetIsLoopback = ["localhost", "127.0.0.1", "::1"].includes(authorizedHost);
    const allowLoopbackLab = labConfirmed && targetIsLoopback;
    // A UI acknowledgement alone is not proof of isolation for RFC1918/ULA
    // destinations. An operator must deliberately enable this deployment-level
    // opt-in and separately isolate worker egress at the network layer.
    const allowPrivateLab = labConfirmed && process.env.PROOFVAPT_ALLOW_PRIVATE_LAB_TARGETS === "true";

    try {
      const addresses = net.isIP(requestedHost)
        ? [{ address: requestedHost, family: net.isIP(requestedHost) }]
        : await dns.lookup(requestedHost, { all: true, verbatim: true });

      if (!addresses.length) {
        return { allowed: false, reason: `DNS resolution returned no addresses for '${hostname}'` };
      }

      for (const addr of addresses) {
        const check = ScopeEnforcingEgressProxy.isRestrictedIP(
          addr.address,
          allowPrivateLab,
          allowLoopbackLab
        );
        if (check.restricted) {
          return { allowed: false, ip: addr.address, reason: check.reason };
        }
      }

      return { allowed: true, ip: addresses[0].address };
    } catch (err) {
      return {
        allowed: false,
        reason: `DNS resolution failed for '${hostname}': ${err instanceof Error ? err.message : "unknown error"}`
      };
    }
  }

  /**
   * Starts the Scope-Enforcing Egress Proxy on a random high loopback port
   */
  public async start(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server = http.createServer(async (req, res) => {
        await this.handleHttpRequest(req, res);
      });

      this.server.on("connection", (socket) => {
        this.sockets.add(socket);
        socket.once("close", () => this.sockets.delete(socket));
      });

      // Handle HTTPS CONNECT tunneling
      this.server.on('connect', async (req, clientSocket, head) => {
        await this.handleConnectTunnel(req, clientSocket as any, head);
      });

      this.server.listen(0, '127.0.0.1', () => {
        const addr = this.server?.address();
        if (addr && typeof addr === 'object') {
          this.port = addr.port;
          console.log(`[EgressProxy] Scope-Enforcing Proxy active on 127.0.0.1:${this.port} for scan ${this.config.scanId}`);
          resolve(this.port);
        } else {
          reject(new Error('Failed to bind proxy to local port'));
        }
      });

      this.server.on('error', (err) => {
        console.error('[EgressProxy] Server error:', err);
      });
    });
  }

  private checkBudgetAndLimits(): { allowed: boolean; reason?: string } {
    if (this.isStopped) {
      return { allowed: false, reason: 'Proxy has stopped processing new requests' };
    }

    const maxBudget = Math.max(1, Math.floor(this.config.target.max_request_budget || 2000));
    if (this.requestCount >= maxBudget) {
      this.isStopped = true;
      const msg = `Proxy event budget (${maxBudget}) reached. Stop condition tripped.`;
      if (this.config.onBudgetExceeded) this.config.onBudgetExceeded(this.requestCount);
      return { allowed: false, reason: msg };
    }

    this.requestCount++;
    return { allowed: true };
  }

  private async handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    const budgetCheck = this.checkBudgetAndLimits();
    if (!budgetCheck.allowed) {
      res.writeHead(429, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'ProofVAPT Egress Proxy: Budget Limit Exceeded', reason: budgetCheck.reason }));
      return;
    }

    if (!req.url) {
      res.writeHead(400);
      res.end('Missing request URL');
      return;
    }

    let targetUrl: URL;
    try {
      targetUrl = new URL(req.url);
    } catch {
      targetUrl = new URL(`http://${req.headers.host}${req.url}`);
    }

    if (targetUrl.protocol !== "http:") {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: "Use HTTP proxy requests for http:// targets and CONNECT for HTTPS targets." }));
      return;
    }

    const host = targetUrl.hostname;
    const port = targetUrl.port ? parseInt(targetUrl.port, 10) : 80;

    const validation = await this.validateDestination(host, port);

    // Record proxy wire log
    const logEntry: ProxyAccessLog = {
      id: `plog-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      scan_id: this.config.scanId,
      timestamp: new Date().toISOString(),
      method: req.method || 'GET',
      destination_host: host,
      destination_port: port,
      destination_ip: validation.ip || 'unresolved',
      // Do not persist query strings: they can contain tokens, email addresses or other sensitive values.
      url: `${targetUrl.origin}${targetUrl.pathname}`,
      status_code: validation.allowed ? 0 : 403,
      blocked: !validation.allowed,
      block_reason: validation.reason,
      client_tool: (req.headers['user-agent'] || 'unknown').includes('ffuf')
        ? 'ffuf'
        : (req.headers['user-agent'] || '').includes('ZAP')
        ? 'owasp_zap'
        : 'prober',
    };
    db.saveProxyLog(logEntry);

    if (!validation.allowed) {
      console.warn(`[EgressProxy] BLOCKED request to ${host}:${port} — ${validation.reason}`);
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        error: 'ProofVAPT Scope Violation: Out-of-scope or restricted destination blocked',
        reason: validation.reason,
      }));
      return;
    }

    // Forward request
    const proxyReq = http.request(
      {
        hostname: validation.ip || host,
        port,
        path: targetUrl.pathname + targetUrl.search,
        method: req.method,
        headers: {
          ...req.headers,
          host: targetUrl.host,
        },
      },
      (proxyRes) => {
        if (proxyRes.statusCode && proxyRes.statusCode >= 500) {
          this.errorCount++;
          if (this.requestCount > 20 && this.errorCount / this.requestCount > 0.3) {
            if (this.config.onErrorThresholdExceeded) {
              this.config.onErrorThresholdExceeded(this.errorCount / this.requestCount);
            }
          }
        }
        res.writeHead(proxyRes.statusCode || 200, proxyRes.headers);
        proxyRes.pipe(res);
      }
    );

    proxyReq.on('error', (err) => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'ProofVAPT Gateway Error', message: err.message }));
    });

    req.pipe(proxyReq);
  }

  private async handleConnectTunnel(
    req: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer
  ) {
    const budgetCheck = this.checkBudgetAndLimits();
    if (!budgetCheck.allowed) {
      clientSocket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    let hostname: string;
    let port: number;
    try {
      const authority = new URL(`http://${req.url || ""}`);
      hostname = authority.hostname;
      port = authority.port ? Number(authority.port) : 443;
    } catch {
      clientSocket.write("HTTP/1.1 400 Bad Request\\r\\n\\r\\n");
      clientSocket.destroy();
      return;
    }

    const validation = await this.validateDestination(hostname, port);

    const logEntry: ProxyAccessLog = {
      id: `plog-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
      scan_id: this.config.scanId,
      timestamp: new Date().toISOString(),
      method: 'CONNECT',
      destination_host: hostname,
      destination_port: port,
      destination_ip: validation.ip || 'unresolved',
      url: `https://${hostname}:${port}`,
      status_code: validation.allowed ? 0 : 403,
      blocked: !validation.allowed,
      block_reason: validation.reason,
      client_tool: (req.headers['user-agent'] || '').includes('ZAP') ? 'owasp_zap' : 'scanner_tool',
    };
    db.saveProxyLog(logEntry);

    if (!validation.allowed) {
      console.warn(`[EgressProxy] BLOCKED HTTPS CONNECT to ${hostname}:${port} — ${validation.reason}`);
      clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    const targetSocket = net.connect(port, validation.ip || hostname, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length > 0) {
        targetSocket.write(head);
      }
      targetSocket.pipe(clientSocket);
      clientSocket.pipe(targetSocket);
    });

    targetSocket.on('error', () => {
      clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
      clientSocket.destroy();
    });

    clientSocket.on('error', () => {
      targetSocket.destroy();
    });
  }

  public async stop(): Promise<void> {
    this.isStopped = true;
    for (const socket of this.sockets) socket.destroy();
    if (this.server) {
      return new Promise((resolve) => {
        this.server?.close(() => {
          console.log(`[EgressProxy] Proxy on port ${this.port} closed.`);
          resolve();
        });
      });
    }
  }
}
