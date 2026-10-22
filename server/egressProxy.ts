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
  private nextRequestAt = 0;
  private isStopped: boolean = false;

  constructor(config: EgressProxyConfig) {
    this.config = config;
  }

  public getPort(): number {
    return this.port;
  }

  public getRequestCount(): number {
    return this.requestCount;
  }

  /**
   * Validates if a destination IP address falls into restricted/private ranges
   */
  public static isRestrictedIP(ip: string, allowLabPrivate: boolean): { restricted: boolean; reason?: string } {
    const normalizedIp = ip.replace(/^\\[|\\]$/g, '').toLowerCase();

    // Link-local addresses include cloud metadata services; always reject them,
    // even when the operator has enabled a private lab target.
    if (normalizedIp === '169.254.169.254' || normalizedIp.startsWith('169.254.')) {
      return { restricted: true, reason: 'Cloud metadata service access prohibited (169.254.169.254)' };
    }

    // IPv6 checks
    if (
      normalizedIp === '::1' ||
      normalizedIp === '::' ||
      /^fe[89ab][0-9a-f]:/i.test(normalizedIp) ||
      /^f[cd][0-9a-f]{2}:/i.test(normalizedIp) ||
      normalizedIp.startsWith('::ffff:')
    ) {
      if (!allowLabPrivate) {
        return { restricted: true, reason: 'IPv6 local/loopback/unique-local address prohibited without isolated lab network' };
      }
    }

    // IPv4 Checks
    const parts = normalizedIp.split('.').map(Number);
    if (parts.length === 4 && parts.every((p) => !isNaN(p) && p >= 0 && p <= 255)) {
      const [b0, b1] = parts;

      // 0.0.0.0/8
      if (b0 === 0) return { restricted: true, reason: 'Current network source (0.0.0.0/8) blocked' };
      // 127.0.0.0/8 (Loopback)
      if (b0 === 127) {
        if (!allowLabPrivate) return { restricted: true, reason: 'Loopback address (127.0.0.0/8) blocked without isolated lab policy' };
      }
      // 10.0.0.0/8 (RFC 1918)
      if (b0 === 10) {
        if (!allowLabPrivate) return { restricted: true, reason: 'Private network (10.0.0.0/8) blocked without isolated lab policy' };
      }
      // 172.16.0.0/12 (RFC 1918)
      if (b0 === 172 && b1 >= 16 && b1 <= 31) {
        if (!allowLabPrivate) return { restricted: true, reason: 'Private network (172.16.0.0/12) blocked without isolated lab policy' };
      }
      // 192.168.0.0/16 (RFC 1918)
      if (b0 === 192 && b1 === 168) {
        if (!allowLabPrivate) return { restricted: true, reason: 'Private network (192.168.0.0/16) blocked without isolated lab policy' };
      }
      // 100.64.0.0/10 (Carrier-grade NAT)
      if (b0 === 100 && b1 >= 64 && b1 <= 127) {
        if (!allowLabPrivate) return { restricted: true, reason: 'Carrier-grade NAT space blocked' };
      }
      // Multicast / Reserved (224.0.0.0/4 and 240.0.0.0/4)
      if (b0 >= 224) {
        return { restricted: true, reason: 'Multicast or reserved IP range blocked' };
      }
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

    // Fail closed: an empty port allowlist must never mean "all ports".
    if (!Array.isArray(target.allowed_ports) || !target.allowed_ports.includes(port)) {
      return { allowed: false, reason: `Port ${port} is not in the authorized ports allowlist.` };
    }

    // One target means one exact hostname. Lab mode does not grant a wildcard
    // exception for arbitrary destinations or redirected hosts.
    const targetHost = target.hostname.toLowerCase().replace(/^\\[|\\]$/g, '');
    const reqHost = hostname.toLowerCase().replace(/^\\[|\\]$/g, '');
    if (reqHost !== targetHost) {
      return { allowed: false, reason: `Host '${hostname}' is outside the authorized target '${target.hostname}'.` };
    }

    // Dynamic DNS resolution at connection time
    try {
      const lookupHost = hostname.toLowerCase().replace(/^\\[|\\]$/g, '');
      const addresses = await dns.lookup(lookupHost, { all: true, verbatim: true });
      if (!addresses || addresses.length === 0) {
        return { allowed: false, reason: `DNS resolution failed for host '${hostname}'` };
      }

      for (const addr of addresses) {
        const ipCheck = ScopeEnforcingEgressProxy.isRestrictedIP(
          addr.address,
          target.mode === 'lab' && target.is_isolated_lab_network_confirmed
        );
        if (ipCheck.restricted) {
          return { allowed: false, ip: addr.address, reason: ipCheck.reason };
        }
      }

      return { allowed: true, ip: addresses[0].address };
    } catch (dnsErr: any) {
      return { allowed: false, reason: `DNS lookup failed: ${dnsErr.message}` };
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

  private async waitForRateLimit(): Promise<void> {
    const configuredRate = Number(this.config.target.rate_limit_rps) || 10;
    const requestsPerSecond = Math.min(30, Math.max(1, configuredRate));
    const now = Date.now();
    const scheduledAt = Math.max(now, this.nextRequestAt);
    this.nextRequestAt = scheduledAt + 1000 / requestsPerSecond;
    const delay = scheduledAt - now;
    if (delay > 0) await new Promise<void>((resolve) => setTimeout(resolve, delay));
  }

  private checkBudgetAndLimits(): { allowed: boolean; reason?: string } {
    if (this.isStopped) {
      return { allowed: false, reason: 'Proxy has stopped processing new requests' };
    }

    const maxBudget = this.config.target.max_request_budget || 2000;

    if (this.requestCount >= maxBudget) {
      this.isStopped = true;
      const msg = `Global request budget (${maxBudget}) reached. Stop condition tripped.`;
      if (this.config.onBudgetExceeded) {
        this.config.onBudgetExceeded(this.requestCount);
      }
      return { allowed: false, reason: msg };
    }

    this.requestCount++;
    return { allowed: true };
  }

  private async handleHttpRequest(req: http.IncomingMessage, res: http.ServerResponse) {
    await this.waitForRateLimit();
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
      try {
        if (!req.headers.host) throw new Error('Missing Host header');
        targetUrl = new URL(`http://${req.headers.host}${req.url}`);
      } catch {
        res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Invalid proxy request URL');
        return;
      }
    }

    if (targetUrl.protocol !== 'http:') {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('HTTPS requests must use CONNECT tunnelling');
      return;
    }

    const excluded = this.config.target.excluded_paths || [];
    if (excluded.some((p) => targetUrl.pathname === p || targetUrl.pathname.startsWith(p.endsWith('/') ? p : p + '/'))) {
      res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Path is excluded from the authorized assessment scope');
      return;
    }

    const host = targetUrl.hostname.replace(/^\\[|\\]$/g, '');
    const port = targetUrl.port ? parseInt(targetUrl.port, 10) : targetUrl.protocol === 'https:' ? 443 : 80;

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
      url: targetUrl.href,
      status_code: validation.allowed ? 200 : 403,
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
    await this.waitForRateLimit();
    const budgetCheck = this.checkBudgetAndLimits();
    if (!budgetCheck.allowed) {
      clientSocket.write('HTTP/1.1 429 Too Many Requests\r\n\r\n');
      clientSocket.destroy();
      return;
    }

    let hostname = '';
    let port = 443;
    try {
      const connectUrl = new URL(`http://${req.url || ''}`);
      hostname = connectUrl.hostname.replace(/^\\[|\\]$/g, '');
      port = connectUrl.port ? Number(connectUrl.port) : 443;
      if (!hostname || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid CONNECT authority');
    } catch {
      clientSocket.write('HTTP/1.1 400 Bad Request\\r\\n\\r\\n');
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
      status_code: validation.allowed ? 200 : 403,
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
