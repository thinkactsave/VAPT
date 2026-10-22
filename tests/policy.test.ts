import test from 'node:test';
import assert from 'node:assert/strict';
import { ScopeEnforcingEgressProxy } from '../server/egressProxy.js';
import { BenchmarkEvaluationEngine } from '../server/benchmarks.js';
import { TargetProfile } from '../src/types/proofvapt.js';

test('always blocks the cloud metadata link-local address, including lab mode', () => {
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('169.254.169.254', true).restricted, true);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('169.254.10.20', true).restricted, true);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('::ffff:169.254.169.254', true).restricted, true);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('::', true).restricted, true);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('ff02::1', true).restricted, true);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('2001:db8::1', true).restricted, true);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('100.64.0.1', true).restricted, true);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('198.51.100.10', true).restricted, true);
});

test('blocks private and local destinations for live scans', () => {
  for (const ip of ['127.0.0.1', '10.0.0.2', '172.16.0.2', '192.168.1.2', '100.64.0.1', '224.0.0.1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1']) {
    assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP(ip, false).restricted, true, `expected ${ip} to be blocked`);
  }
});

test('permits local RFC1918 addresses only when the lab policy is explicit', () => {
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('127.0.0.1', true).restricted, false);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('10.0.0.2', true).restricted, false);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('192.168.1.2', true).restricted, false);
});

test('does not manufacture research baselines or accuracy numbers', () => {
  const metrics = BenchmarkEvaluationEngine.evaluateScanAgainstGroundTruth([], undefined, 0, 0, 0);
  assert.equal(metrics.false_positive_reduction, 'Undefined');
  assert.equal(metrics.duplicate_reduction, 'Undefined');
  assert.equal(metrics.time_overhead_pct, 'Undefined');
  assert.equal(metrics.request_overhead_pct, 'Undefined');
  assert.equal(metrics.verification_accuracy, 'Undefined');
  assert.equal(metrics.total_requests, 0);
  assert.equal(metrics.duration_seconds, 0);
});

test('fails closed for a foreign host or a port outside scope, even in lab mode', async () => {
  const target: TargetProfile = {
    id: 'target-policy-test',
    name: 'Test lab target',
    mode: 'lab',
    target_url: 'http://juice-shop:3000/',
    hostname: 'juice-shop',
    allowed_ports: [3000],
    excluded_paths: ['/logout'],
    rate_limit_rps: 5,
    max_request_budget: 25,
    timeout_ms: 3000,
    is_isolated_lab_network_confirmed: true,
    active_scan_scope_confirmed: true,
    created_at: new Date(0).toISOString()
  };
  const proxy = new ScopeEnforcingEgressProxy({ scanId: 'policy-test', target });
  const foreignHost = await proxy.validateDestination('example.com', 3000);
  const foreignPort = await proxy.validateDestination('juice-shop', 443);
  assert.equal(foreignHost.allowed, false);
  assert.equal(foreignPort.allowed, false);
});
