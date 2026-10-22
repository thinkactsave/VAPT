import test from 'node:test';
import assert from 'node:assert/strict';
import { ScopeEnforcingEgressProxy } from '../server/egressProxy.js';
import { BenchmarkEvaluationEngine } from '../server/benchmarks.js';

test('always blocks the cloud metadata link-local address, including lab mode', () => {
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('169.254.169.254', true).restricted, true);
  assert.equal(ScopeEnforcingEgressProxy.isRestrictedIP('169.254.10.20', true).restricted, true);
});

test('blocks private and local destinations for live scans', () => {
  for (const ip of ['127.0.0.1', '10.0.0.2', '172.16.0.2', '192.168.1.2', '100.64.0.1', '224.0.0.1', 'fd00::1', 'fe80::1']) {
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
