import { ResearchMetrics, UnifiedFinding } from '../src/types/proofvapt.js';

export interface GroundTruthItem {
  id: string;
  name: string;
  endpoint: string;
  parameter: string | null;
  owasp_category: string;
  is_true_vulnerability: boolean; // true = TP ground truth, false = TN ground truth
  cwe_id: string;
  expected_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export const JUICE_SHOP_GROUND_TRUTH: GroundTruthItem[] = [
  {
    id: 'GT-JS-01',
    name: 'SQL Injection on Login',
    endpoint: '/rest/user/login',
    parameter: 'email',
    owasp_category: 'A05',
    is_true_vulnerability: true,
    cwe_id: 'CWE-89',
    expected_severity: 'CRITICAL',
    description: 'Unsanitized user email input allows SQL injection authentication bypass.'
  },
  {
    id: 'GT-JS-02',
    name: 'Reflected XSS in Search Query',
    endpoint: '/rest/products/search',
    parameter: 'q',
    owasp_category: 'A05',
    is_true_vulnerability: true,
    cwe_id: 'CWE-79',
    expected_severity: 'HIGH',
    description: 'Unsanitized query parameter reflected into DOM.'
  },
  {
    id: 'GT-JS-03',
    name: 'Exposed FTP / Backup Directory',
    endpoint: '/ftp',
    parameter: null,
    owasp_category: 'A02',
    is_true_vulnerability: true,
    cwe_id: 'CWE-538',
    expected_severity: 'HIGH',
    description: 'Publicly browsable directory with leaked incident and backup files.'
  },
  {
    id: 'GT-JS-04',
    name: 'Missing Security Headers',
    endpoint: '/',
    parameter: null,
    owasp_category: 'A02',
    is_true_vulnerability: true,
    cwe_id: 'CWE-693',
    expected_severity: 'MEDIUM',
    description: 'Absence of HSTS and strict Content-Security-Policy headers.'
  },
  {
    id: 'GT-JS-05',
    name: 'Permissive CORS Header',
    endpoint: '/api/BasketItems',
    parameter: 'Origin',
    owasp_category: 'A02',
    is_true_vulnerability: true,
    cwe_id: 'CWE-942',
    expected_severity: 'MEDIUM',
    description: 'Permissive cross-origin policy allows arbitrary origin reads.'
  },
  {
    id: 'GT-JS-06',
    name: 'Hardened Static Asset Path (Control Test Instance)',
    endpoint: '/assets/public/favicon_ico',
    parameter: null,
    owasp_category: 'A02',
    is_true_vulnerability: false, // True Negative instance
    cwe_id: 'CWE-0',
    expected_severity: 'LOW',
    description: 'Properly hardened static route; should NOT report directory listing or access violations.'
  },
  {
    id: 'GT-JS-07',
    name: 'Sanitized Parameter Endpoint (Control Test Instance)',
    endpoint: '/api/Quantity',
    parameter: 'id',
    owasp_category: 'A05',
    is_true_vulnerability: false, // True Negative instance
    cwe_id: 'CWE-0',
    expected_severity: 'LOW',
    description: 'Strict integer parameterized route; should NOT trigger false positive SQL injection.'
  },
  {
    id: 'GT-JS-08',
    name: 'Stack Trace Leakage in Error Response',
    endpoint: '/rest/track-order',
    parameter: 'id',
    owasp_category: 'A10',
    is_true_vulnerability: true,
    cwe_id: 'CWE-209',
    expected_severity: 'MEDIUM',
    description: 'Invalid order ID leaks internal Sequelize stack trace.'
  }
];

export class BenchmarkEvaluationEngine {
  /**
   * Computes precision, recall, FPR, and overhead metrics against documented ground truth
   */
  public static evaluateScanAgainstGroundTruth(
    findings: UnifiedFinding[],
    groundTruth: GroundTruthItem[] = JUICE_SHOP_GROUND_TRUTH,
    rawAlertsCount: number = 0,
    scanDurationSeconds: number = 0,
    totalRequestsCount: number = 0,
    baselineTimeSeconds: number = 0,
    baselineRequestsCount: number = 0
  ): ResearchMetrics {
    let tp = 0;
    let fp = 0;
    let fn = 0;
    let tn = 0;

    for (const gt of groundTruth) {
      // Look for a matching finding in the scan output
      const match = findings.find((f) => {
        const matchesCategory = f.owasp_category_code === gt.owasp_category;
        const matchesEndpoint = f.affected_url.includes(gt.endpoint);
        const matchesParam = !gt.parameter || f.parameter?.includes(gt.parameter);
        return matchesCategory && matchesEndpoint && matchesParam;
      });

      if (gt.is_true_vulnerability) {
        if (match && match.verification_status !== 'not_reproduced') {
          tp++;
        } else {
          fn++;
        }
      } else {
        if (match && match.verification_status === 'verified') {
          fp++;
        } else {
          tn++;
        }
      }
    }

    // Explicit division by zero handling
    const precision = tp + fp > 0 ? Number((tp / (tp + fp)).toFixed(4)) : 'Undefined';
    const recall = tp + fn > 0 ? Number((tp / (tp + fn)).toFixed(4)) : 'Undefined';
    const fpr = fp + tn > 0 ? Number((fp / (fp + tn)).toFixed(4)) : 'Undefined';

    // Comparative claims require measured baseline data. Do not invent a
    // baseline or pad the raw-alert count to make results look better.
    const fpReduction = 'Undefined';
    const totalRaw = Math.max(0, rawAlertsCount);
    const totalUnified = findings.length;
    const dupReduction = totalRaw > 0
      ? Number((((totalRaw - totalUnified) / totalRaw) * 100).toFixed(2))
      : 'Undefined';

    const timeOverhead = baselineTimeSeconds > 0 && scanDurationSeconds >= 0
      ? Number((((scanDurationSeconds - baselineTimeSeconds) / baselineTimeSeconds) * 100).toFixed(2))
      : 'Undefined';

    const reqOverhead = baselineRequestsCount > 0 && totalRequestsCount >= 0
      ? Number((((totalRequestsCount - baselineRequestsCount) / baselineRequestsCount) * 100).toFixed(2))
      : 'Undefined';

    return {
      precision,
      recall,
      false_positive_rate: fpr,
      false_positive_reduction: fpReduction,
      duplicate_reduction: dupReduction,
      time_overhead_pct: timeOverhead,
      request_overhead_pct: reqOverhead,
      verification_accuracy: 'Undefined',
      tp_count: tp,
      fp_count: fp,
      fn_count: fn,
      tn_count: tn,
      sample_size: groundTruth.length,
      raw_alerts_count: totalRaw,
      unified_findings_count: totalUnified,
      total_requests: totalRequestsCount,
      duration_seconds: scanDurationSeconds
    };
  }
}
