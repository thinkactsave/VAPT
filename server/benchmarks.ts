import { ResearchMetrics, UnifiedFinding, VerificationStatus } from '../src/types/proofvapt.js';

export interface GroundTruthItem {
  id: string;
  name: string;
  endpoint: string;
  parameter: string | null;
  owasp_category: string;
  is_true_vulnerability: boolean;
  cwe_id: string;
  expected_severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  description: string;
}

export interface BenchmarkBaseline {
  /** Number of raw alerts actually emitted by the baseline scanner run. */
  raw_alerts_count: number;
  /** Confirmed false positives from a separately reviewed baseline run. */
  confirmed_false_positives: number;
  /** Duration of the baseline run, in seconds. */
  duration_seconds: number;
  /** Requests observed for the baseline run. */
  requests_count: number;
  /** Duplicate alert records observed before correlation. */
  duplicate_alerts_count: number;
}

/**
 * Important: this is a starter evaluation set, not authoritative ground truth for
 * every version/configuration of Juice Shop. Review each item against the exact
 * local lab build and record before collecting dissertation results.
 */
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
    description: 'Candidate known-vulnerable test case; confirm against the pinned local lab version.'
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
    description: 'Candidate XSS test case; endpoint and parameter behavior must be validated against the chosen lab version.'
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
    description: 'Candidate exposed-resource test case; confirm actual contents and access behavior.'
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
    description: 'Header-policy test case; define the expected policy for the exact lab deployment before scoring.'
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
    description: 'Candidate CORS test case; validate whether sensitive cross-origin data is actually exposed.'
  },
  {
    id: 'GT-JS-06',
    name: 'Hardened Static Asset Path (Control Test Instance)',
    endpoint: '/assets/public/favicon_ico',
    parameter: null,
    owasp_category: 'A02',
    is_true_vulnerability: false,
    cwe_id: 'CWE-0',
    expected_severity: 'LOW',
    description: 'Negative control; verify that this route exists and is correctly configured in the exact testbed.'
  },
  {
    id: 'GT-JS-07',
    name: 'Sanitized Parameter Endpoint (Control Test Instance)',
    endpoint: '/api/Quantity',
    parameter: 'id',
    owasp_category: 'A05',
    is_true_vulnerability: false,
    cwe_id: 'CWE-0',
    expected_severity: 'LOW',
    description: 'Negative control; verify the endpoint behavior and expected safe handling before including it.'
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
    description: 'Candidate error-disclosure test case; confirm response behavior in the pinned lab version.'
  }
];

export class BenchmarkEvaluationEngine {
  /**
   * Computes metrics against reviewed ground-truth test instances.
   *
   * Findings are matched by normalized URL path, category and (where supplied)
   * parameter. Unknown or unverified findings are not silently promoted to TP.
   * Baseline-based reduction metrics are undefined unless measured baseline data
   * are passed in explicitly.
   */
  public static evaluateScanAgainstGroundTruth(
    findings: UnifiedFinding[],
    groundTruth: GroundTruthItem[] = JUICE_SHOP_GROUND_TRUTH,
    rawAlertsCount = 0,
    scanDurationSeconds = 0,
    totalRequestsCount = 0,
    baseline?: BenchmarkBaseline
  ): ResearchMetrics {
    let tp = 0;
    let fp = 0;
    let fn = 0;
    let tn = 0;

    const matchedFindingIds = new Set<string>();

    for (const gt of groundTruth) {
      const match = findings.find((finding) => {
        if (matchedFindingIds.has(finding.id)) return false;

        let findingPath: string;
        try {
          findingPath = new URL(finding.affected_url).pathname;
        } catch {
          findingPath = finding.affected_url.split(/[?#]/, 1)[0];
        }

        const normalizedFindingPath = findingPath.replace(/\/+$/, '') || '/';
        const normalizedGroundTruthPath = gt.endpoint.replace(/\/+$/, '') || '/';
        const matchesCategory = finding.owasp_category_code === gt.owasp_category;
        const matchesEndpoint = normalizedFindingPath === normalizedGroundTruthPath;
        const matchesParam = !gt.parameter ||
          (finding.parameter || '').toLowerCase().includes(gt.parameter.toLowerCase());
        return matchesCategory && matchesEndpoint && matchesParam;
      });

      if (match) matchedFindingIds.add(match.id);

      if (gt.is_true_vulnerability) {
        if (match?.verification_status === 'verified') {
          tp++;
        } else {
          fn++;
        }
      } else {
        if (match) {
          // A finding on a documented negative-control instance is a false alarm,
          // regardless of whether the scanner labelled it "verified".
          fp++;
        } else {
          tn++;
        }
      }
    }

    const divide = (numerator: number, denominator: number): number | 'Undefined' =>
      denominator > 0 ? Number((numerator / denominator).toFixed(4)) : 'Undefined';

    const precision = divide(tp, tp + fp);
    const recall = divide(tp, tp + fn);
    const fpr = divide(fp, fp + tn);

    // A baseline comparison needs observed baseline labels; never fabricate an
    // assumed number of false positives, alerts, requests, or seconds.
    const fpReduction =
      baseline && baseline.confirmed_false_positives > 0
        ? Number(((baseline.confirmed_false_positives - fp) / baseline.confirmed_false_positives * 100).toFixed(2))
        : 'Undefined';

    const duplicateReduction =
      baseline && baseline.raw_alerts_count > 0 && baseline.duplicate_alerts_count >= 0
        ? Number(((baseline.duplicate_alerts_count - Math.max(0, rawAlertsCount - findings.length)) /
          Math.max(1, baseline.duplicate_alerts_count) * 100).toFixed(2))
        : 'Undefined';

    const timeOverhead =
      baseline && baseline.duration_seconds > 0
        ? Number(((scanDurationSeconds - baseline.duration_seconds) / baseline.duration_seconds * 100).toFixed(2))
        : 'Undefined';

    const requestOverhead =
      baseline && baseline.requests_count > 0
        ? Number(((totalRequestsCount - baseline.requests_count) / baseline.requests_count * 100).toFixed(2))
        : 'Undefined';

    return {
      precision,
      recall,
      false_positive_rate: fpr,
      false_positive_reduction: fpReduction,
      duplicate_reduction: duplicateReduction,
      time_overhead_pct: timeOverhead,
      request_overhead_pct: requestOverhead,
      verification_accuracy: 'Undefined',
      tp_count: tp,
      fp_count: fp,
      fn_count: fn,
      tn_count: tn,
      sample_size: groundTruth.length,
      raw_alerts_count: rawAlertsCount,
      unified_findings_count: findings.length,
      total_requests: totalRequestsCount,
      duration_seconds: scanDurationSeconds
    };
  }
}
