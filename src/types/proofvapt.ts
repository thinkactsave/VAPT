/**
 * ProofVAPT - Unified TypeScript Types & Domain Interfaces
 * MSc Cyber Security Research Prototype
 */

export type ScanProfile = 'passive_only' | 'standard_active' | 'authenticated_lab';
export type ScanStatus = 'queued' | 'running' | 'completed' | 'aborted' | 'failed';
export type ScanStage =
  | 'scope_validation'
  | 'reconnaissance'
  | 'discovery'
  | 'automated_checks'
  | 'correlation'
  | 'verification'
  | 'reporting';

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type VerificationStatus =
  | 'verified'
  | 'potential'
  | 'not_reproduced'
  | 'manual_review_required';

export type RemediationStatus =
  | 'open'
  | 'fix_in_progress'
  | 'pending_retest'
  | 'remediated_verified'
  | 'reopened';

export interface TargetProfile {
  id: string;
  name: string;
  mode: 'live' | 'lab';
  target_url: string;
  hostname: string;
  allowed_ports: number[];
  excluded_paths: string[];
  rate_limit_rps: number;
  max_request_budget: number;
  timeout_ms: number;
  is_isolated_lab_network_confirmed: boolean;
  active_scan_scope_confirmed: boolean;
  created_at: string;
}

export interface StageProgress {
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  progress_pct: number;
  start_time?: string;
  end_time?: string;
  summary?: string;
}

export interface ScanExecution {
  id: string;
  target_id: string;
  scan_profile: ScanProfile;
  status: ScanStatus;
  current_stage: ScanStage;
  stage_progress: Record<ScanStage, StageProgress>;
  observed_request_count: number;
  stop_condition_triggered: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  target?: TargetProfile;
}

export interface ToolExecutionRecord {
  id: string;
  scan_id: string;
  tool_name: 'ffuf' | 'owasp_zap_spider' | 'owasp_zap_active' | 'owasp_zap_passive' | 'tls_header_prober' | 'egress_proxy';
  tool_version: string;
  command_line: string;
  exit_code: number;
  raw_output_path: string;
  stdout_summary: string;
  stderr_summary: string;
  started_at: string;
  ended_at: string;
}

export interface AttackSurfaceEndpoint {
  id: string;
  scan_id: string;
  url: string;
  path: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'OPTIONS' | 'HEAD';
  status_code: number;
  content_length: number;
  content_type: string;
  discovered_by: 'recon' | 'ffuf' | 'zap_spider' | 'manual';
  parameters?: Array<{ name: string; type: 'query' | 'body' | 'header' }>;
  created_at: string;
}

export interface OWASPTestRegistryItem {
  test_id: string;
  name: string;
  owasp_category: string; // e.g., 'A01' through 'A10'
  category_title: string;
  description: string;
  execution_method: 'automated_zap' | 'automated_ffuf' | 'automated_prober' | 'manual_review';
  prerequisites: string;
  limitations: string;
  validation_criteria: string;
}

export interface TestExecution {
  id: string;
  scan_id: string;
  test_id: string;
  execution_status: 'queued' | 'running' | 'completed' | 'skipped' | 'failed';
  outcome: 'vulnerable' | 'clean' | 'inconclusive' | 'error';
  evidence_references: string[];
  skip_or_error_reason: string | null;
  started_at: string;
  ended_at: string;
  test?: OWASPTestRegistryItem;
}

export interface FindingSource {
  id: string;
  finding_id: string;
  tool_name: 'owasp_zap' | 'ffuf' | 'tls_prober';
  source_alert_id: string;
  original_severity: SeverityLevel;
  raw_artifact_path: string;
  created_at: string;
}

export interface FindingEvidence {
  id: string;
  finding_id: string;
  request_headers: string;
  request_body: string | null;
  response_headers: string;
  response_body_snippet: string;
  matched_pattern: string;
  raw_tool_finding_json?: string;
  created_at: string;
}

export interface UnifiedFinding {
  id: string;
  scan_id: string;
  test_id: string;
  title: string;
  owasp_category: string;
  owasp_category_code: string; // 'A01' to 'A10'
  source_severity: SeverityLevel;
  /** Only populated when a standards-based CVSS score is calculated or imported from a trusted source. */
  official_cvss_score: number | null;
  official_cvss_version: '3.1' | '4.0' | null;
  official_cvss_vector: string | null;
  contextual_remediation_priority: number; // 0.0 - 10.0
  affected_url: string;
  parameter: string | null;
  verification_status: VerificationStatus;
  remediation_status: RemediationStatus;
  verification_notes: string;
  remediation_guidance: string;
  cwe_id: string;
  sources?: FindingSource[];
  evidence?: FindingEvidence[];
  created_at: string;
}

export interface VerificationAttempt {
  id: string;
  finding_id: string;
  timestamp: string;
  retest_type: 'reproduce_exploit' | 'check_header' | 'probe_endpoint';
  outcome: 'still_vulnerable' | 'remediated' | 'inconclusive';
  retest_evidence: string;
}

export interface ProxyAccessLog {
  id: string;
  scan_id: string;
  timestamp: string;
  method: string;
  destination_host: string;
  destination_port: number;
  destination_ip: string;
  url: string;
  status_code: number;
  blocked: boolean;
  block_reason?: string;
  client_tool: string;
}

export interface OWASPCoverageSummary {
  category_code: string; // 'A01' to 'A10'
  category_title: string;
  tests_total: number;
  tests_executed: number;
  vulnerabilities_found: number;
  status: 'tested' | 'partially_tested' | 'manual_review_required' | 'not_tested';
}

export interface ResearchMetrics {
  precision: number | 'Undefined';
  recall: number | 'Undefined';
  false_positive_rate: number | 'Undefined';
  false_positive_reduction: number | 'Undefined';
  duplicate_reduction: number | 'Undefined';
  time_overhead_pct: number | 'Undefined';
  request_overhead_pct: number | 'Undefined';
  verification_accuracy: number | 'Undefined';
  tp_count: number;
  fp_count: number;
  fn_count: number;
  tn_count: number;
  sample_size: number;
  raw_alerts_count: number;
  unified_findings_count: number;
  total_requests: number;
  duration_seconds: number;
}
