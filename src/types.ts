export type Category = 'rule' | 'skill' | 'knowledge' | 'tool';
export type Scope = 'global' | 'project' | 'task';
export type RiskKind = 'conflict' | 'duplicate' | 'broken-reference' | 'secret' | 'semantic-conflict';
export type SourceKind = 'local-project' | 'context-package';
export type BudgetPolicy = 'warn' | 'block' | 'auto-trim';
export type ExportFormat = 'json' | 'agents';

export interface Entry {
  id: string;
  logicalKey: string;
  title: string;
  category: Category;
  packageType: 'fact' | 'instruction' | 'preference' | 'workflow' | 'reference' | 'secret-warning';
  scope: Scope;
  content: string;
  summary: string;
  source: {
    relativePath: string;
    uri: string;
    locator: string;
    startLine: number;
    endLine: number;
    revision: string;
    modifiedAt: string;
  };
  sensitivity: 'public' | 'internal' | 'sensitive' | 'secret';
  validity?: { observedAt: string; expiresAt: string | null; confidence: number };
  tags: string[];
  riskIds: string[];
  tokenCount: number;
  tokenEncoding: 'o200k_base';
  tokenEstimate: number;
}

export interface RiskSide {
  itemId: string;
  title: string;
  source: string;
  locator: string;
  excerpt: string;
}

export interface Risk {
  id: string;
  kind: RiskKind;
  severity: 'warning' | 'danger';
  title: string;
  description: string;
  sides: RiskSide[];
  analyzerId?: string;
}

export interface Rules {
  included: string[];
  excludedDirectories: string[];
  excludedFiles: string[];
  maxFileBytes: number;
  maxFiles: number;
  maxDirectories: number;
  maxFsEntries: number;
  maxEntriesPerFile: number;
  maxEntries: number;
  maxRisks: number;
  maxClaims: number;
  maxTotalBytes: number;
  concurrency: number;
}

export interface ScanProgress {
  phase: 'discover' | 'read' | 'analyze' | 'persist' | 'done';
  processed: number;
  total: number | null;
  percent: number;
  message: string;
}

export interface ScanResult {
  /** Persisted/public snapshots intentionally redact the physical root. */
  rootPath?: string;
  projectName: string;
  sourceKind: SourceKind;
  scannedAt: string;
  entries: Entry[];
  risks: Risk[];
  warnings: string[];
  analyzers: Array<{
    id: string;
    version: string;
    mode: 'local' | 'local-http';
    privacy: string;
    status: 'ok' | 'degraded' | 'disabled';
  }>;
  stats: {
    filesScanned: number;
    entries: number;
    risks: number;
    tokenCount: number;
    tokenEstimate: number;
    tokenEncoding: 'o200k_base';
    healthScore: number;
    performance: {
      directoriesVisited: number;
      fsEntriesVisited: number;
      candidatesDiscovered: number;
      filesRead: number;
      cacheHits: number;
      cacheMisses: number;
      ignoredPaths: number;
      totalBytesRead: number;
      durationMs: number;
      truncated: boolean;
    };
  };
  rules: Rules;
}

export interface SnapshotDiffItem {
  logicalKey: string;
  title: string;
  source: string;
  beforeId?: string;
  afterId?: string;
}

export interface SnapshotDiff {
  fromSnapshotId: string | null;
  toSnapshotId: string;
  added: SnapshotDiffItem[];
  removed: SnapshotDiffItem[];
  changed: SnapshotDiffItem[];
  unchanged: number;
  files: { added: string[]; removed: string[]; changed: string[]; unchanged: number };
  risks: { added: number; removed: number };
}

export interface SignatureVerification {
  status: 'unsigned' | 'valid-trusted' | 'valid-untrusted' | 'invalid';
  keyId: string | null;
  message: string;
}

export interface SnapshotMetadata {
  id: string;
  projectId: string;
  capturedAt: string;
  parentSnapshotId: string | null;
  entries: number;
  risks: number;
  tokenCount: number;
  durationMs: number;
  cacheHits: number;
  sourceKind: SourceKind;
  signatureVerification?: SignatureVerification;
}

export interface PublicProject {
  id: string;
  name: string;
  sourceKind: SourceKind;
  createdAt: string;
  updatedAt: string;
  latestSnapshotId: string;
  snapshots: SnapshotMetadata[];
}

export interface SnapshotView {
  metadata: SnapshotMetadata;
  diff: SnapshotDiff;
  result: ScanResult;
}

export interface WorkspaceData {
  project: PublicProject;
  snapshot: SnapshotView;
}

export interface ConfigResponse {
  samplePath: string;
  csrfToken: string;
  rules?: Rules;
  tokenizers: Array<string | { id?: string; encoding?: string; label?: string }>;
  defaultBudget: { maxTokens: number; policy: BudgetPolicy };
  signing: { available?: boolean; enabled?: boolean; keyId?: string; algorithm?: string };
}

export interface BudgetReport {
  encoding: 'o200k_base';
  maxTokens: number;
  exactTokens: number;
  policy: BudgetPolicy;
  exceeded: boolean;
  blocked: boolean;
  autoTrimmed: boolean;
  selectedIds: string[];
  omittedIds: string[];
  selectionRevision: string;
}

export interface ExportPreviewResult {
  content: string;
  filename: string;
  mediaType: string;
  selectionRevision?: string;
  budget: BudgetReport;
  signature?: SignatureVerification;
  signatureVerification?: SignatureVerification;
}

export interface PackageInspection {
  accepted: true;
  schemaVersion: '0.1';
  packageId: string;
  name: string;
  kind: 'repository' | 'web' | 'memory' | 'rule' | 'mixed';
  producer: { name: string; version: string };
  rawBytes: number;
  itemCount: number;
  sensitiveItemCount: number;
  secretWarningCount: number;
  contentBytes: number;
  exactTokens: number;
  tokenEncoding: 'o200k_base';
  sourceAccess: 'metadata-only';
  signatureVerification: SignatureVerification;
  warnings: string[];
  limits: { rawBytes: number; items: number; itemContentBytes: number; totalContentBytes: number; maxNestingDepth: number };
}

export interface PackageInspectionResponse {
  inspectionId: string;
  inspection: PackageInspection;
}

export type ScanJobStatus = 'queued' | 'running' | 'completed' | 'partial' | 'cancelled' | 'failed';

export interface CompletionEnvelope {
  project: PublicProject;
  snapshot: SnapshotView | SnapshotMetadata;
  diff?: SnapshotDiff;
  result?: ScanResult;
}

export interface ScanJob {
  id: string;
  status: ScanJobStatus;
  createdAt: string;
  updatedAt: string;
  progress: ScanProgress;
  result?: CompletionEnvelope;
  envelope?: CompletionEnvelope;
  partialResult?: ScanResult;
  error?: { code: string; message: string };
}
