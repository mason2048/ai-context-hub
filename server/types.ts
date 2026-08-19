export type ItemCategory = 'rule' | 'skill' | 'knowledge' | 'tool';
export type ItemScope = 'global' | 'project' | 'task';
export type RiskKind = 'conflict' | 'duplicate' | 'broken-reference' | 'secret' | 'semantic-conflict';
export type SourceKind = 'local-project' | 'context-package';
export type BudgetPolicy = 'warn' | 'block' | 'auto-trim';

export interface SourceLocation {
  relativePath: string;
  uri: string;
  locator: string;
  startLine: number;
  endLine: number;
  revision: string;
  modifiedAt: string;
}

export interface ContextEntry {
  id: string;
  logicalKey: string;
  title: string;
  category: ItemCategory;
  packageType: 'fact' | 'instruction' | 'preference' | 'workflow' | 'reference' | 'secret-warning';
  scope: ItemScope;
  content: string;
  summary: string;
  source: SourceLocation;
  sensitivity: 'public' | 'internal' | 'sensitive' | 'secret';
  validity?: { observedAt: string; expiresAt: string | null; confidence: number };
  tags: string[];
  riskIds: string[];
  tokenCount: number;
  tokenEncoding: 'o200k_base';
  /** Compatibility alias for v0.1 clients. It is now exact, not estimated. */
  tokenEstimate: number;
}

export interface RiskSide {
  itemId: string;
  title: string;
  source: string;
  locator: string;
  excerpt: string;
}

export interface ContextRisk {
  id: string;
  kind: RiskKind;
  severity: 'warning' | 'danger';
  title: string;
  description: string;
  sides: RiskSide[];
  analyzerId?: string;
}

export interface ScanRules {
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

export interface ScanPerformance {
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
}

export interface AnalyzerDescriptor {
  id: string;
  version: string;
  mode: 'local' | 'local-http';
  privacy: string;
  status: 'ok' | 'degraded' | 'disabled';
}

export interface ScanResult {
  rootPath: string;
  projectName: string;
  sourceKind: SourceKind;
  scannedAt: string;
  entries: ContextEntry[];
  risks: ContextRisk[];
  warnings: string[];
  analyzers: AnalyzerDescriptor[];
  stats: {
    filesScanned: number;
    entries: number;
    risks: number;
    tokenCount: number;
    tokenEstimate: number;
    tokenEncoding: 'o200k_base';
    healthScore: number;
    performance: ScanPerformance;
  };
  rules: ScanRules;
}

export interface FileIndexEntry {
  statKey: string;
  revision: string;
  entries: ContextEntry[];
}

export interface ScanIndex {
  version: 1;
  rootRevision: string;
  files: Record<string, FileIndexEntry>;
}

export type ScanPhase = 'discover' | 'read' | 'analyze' | 'persist' | 'done';

export interface ScanProgress {
  phase: ScanPhase;
  processed: number;
  total: number | null;
  percent: number;
  message: string;
}

export interface ScanOptions {
  previousIndex?: ScanIndex;
  maxFileBytes?: number;
  maxFiles?: number;
  maxDirectories?: number;
  maxFsEntries?: number;
  maxEntriesPerFile?: number;
  maxEntries?: number;
  maxRisks?: number;
  maxClaims?: number;
  maxTotalBytes?: number;
  concurrency?: number;
  analyzer?: Analyzer;
  signal?: AbortSignal;
  onProgress?: (progress: ScanProgress) => void;
}

export interface AnalysisResult {
  risks: ContextRisk[];
  warnings: string[];
  descriptor: AnalyzerDescriptor;
  truncated?: boolean;
}

export interface Analyzer {
  readonly descriptor: Omit<AnalyzerDescriptor, 'status'>;
  analyze(entries: readonly ContextEntry[], rootPath: string, signal?: AbortSignal): Promise<AnalysisResult>;
}

export interface ScanExecution {
  result: ScanResult;
  index: ScanIndex;
  /** Revalidates the scanned root immediately before an immutable snapshot commit. */
  verifySource?: () => Promise<void>;
}

export interface ContextPackageItem {
  id: string;
  type: ContextEntry['packageType'];
  title: string;
  content: string;
  scope: ItemScope;
  source: { uri: string; revision: string; locator: string };
  validity: { observedAt: string; expiresAt: string | null; confidence: number };
  sensitivity: ContextEntry['sensitivity'];
  tags: string[];
}

export interface PackageSignature {
  algorithm: 'Ed25519';
  canonicalization: 'context-hub-jcs-v1';
  keyId: string;
  createdAt: string;
  publicKey: string;
  value: string;
}

export interface ContextPackage {
  schemaVersion: '0.1';
  packageId: string;
  name: string;
  kind: 'repository' | 'web' | 'memory' | 'rule' | 'mixed';
  createdAt: string;
  producer: { name: string; version: string };
  items: ContextPackageItem[];
  warnings: unknown[];
  signature?: PackageSignature;
}

export interface SignatureVerification {
  status: 'unsigned' | 'valid-trusted' | 'valid-untrusted' | 'invalid';
  keyId: string | null;
  message: string;
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

export interface ProjectRecord {
  id: string;
  name: string;
  sourceKind: SourceKind;
  locator: string;
  createdAt: string;
  updatedAt: string;
  latestSnapshotId: string;
  snapshots: SnapshotMetadata[];
}

export interface StoredSnapshot {
  metadata: SnapshotMetadata;
  result: ScanResult;
  index: ScanIndex | null;
  diff: SnapshotDiff;
  /** Full canonical package identity, kept private so unknown extensions can affect collision checks without being persisted. */
  packageDigest?: string;
}

export interface SnapshotEnvelope {
  project: ProjectRecord;
  snapshot: SnapshotMetadata;
  diff: SnapshotDiff;
  result: ScanResult;
}

export interface PublicSnapshotMetadata extends SnapshotMetadata {}

export interface PublicProjectRecord extends Omit<ProjectRecord, 'locator' | 'snapshots'> {
  snapshots: PublicSnapshotMetadata[];
}

export interface BudgetConfig {
  maxTokens: number;
  policy: BudgetPolicy;
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
  budget: BudgetReport;
  signature: SignatureVerification;
}

export type ScanJobStatus = 'queued' | 'running' | 'completed' | 'partial' | 'cancelled' | 'failed';

export interface ScanJobView {
  id: string;
  status: ScanJobStatus;
  createdAt: string;
  updatedAt: string;
  progress: ScanProgress;
  envelope?: SnapshotEnvelope;
  partialResult?: ScanResult;
  error?: { code: string; message: string };
}
