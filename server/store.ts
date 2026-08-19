import { createHash, randomUUID } from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  chmod,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  stat,
  unlink,
} from 'node:fs/promises';
import path from 'node:path';
import type {
  ContextEntry,
  ContextRisk,
  ProjectRecord,
  ScanIndex,
  ScanResult,
  SignatureVerification,
  SnapshotDiff,
  SnapshotDiffItem,
  SnapshotEnvelope,
  SnapshotMetadata,
  SourceKind,
  StoredSnapshot,
} from './types.js';

const STORE_VERSION = 1 as const;
const MANIFEST_FILE = 'manifest.json';
const MAX_STORE_FILE_BYTES = 128 * 1024 * 1024;
const SAFE_ID = /^[a-z0-9][a-z0-9-]{0,127}$/;

interface StoreManifest {
  version: typeof STORE_VERSION;
  projects: Record<string, ProjectRecord>;
}

export interface SnapshotStoreOptions {
  /** Retention is deliberately capped so a forgotten local store cannot grow forever. */
  maxSnapshotsPerProject?: number;
  /** Primarily a deterministic test seam; production defaults to the fixed 128 MiB read ceiling. */
  maxStoreFileBytes?: number;
  now?: () => Date;
}

export interface SaveSnapshotOptions {
  /** A virtual locator (normally package:<id>) may identify an imported package. */
  locator?: string;
  signatureVerification?: SignatureVerification;
  /** Cancellation is a commit gate: an aborted save never advances the latest manifest pointer. */
  signal?: AbortSignal;
  /** Canonical full-package digest for atomic idempotency/collision checks. */
  packageDigest?: string;
  /** Local-source identity/revision gate run immediately before latest changes. */
  verifySource?: () => Promise<void>;
}

export interface StoreDiagnostic {
  code: 'MANIFEST_CORRUPT' | 'SNAPSHOT_CORRUPT';
  path: string;
  message: string;
}

export interface PublicProjectRecord extends Omit<ProjectRecord, 'locator'> {}

export interface PublicSnapshotView {
  metadata: SnapshotMetadata;
  diff: SnapshotDiff;
  result: Omit<ScanResult, 'rootPath'>;
}

export class StoreCorruptionError extends Error {
  readonly name = 'StoreCorruptionError';

  constructor(
    readonly code: StoreDiagnostic['code'],
    readonly filePath: string,
    message: string,
  ) {
    super(message);
  }
}

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function clone<T>(value: T): T {
  return structuredClone(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function cleanDisplay(value: unknown, fallback: string, maximum = 2_000): string {
  if (typeof value !== 'string') return fallback;
  const clean = value.replace(/\0/g, '').replace(/[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, ' ').trim();
  if (!clean) return fallback;
  return clean.length > maximum ? `${clean.slice(0, maximum - 1)}…` : clean;
}

function cleanStrings(value: unknown, maximumItems: number, maximumLength: number): string[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, maximumItems).map((item) => cleanDisplay(item, '', maximumLength)).filter(Boolean);
}

function safeRelativePath(value: unknown): string {
  const raw = cleanDisplay(value, 'unknown-source', 2_000).replace(/\\/g, '/');
  const normalized = path.posix.normalize(raw).replace(/^\.\//, '');
  if (
    normalized === '..'
    || normalized.startsWith('../')
    || normalized.startsWith('/')
    || /^[A-Za-z]:\//.test(normalized)
  ) return `redacted-source/${digest(raw).slice(0, 20)}`;
  return normalized || 'unknown-source';
}

function safeSourceUri(uri: unknown, relativePath: string, sourceKind: SourceKind): string {
  if (sourceKind === 'local-project') {
    return `context-hub://local/${relativePath.split('/').map(encodeURIComponent).join('/')}`;
  }
  const raw = cleanDisplay(uri, '', 4_096);
  try {
    const parsed = new URL(raw);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      parsed.username = '';
      parsed.password = '';
      parsed.search = '';
      parsed.hash = '';
      return parsed.toString();
    }
    if (parsed.protocol === 'context-package:' || parsed.protocol === 'context-hub:') return parsed.toString();
  } catch {
    // Opaque and file sources receive a local display handle below.
  }
  return `context-hub://imported/${digest(raw || relativePath).slice(0, 24)}`;
}

function finiteInteger(value: unknown, fallback = 0, maximum = Number.MAX_SAFE_INTEGER): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.max(0, Math.min(maximum, Math.round(value)))
    : fallback;
}

function finiteNumber(value: unknown, fallback = 0, minimum = 0, maximum = 1): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.max(minimum, Math.min(maximum, value))
    : fallback;
}

function isoDate(value: unknown, fallback: string): string {
  if (typeof value !== 'string' || !Number.isFinite(Date.parse(value))) return fallback;
  return new Date(value).toISOString();
}

function sanitizeEntry(entry: ContextEntry, sourceKind: SourceKind, fallbackDate: string): ContextEntry {
  const relativePath = safeRelativePath(entry.source?.relativePath);
  const title = cleanDisplay(entry.title, '未命名条目', 500);
  const content = typeof entry.content === 'string' ? entry.content.replace(/\0/g, '') : '';
  const tokenCount = finiteInteger(entry.tokenCount ?? entry.tokenEstimate, 0);
  const validity = entry.validity && isRecord(entry.validity)
    ? {
        observedAt: isoDate(entry.validity.observedAt, fallbackDate),
        expiresAt: entry.validity.expiresAt === null ? null : isoDate(entry.validity.expiresAt, fallbackDate),
        confidence: finiteNumber(entry.validity.confidence, 0),
      }
    : undefined;
  return {
    id: cleanDisplay(entry.id, `item-${digest(`${relativePath}\0${title}\0${content}`).slice(0, 24)}`, 256),
    logicalKey: cleanDisplay(entry.logicalKey, `logical-${digest(`${relativePath}\0${title}`).slice(0, 24)}`, 256),
    title,
    category: ['rule', 'skill', 'knowledge', 'tool'].includes(entry.category) ? entry.category : 'knowledge',
    packageType: ['fact', 'instruction', 'preference', 'workflow', 'reference', 'secret-warning'].includes(entry.packageType)
      ? entry.packageType
      : 'reference',
    scope: ['global', 'project', 'task'].includes(entry.scope) ? entry.scope : 'project',
    content,
    summary: cleanDisplay(entry.summary, title, 1_000),
    source: {
      relativePath,
      uri: safeSourceUri(entry.source?.uri, relativePath, sourceKind),
      locator: cleanDisplay(entry.source?.locator, '来源定位不可用', 1_000),
      startLine: Math.max(1, finiteInteger(entry.source?.startLine, 1)),
      endLine: Math.max(1, finiteInteger(entry.source?.endLine, 1)),
      revision: cleanDisplay(entry.source?.revision, `unknown-${digest(content)}`, 512),
      modifiedAt: isoDate(entry.source?.modifiedAt, fallbackDate),
    },
    sensitivity: ['public', 'internal', 'sensitive', 'secret'].includes(entry.sensitivity)
      ? entry.sensitivity
      : 'internal',
    ...(validity ? { validity } : {}),
    tags: cleanStrings(entry.tags, 256, 200),
    riskIds: cleanStrings(entry.riskIds, 1_000, 256),
    tokenCount,
    tokenEncoding: 'o200k_base',
    tokenEstimate: tokenCount,
  };
}

function sanitizeRisk(risk: ContextRisk): ContextRisk {
  return {
    id: cleanDisplay(risk.id, `risk-${digest(JSON.stringify(risk)).slice(0, 24)}`, 256),
    kind: ['conflict', 'duplicate', 'broken-reference', 'secret', 'semantic-conflict'].includes(risk.kind)
      ? risk.kind
      : 'semantic-conflict',
    severity: risk.severity === 'danger' ? 'danger' : 'warning',
    title: cleanDisplay(risk.title, '上下文风险', 500),
    description: cleanDisplay(risk.description, '未提供说明。', 2_000),
    sides: Array.isArray(risk.sides) ? risk.sides.slice(0, 100).map((side) => ({
      itemId: cleanDisplay(side?.itemId, 'unknown-item', 256),
      title: cleanDisplay(side?.title, '未命名条目', 500),
      source: safeRelativePath(side?.source),
      locator: cleanDisplay(side?.locator, '来源定位不可用', 1_000),
      excerpt: cleanDisplay(side?.excerpt, '', 2_000),
    })) : [],
    ...(typeof risk.analyzerId === 'string' ? { analyzerId: cleanDisplay(risk.analyzerId, 'unknown', 256) } : {}),
  };
}

/** Removes absolute roots, file URIs, unknown fields, and non-finite counters. */
export function sanitizeScanResult(result: ScanResult): ScanResult {
  const scannedAt = isoDate(result.scannedAt, new Date(0).toISOString());
  const sourceKind: SourceKind = result.sourceKind === 'context-package' ? 'context-package' : 'local-project';
  const entries = Array.isArray(result.entries)
    ? result.entries.slice(0, 100_000).map((entry) => sanitizeEntry(entry, sourceKind, scannedAt))
    : [];
  const risks = Array.isArray(result.risks) ? result.risks.slice(0, 100_000).map(sanitizeRisk) : [];
  const performance = result.stats?.performance;
  return {
    rootPath: '',
    projectName: cleanDisplay(result.projectName, '未命名项目', 500),
    sourceKind,
    scannedAt,
    entries,
    risks,
    warnings: cleanStrings(result.warnings, 10_000, 2_000),
    analyzers: Array.isArray(result.analyzers) ? result.analyzers.slice(0, 100).map((analyzer) => ({
      id: cleanDisplay(analyzer?.id, 'unknown', 256),
      version: cleanDisplay(analyzer?.version, 'unknown', 128),
      mode: analyzer?.mode === 'local-http' ? 'local-http' : 'local',
      privacy: cleanDisplay(analyzer?.privacy, '未提供隐私说明。', 1_000),
      status: analyzer?.status === 'degraded' || analyzer?.status === 'disabled' ? analyzer.status : 'ok',
    })) : [],
    stats: {
      filesScanned: finiteInteger(result.stats?.filesScanned, 0),
      entries: entries.length,
      risks: risks.length,
      tokenCount: entries.reduce((sum, entry) => sum + entry.tokenCount, 0),
      tokenEstimate: entries.reduce((sum, entry) => sum + entry.tokenCount, 0),
      tokenEncoding: 'o200k_base',
      healthScore: finiteNumber(result.stats?.healthScore, 100, 0, 100),
      performance: {
        directoriesVisited: finiteInteger(performance?.directoriesVisited, 0),
        fsEntriesVisited: finiteInteger(performance?.fsEntriesVisited, 0),
        candidatesDiscovered: finiteInteger(performance?.candidatesDiscovered, 0),
        filesRead: finiteInteger(performance?.filesRead, 0),
        cacheHits: finiteInteger(performance?.cacheHits, 0),
        cacheMisses: finiteInteger(performance?.cacheMisses, 0),
        ignoredPaths: finiteInteger(performance?.ignoredPaths, 0),
        totalBytesRead: finiteInteger(performance?.totalBytesRead, 0),
        durationMs: finiteInteger(performance?.durationMs, 0),
        truncated: performance?.truncated === true,
      },
    },
    rules: {
      included: cleanStrings(result.rules?.included, 1_000, 1_000),
      excludedDirectories: cleanStrings(result.rules?.excludedDirectories, 10_000, 1_000),
      excludedFiles: cleanStrings(result.rules?.excludedFiles, 10_000, 1_000),
      maxFileBytes: finiteInteger(result.rules?.maxFileBytes, 0),
      maxFiles: finiteInteger(result.rules?.maxFiles, 0),
      maxDirectories: finiteInteger(result.rules?.maxDirectories, 0),
      maxFsEntries: finiteInteger(result.rules?.maxFsEntries, 100_000),
      maxEntriesPerFile: finiteInteger(result.rules?.maxEntriesPerFile, 1_000),
      maxEntries: finiteInteger(result.rules?.maxEntries, 5_000),
      maxRisks: finiteInteger(result.rules?.maxRisks, 5_000),
      maxClaims: finiteInteger(result.rules?.maxClaims, 20_000),
      maxTotalBytes: finiteInteger(result.rules?.maxTotalBytes, 32 * 1024 * 1024),
      concurrency: finiteInteger(result.rules?.concurrency, 1, 1_000),
    },
  };
}

export function sanitizeScanIndex(index: ScanIndex | null | undefined, sourceKind: SourceKind, fallbackDate: string): ScanIndex | null {
  if (!index || index.version !== 1 || !isRecord(index.files)) return null;
  const files: ScanIndex['files'] = {};
  for (const [rawPath, file] of Object.entries(index.files).slice(0, 100_000)) {
    if (!isRecord(file)) continue;
    const relativePath = safeRelativePath(rawPath);
    const rawEntries = Array.isArray(file.entries) ? file.entries : [];
    files[relativePath] = {
      statKey: cleanDisplay(file.statKey, `stat-${digest(relativePath)}`, 1_000),
      revision: cleanDisplay(file.revision, 'unknown', 512),
      entries: rawEntries.slice(0, 1_000).map((entry) => sanitizeEntry(entry as ContextEntry, sourceKind, fallbackDate)),
    };
  }
  return {
    version: 1,
    rootRevision: cleanDisplay(index.rootRevision, `root-${digest(Object.keys(files).sort().join('\0'))}`, 1_000),
    files,
  };
}

function itemForDiff(entry: ContextEntry, before: boolean): SnapshotDiffItem {
  return {
    logicalKey: entry.logicalKey,
    title: entry.title,
    source: entry.source.relativePath,
    ...(before ? { beforeId: entry.id } : { afterId: entry.id }),
  };
}

function fileRevisions(result: ScanResult, index: ScanIndex | null): Map<string, string> {
  if (index) return new Map(Object.entries(index.files).map(([name, file]) => [name, file.revision]));
  const groups = new Map<string, string[]>();
  for (const entry of result.entries) {
    const group = groups.get(entry.source.relativePath) ?? [];
    group.push(`${entry.logicalKey}:${entry.source.revision}`);
    groups.set(entry.source.relativePath, group);
  }
  return new Map([...groups].map(([name, revisions]) => [name, digest(revisions.sort().join('\0'))]));
}

function riskKeys(result: ScanResult): Set<string> {
  return new Set(result.risks.map((risk) => risk.id));
}

/** Computes semantic entry changes by stable logical key and source revision. */
export function computeSnapshotDiff(
  previous: StoredSnapshot | null,
  currentResult: ScanResult,
  currentIndex: ScanIndex | null,
  toSnapshotId: string,
): SnapshotDiff {
  const beforeEntries = new Map((previous?.result.entries ?? []).map((entry) => [entry.logicalKey, entry]));
  const afterEntries = new Map(currentResult.entries.map((entry) => [entry.logicalKey, entry]));
  const added: SnapshotDiffItem[] = [];
  const removed: SnapshotDiffItem[] = [];
  const changed: SnapshotDiffItem[] = [];
  let unchanged = 0;

  for (const [logicalKey, entry] of afterEntries) {
    const before = beforeEntries.get(logicalKey);
    if (!before) added.push(itemForDiff(entry, false));
    else if (before.source.revision !== entry.source.revision) {
      changed.push({
        logicalKey,
        title: entry.title,
        source: entry.source.relativePath,
        beforeId: before.id,
        afterId: entry.id,
      });
    } else unchanged += 1;
  }
  for (const [logicalKey, entry] of beforeEntries) {
    if (!afterEntries.has(logicalKey)) removed.push(itemForDiff(entry, true));
  }

  const beforeFiles = previous ? fileRevisions(previous.result, previous.index) : new Map<string, string>();
  const afterFiles = fileRevisions(currentResult, currentIndex);
  const files = { added: [] as string[], removed: [] as string[], changed: [] as string[], unchanged: 0 };
  for (const [name, revision] of afterFiles) {
    const beforeRevision = beforeFiles.get(name);
    if (beforeRevision === undefined) files.added.push(name);
    else if (beforeRevision !== revision) files.changed.push(name);
    else files.unchanged += 1;
  }
  for (const name of beforeFiles.keys()) if (!afterFiles.has(name)) files.removed.push(name);

  const beforeRisks = previous ? riskKeys(previous.result) : new Set<string>();
  const afterRisks = riskKeys(currentResult);
  const byKey = (left: SnapshotDiffItem, right: SnapshotDiffItem) => left.logicalKey.localeCompare(right.logicalKey);
  added.sort(byKey);
  removed.sort(byKey);
  changed.sort(byKey);
  files.added.sort();
  files.removed.sort();
  files.changed.sort();
  return {
    fromSnapshotId: previous?.metadata.id ?? null,
    toSnapshotId,
    added,
    removed,
    changed,
    unchanged,
    files,
    risks: {
      added: [...afterRisks].filter((id) => !beforeRisks.has(id)).length,
      removed: [...beforeRisks].filter((id) => !afterRisks.has(id)).length,
    },
  };
}

export function stableProjectId(sourceKind: SourceKind, locator: string): string {
  const prefix = sourceKind === 'local-project' ? 'local' : 'package';
  const normalized = sourceKind === 'local-project'
    ? path.resolve(locator).normalize('NFC')
    : cleanDisplay(locator, 'context-package', 8_000).normalize('NFC');
  return `${prefix}-${digest(`${sourceKind}\0${normalized}`).slice(0, 32)}`;
}

function isWithin(child: string, parent: string): boolean {
  const relative = path.relative(parent, child);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

async function canonicalizePotentialPath(target: string): Promise<string> {
  let cursor = path.resolve(target);
  const missing: string[] = [];
  while (true) {
    try {
      return path.join(await realpath(cursor), ...missing.reverse());
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== 'ENOENT' && code !== 'ENOTDIR') throw error;
      const parent = path.dirname(cursor);
      if (parent === cursor) throw error;
      missing.push(path.basename(cursor));
      cursor = parent;
    }
  }
}

/** Rejects any physical, lexical, or symlink-resolved overlap before the store creates a file. */
export async function assertStoreOutsideProject(dataDirectory: string, projectDirectory: string): Promise<void> {
  const canonicalProject = await realpath(projectDirectory);
  const canonicalStore = await canonicalizePotentialPath(dataDirectory);
  const lexicalStore = path.resolve(dataDirectory);
  if (
    isWithin(canonicalStore, canonicalProject)
    || isWithin(lexicalStore, canonicalProject)
    || isWithin(canonicalProject, canonicalStore)
  ) {
    throw new Error('上下文快照数据目录不能与被扫描项目重叠。');
  }
}

function copyMetadata(metadata: SnapshotMetadata): SnapshotMetadata {
  return clone(metadata);
}

export function toPublicProjectRecord(project: ProjectRecord): PublicProjectRecord {
  return {
    id: project.id,
    name: project.name,
    sourceKind: project.sourceKind,
    createdAt: project.createdAt,
    updatedAt: project.updatedAt,
    latestSnapshotId: project.latestSnapshotId,
    snapshots: project.snapshots.map(copyMetadata),
  };
}

export function toPublicSnapshotView(snapshot: StoredSnapshot): PublicSnapshotView {
  const { rootPath: _privateRoot, ...publicResult } = sanitizeScanResult(snapshot.result);
  return {
    metadata: copyMetadata(snapshot.metadata),
    diff: clone(snapshot.diff),
    result: publicResult,
  };
}

async function syncDirectory(directory: string): Promise<void> {
  let handle;
  try {
    handle = await open(directory, fsConstants.O_RDONLY);
    await handle.sync();
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (!['EINVAL', 'ENOTSUP', 'EBADF', 'EISDIR'].includes(code ?? '')) throw error;
  } finally {
    await handle?.close();
  }
}

async function secureDirectory(directory: string): Promise<void> {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
}

async function atomicWriteJson(filePath: string, value: unknown, maxBytes = MAX_STORE_FILE_BYTES): Promise<void> {
  const serialized = `${JSON.stringify(value)}\n`;
  if (Buffer.byteLength(serialized, 'utf8') > maxBytes) {
    const error = new Error('快照序列化后超过本地存储安全上限，latest 未修改。');
    error.name = 'SnapshotTooLargeError';
    throw error;
  }
  const directory = path.dirname(filePath);
  await secureDirectory(directory);
  const temporary = path.join(directory, `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
    await handle.writeFile(serialized, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await chmod(temporary, 0o600);
    await rename(temporary, filePath);
    await chmod(filePath, 0o600);
    await syncDirectory(directory);
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

async function readJsonFile(filePath: string): Promise<unknown> {
  const info = await stat(filePath);
  if (!info.isFile() || info.size > MAX_STORE_FILE_BYTES) throw new Error('存储文件不是受支持的普通 JSON 文件。');
  return JSON.parse(await readFile(filePath, 'utf8')) as unknown;
}

function throwIfAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  const error = new Error('快照保存已取消。');
  error.name = 'AbortError';
  throw error;
}

function isSnapshotMetadata(value: unknown): value is SnapshotMetadata {
  return isRecord(value)
    && typeof value.id === 'string'
    && typeof value.projectId === 'string'
    && typeof value.capturedAt === 'string'
    && (value.parentSnapshotId === null || typeof value.parentSnapshotId === 'string')
    && typeof value.entries === 'number'
    && typeof value.risks === 'number'
    && typeof value.tokenCount === 'number'
    && typeof value.durationMs === 'number'
    && typeof value.cacheHits === 'number'
    && (value.sourceKind === 'local-project' || value.sourceKind === 'context-package');
}

function isProjectRecord(value: unknown): value is ProjectRecord {
  return isRecord(value)
    && typeof value.id === 'string'
    && typeof value.name === 'string'
    && (value.sourceKind === 'local-project' || value.sourceKind === 'context-package')
    && typeof value.locator === 'string'
    && typeof value.createdAt === 'string'
    && typeof value.updatedAt === 'string'
    && typeof value.latestSnapshotId === 'string'
    && Array.isArray(value.snapshots)
    && value.snapshots.every(isSnapshotMetadata);
}

function parseManifest(value: unknown): StoreManifest {
  if (!isRecord(value) || value.version !== STORE_VERSION || !isRecord(value.projects)) {
    throw new Error('manifest 结构或版本无效。');
  }
  const projects: Record<string, ProjectRecord> = {};
  for (const [id, project] of Object.entries(value.projects)) {
    if (!SAFE_ID.test(id) || !isProjectRecord(project) || project.id !== id) throw new Error('manifest 项目记录无效。');
    projects[id] = clone(project);
  }
  return { version: STORE_VERSION, projects };
}

function parseStoredSnapshot(value: unknown, projectId: string, snapshotId: string): StoredSnapshot {
  if (!isRecord(value)
    || !isSnapshotMetadata(value.metadata)
    || value.metadata.projectId !== projectId
    || value.metadata.id !== snapshotId
    || !isRecord(value.result)
    || !isRecord(value.diff)) {
    throw new Error('快照结构或标识无效。');
  }
  const snapshot = value as unknown as StoredSnapshot;
  const sanitizedResult = sanitizeScanResult(snapshot.result);
  const sanitizedIndex = sanitizeScanIndex(snapshot.index, sanitizedResult.sourceKind, sanitizedResult.scannedAt);
  return {
    metadata: copyMetadata(snapshot.metadata),
    result: sanitizedResult,
    index: sanitizedIndex,
    diff: clone(snapshot.diff),
    ...(typeof snapshot.packageDigest === 'string' && /^sha256:[a-f0-9]{64}$/.test(snapshot.packageDigest)
      ? { packageDigest: snapshot.packageDigest }
      : {}),
  };
}

function safeIdentifier(value: string, label: string): void {
  if (!SAFE_ID.test(value)) throw new Error(`${label}格式无效。`);
}

function importedLocator(result: ScanResult, explicit?: string): string {
  if (explicit) return cleanDisplay(explicit, '', 8_000);
  if (result.rootPath) return cleanDisplay(result.rootPath, '', 8_000);
  const logicalKeys = result.entries.map((entry) => entry.logicalKey).sort().join('\0');
  return `context-package:${digest(`${result.projectName}\0${logicalKeys}`)}`;
}

export class SnapshotStore {
  readonly dataDirectory: string;
  readonly maxSnapshotsPerProject: number;
  readonly maxStoreFileBytes: number;
  private readonly now: () => Date;
  private manifest: StoreManifest | null = null;
  private manifestCorruption: StoreCorruptionError | null = null;
  private diagnostics: StoreDiagnostic[] = [];
  private mutationQueue: Promise<void> = Promise.resolve();

  constructor(dataDirectory: string, options: SnapshotStoreOptions = {}) {
    if (!dataDirectory || !path.isAbsolute(dataDirectory)) throw new Error('快照数据目录必须是绝对路径。');
    this.dataDirectory = path.resolve(dataDirectory);
    this.maxSnapshotsPerProject = Math.max(1, Math.min(50, Math.round(options.maxSnapshotsPerProject ?? 50)));
    this.maxStoreFileBytes = Math.max(1_024, Math.min(MAX_STORE_FILE_BYTES, Math.round(options.maxStoreFileBytes ?? MAX_STORE_FILE_BYTES)));
    this.now = options.now ?? (() => new Date());
  }

  async initialize(): Promise<void> {
    const manifestPath = path.join(this.dataDirectory, MANIFEST_FILE);
    try {
      this.manifest = parseManifest(await readJsonFile(manifestPath));
      this.manifestCorruption = null;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        const empty: StoreManifest = { version: STORE_VERSION, projects: {} };
        this.manifest = empty;
        this.manifestCorruption = null;
        return;
      }
      const corruption = new StoreCorruptionError('MANIFEST_CORRUPT', manifestPath, '本地快照 manifest 已损坏；存储已进入只读安全降级，原文件不会被覆盖。');
      this.manifest = { version: STORE_VERSION, projects: {} };
      this.manifestCorruption = corruption;
      this.recordDiagnostic(corruption);
    }
  }

  getDiagnostics(): StoreDiagnostic[] {
    return clone(this.diagnostics);
  }

  isReadOnly(): boolean {
    return this.manifestCorruption !== null;
  }

  async listProjects(): Promise<ProjectRecord[]> {
    await this.ensureInitialized();
    return Object.values(this.manifest!.projects)
      .map((project) => clone(project))
      .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
  }

  async getProject(projectId: string): Promise<ProjectRecord | null> {
    safeIdentifier(projectId, '项目 ID');
    await this.ensureInitialized();
    const project = this.manifest!.projects[projectId];
    return project ? clone(project) : null;
  }

  async listSnapshots(projectId: string): Promise<SnapshotMetadata[]> {
    return (await this.getProject(projectId))?.snapshots.map(copyMetadata) ?? [];
  }

  async getLatestSnapshot(projectId: string): Promise<StoredSnapshot | null> {
    const project = await this.getProject(projectId);
    return project ? this.getSnapshot(projectId, project.latestSnapshotId) : null;
  }

  async getSnapshot(projectId: string, snapshotId?: string): Promise<StoredSnapshot | null> {
    safeIdentifier(projectId, '项目 ID');
    await this.ensureInitialized();
    const project = this.manifest!.projects[projectId];
    if (!project) return null;
    const targetId = snapshotId ?? project.latestSnapshotId;
    safeIdentifier(targetId, '快照 ID');
    if (!project.snapshots.some((snapshot) => snapshot.id === targetId)) return null;
    const filePath = this.snapshotPath(projectId, targetId);
    try {
      return parseStoredSnapshot(await readJsonFile(filePath), projectId, targetId);
    } catch (error) {
      if (error instanceof StoreCorruptionError) throw error;
      const corruption = new StoreCorruptionError('SNAPSHOT_CORRUPT', filePath, `快照 ${targetId} 已损坏或丢失；原文件不会被覆盖。`);
      this.recordDiagnostic(corruption);
      throw corruption;
    }
  }

  async saveSnapshot(
    result: ScanResult,
    index: ScanIndex | null = null,
    verificationOrOptions: SignatureVerification | SaveSnapshotOptions = {},
  ): Promise<SnapshotEnvelope> {
    const options: SaveSnapshotOptions = 'status' in verificationOrOptions
      ? { signatureVerification: verificationOrOptions }
      : verificationOrOptions;
    let output!: SnapshotEnvelope;
    const operation = this.mutationQueue.then(async () => {
      output = await this.saveSnapshotLocked(result, index, options);
    });
    this.mutationQueue = operation.catch(() => undefined);
    await operation;
    return output;
  }

  private async saveSnapshotLocked(result: ScanResult, index: ScanIndex | null, options: SaveSnapshotOptions): Promise<SnapshotEnvelope> {
    throwIfAborted(options.signal);
    await this.ensureInitialized();
    if (this.manifestCorruption) throw this.manifestCorruption;

    let locator: string;
    if (result.sourceKind === 'local-project') {
      if (!result.rootPath || !path.isAbsolute(result.rootPath)) throw new Error('本地项目快照必须提供绝对项目路径。');
      locator = await realpath(result.rootPath);
      await assertStoreOutsideProject(this.dataDirectory, locator);
      await options.verifySource?.();
    } else {
      locator = importedLocator(result, options.locator);
    }
    const projectId = stableProjectId(result.sourceKind, locator);
    const capturedAt = this.now().toISOString();
    const sanitizedResult = sanitizeScanResult(result);
    const sanitizedIndex = sanitizeScanIndex(index, sanitizedResult.sourceKind, sanitizedResult.scannedAt);
    const existingProject = this.manifest!.projects[projectId];
    let previous: StoredSnapshot | null = null;
    if (existingProject?.latestSnapshotId) {
      try { previous = await this.getSnapshot(projectId, existingProject.latestSnapshotId); }
      catch (error) {
        if (!(error instanceof StoreCorruptionError)) throw error;
        // A new immutable snapshot can still be saved; the corrupt predecessor is retained and reported.
      }
    }

    const snapshotId = `snapshot-${capturedAt.replace(/[-:.TZ]/g, '').slice(0, 17)}-${randomUUID().replace(/-/g, '').slice(0, 16)}`;
    const metadata: SnapshotMetadata = {
      id: snapshotId,
      projectId,
      capturedAt,
      parentSnapshotId: previous?.metadata.id ?? null,
      entries: sanitizedResult.entries.length,
      risks: sanitizedResult.risks.length,
      tokenCount: sanitizedResult.stats.tokenCount,
      durationMs: sanitizedResult.stats.performance.durationMs,
      cacheHits: sanitizedResult.stats.performance.cacheHits,
      sourceKind: sanitizedResult.sourceKind,
      ...(options.signatureVerification ? { signatureVerification: clone(options.signatureVerification) } : {}),
    };
    const diff = computeSnapshotDiff(previous, sanitizedResult, sanitizedIndex, snapshotId);
    const stored: StoredSnapshot = {
      metadata,
      result: sanitizedResult,
      index: sanitizedIndex,
      diff,
      ...(options.packageDigest && /^sha256:[a-f0-9]{64}$/.test(options.packageDigest)
        ? { packageDigest: options.packageDigest }
        : {}),
    };

    // Durability order matters: publish the immutable snapshot before moving latest in the manifest.
    const projectDirectory = path.dirname(this.snapshotPath(projectId, snapshotId));
    throwIfAborted(options.signal);
    await secureDirectory(this.dataDirectory);
    await secureDirectory(path.join(this.dataDirectory, 'snapshots'));
    await secureDirectory(projectDirectory);
    const snapshotPath = this.snapshotPath(projectId, snapshotId);
    await options.verifySource?.();
    await atomicWriteJson(snapshotPath, stored, this.maxStoreFileBytes);

    // Cancellation may leave private directories, but never an immutable snapshot or a moved latest pointer.
    if (options.signal?.aborted) {
      await unlink(snapshotPath).catch(() => undefined);
      await syncDirectory(projectDirectory);
      throwIfAborted(options.signal);
    }

    const allMetadata = [...(existingProject?.snapshots ?? []), metadata];
    const retained = allMetadata.slice(-this.maxSnapshotsPerProject);
    const project: ProjectRecord = {
      id: projectId,
      name: sanitizedResult.projectName,
      sourceKind: sanitizedResult.sourceKind,
      locator,
      createdAt: existingProject?.createdAt ?? capturedAt,
      updatedAt: capturedAt,
      latestSnapshotId: snapshotId,
      snapshots: retained,
    };
    const nextManifest: StoreManifest = {
      version: STORE_VERSION,
      projects: { ...this.manifest!.projects, [projectId]: project },
    };
    try {
      await options.verifySource?.();
    } catch (error) {
      await unlink(snapshotPath).catch(() => undefined);
      await syncDirectory(projectDirectory);
      throw error;
    }
    await atomicWriteJson(path.join(this.dataDirectory, MANIFEST_FILE), nextManifest, this.maxStoreFileBytes);
    this.manifest = nextManifest;

    // Remove only snapshots made unreachable by the already-durable manifest. Failure leaves a harmless orphan.
    const retainedIds = new Set(retained.map((snapshot) => snapshot.id));
    for (const expired of allMetadata) {
      if (!retainedIds.has(expired.id)) await unlink(this.snapshotPath(projectId, expired.id)).catch(() => undefined);
    }
    await syncDirectory(projectDirectory);
    return { project: clone(project), snapshot: copyMetadata(metadata), diff: clone(diff), result: clone(sanitizedResult) };
  }

  private snapshotPath(projectId: string, snapshotId: string): string {
    safeIdentifier(projectId, '项目 ID');
    safeIdentifier(snapshotId, '快照 ID');
    return path.join(this.dataDirectory, 'snapshots', projectId, `${snapshotId}.json`);
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.manifest) await this.initialize();
  }

  private recordDiagnostic(error: StoreCorruptionError): void {
    if (this.diagnostics.some((item) => item.code === error.code && item.path === error.filePath)) return;
    this.diagnostics.push({ code: error.code, path: error.filePath, message: error.message });
  }
}

export async function createSnapshotStore(dataDirectory: string, options: SnapshotStoreOptions = {}): Promise<SnapshotStore> {
  const store = new SnapshotStore(dataDirectory, options);
  await store.initialize();
  return store;
}
