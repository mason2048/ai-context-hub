import { createHash, randomBytes, randomUUID } from 'node:crypto';
import express, { type NextFunction, type Request, type Response } from 'express';
import os from 'node:os';
import path from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import {
  createExportPreview,
  isSelectionRevisionStale,
  TokenBudgetExceededError,
  type ExportFormat,
} from './exporter.js';
import { ScanJobManager } from './jobs.js';
import {
  inspectContextPackage,
  PackageImportError,
  PACKAGE_IMPORT_LIMITS,
  type PackageImportResult,
} from './package-import.js';
import { SCAN_RULES, scanProjectWithIndex } from './scanner.js';
import { SigningService } from './signing.js';
import {
  assertStoreOutsideProject,
  createSnapshotStore,
  sanitizeScanResult,
  stableProjectId,
  toPublicProjectRecord,
  toPublicSnapshotView,
  type SnapshotStore,
} from './store.js';
import type {
  BudgetConfig,
  ProjectRecord,
  ScanJobView,
  ScanOptions,
  ScanResult,
  SnapshotEnvelope,
} from './types.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(here, '..');
const INSPECTION_TTL_MS = 15 * 60 * 1_000;
const MAX_SELECTED_ITEMS = 5_000;

interface PendingInspection extends PackageImportResult {
  createdAt: number;
}

export interface CreateAppOptions {
  dataDirectory?: string;
  csrfToken?: string;
  serveStatic?: boolean;
  /** Deterministic local/test override; browser requests cannot widen scanner limits. */
  scanOptions?: Pick<ScanOptions, 'maxFileBytes' | 'maxFiles' | 'maxDirectories' | 'maxFsEntries' | 'maxEntriesPerFile' | 'maxEntries' | 'maxRisks' | 'maxClaims' | 'maxTotalBytes' | 'concurrency'>;
}

export interface AppRuntime {
  app: express.Express;
  store: SnapshotStore;
  csrfToken: string;
}

class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
    readonly details?: unknown,
  ) {
    super(message);
  }
}

function defaultDataDirectory(): string {
  if (process.env.CONTEXT_HUB_DATA_DIR) return path.resolve(process.env.CONTEXT_HUB_DATA_DIR);
  if (process.platform === 'darwin') {
    return path.join(os.homedir(), 'Library', 'Application Support', 'AI Context Hub', 'v1');
  }
  return path.join(os.homedir(), '.local', 'share', 'ai-context-hub', 'v1');
}

function isLoopbackHost(value: string): boolean {
  const host = value.trim().toLowerCase();
  return /^(?:127\.0\.0\.1|localhost)(?::\d{1,5})?$/.test(host)
    || /^\[::1\](?::\d{1,5})?$/.test(host);
}

function safeOrigin(value: string): boolean {
  try {
    const parsed = new URL(value);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:')
      && ['127.0.0.1', 'localhost', '::1'].includes(parsed.hostname.toLowerCase());
  } catch {
    return false;
  }
}

function publicEnvelope(envelope: SnapshotEnvelope): Record<string, unknown> {
  return {
    project: toPublicProjectRecord(envelope.project),
    snapshot: {
      metadata: structuredClone(envelope.snapshot),
      diff: structuredClone(envelope.diff),
      result: structuredClone(envelope.result),
    },
    diff: structuredClone(envelope.diff),
  };
}

function publicJob(job: ScanJobView): Record<string, unknown> {
  const { envelope, partialResult, ...safe } = job;
  const safePartial = partialResult ? sanitizeScanResult(partialResult) : undefined;
  if (safePartial) safePartial.rootPath = '';
  return {
    ...safe,
    ...(envelope ? { result: publicEnvelope(envelope) } : {}),
    ...(safePartial ? { partialResult: safePartial } : {}),
  };
}

function parseSelectedIds(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_SELECTED_ITEMS) {
    throw new ApiError(422, 'INVALID_SELECTION', `selectedIds 必须是最多 ${MAX_SELECTED_ITEMS} 个条目的数组。`);
  }
  const ids = value.filter((id): id is string => typeof id === 'string' && id.length > 0 && id.length <= 512);
  if (ids.length !== value.length) throw new ApiError(422, 'INVALID_SELECTION', 'selectedIds 含无效条目标识。');
  return [...new Set(ids)];
}

function parseBudget(value: unknown): BudgetConfig {
  const record = typeof value === 'object' && value !== null ? value as Record<string, unknown> : {};
  const maxTokens = record.maxTokens;
  const policy = record.policy;
  if (!Number.isSafeInteger(maxTokens) || (maxTokens as number) < 0 || (maxTokens as number) > 10_000_000) {
    throw new ApiError(422, 'INVALID_BUDGET', 'Token 预算必须是 0 到 10,000,000 的整数。');
  }
  if (!['warn', 'block', 'auto-trim'].includes(String(policy))) {
    throw new ApiError(422, 'INVALID_BUDGET', '预算策略必须是 warn、block 或 auto-trim。');
  }
  return { maxTokens: maxTokens as number, policy: policy as BudgetConfig['policy'] };
}

function normalizedEntriesDigest(result: ScanResult): string {
  const normalized = sanitizeScanResult(result);
  const identity = {
    projectName: normalized.projectName,
    sourceKind: normalized.sourceKind,
    entries: normalized.entries.map((entry) => ({
      id: entry.id,
      logicalKey: entry.logicalKey,
      title: entry.title,
      packageType: entry.packageType,
      scope: entry.scope,
      content: entry.content,
      source: {
        relativePath: entry.source.relativePath,
        uri: entry.source.uri,
        locator: entry.source.locator,
        revision: entry.source.revision,
      },
      validity: entry.validity ?? null,
      sensitivity: entry.sensitivity,
      tags: entry.tags,
    })),
  };
  return createHash('sha256')
    .update(JSON.stringify(identity))
    .digest('hex');
}

function safeRelative(value: string): boolean {
  const normalized = path.posix.normalize(value.replace(/\\/g, '/'));
  return normalized !== '..'
    && !normalized.startsWith('../')
    && !normalized.startsWith('/')
    && !/^[A-Za-z]:\//.test(normalized);
}

/** Absolute file URIs are reconstructed only inside an explicit export preview. */
function withExportSources(result: ScanResult, project: ProjectRecord): ScanResult {
  if (project.sourceKind !== 'local-project') return result;
  const canonicalRoot = path.resolve(project.locator);
  return {
    ...structuredClone(result),
    entries: result.entries.map((entry) => {
      const relativePath = entry.source.relativePath;
      if (!safeRelative(relativePath)) return structuredClone(entry);
      const absolute = path.resolve(canonicalRoot, relativePath);
      const relation = path.relative(canonicalRoot, absolute);
      if (relation === '..' || relation.startsWith(`..${path.sep}`) || path.isAbsolute(relation)) {
        return structuredClone(entry);
      }
      return { ...structuredClone(entry), source: { ...entry.source, uri: pathToFileURL(absolute).href } };
    }),
  };
}

function pruneInspections(inspections: Map<string, PendingInspection>): void {
  const threshold = Date.now() - INSPECTION_TTL_MS;
  for (const [id, value] of inspections) if (value.createdAt < threshold) inspections.delete(id);
}

function sendError(response: Response, error: unknown): void {
  if (error instanceof ApiError) {
    response.status(error.status).json({ error: { code: error.code, message: error.message, ...(error.details ? { details: error.details } : {}) } });
    return;
  }
  if (error instanceof PackageImportError) {
    const status = error.code === 'RAW_TOO_LARGE' ? 413 : 422;
    response.status(status).json({ error: { code: error.code, message: error.message, ...(error.details.length ? { details: error.details } : {}) } });
    return;
  }
  if (error instanceof TokenBudgetExceededError) {
    response.status(409).json({ error: { code: error.code, message: error.message, details: error.report } });
    return;
  }
  const bodyError = error as { status?: number; type?: string };
  if (bodyError?.status === 413 || bodyError?.type === 'entity.too.large') {
    response.status(413).json({ error: { code: 'PAYLOAD_TOO_LARGE', message: '请求内容超过本地服务的安全上限。' } });
    return;
  }
  if (error instanceof SyntaxError) {
    response.status(400).json({ error: { code: 'MALFORMED_JSON', message: '请求不是有效的 JSON。' } });
    return;
  }
  response.status(500).json({ error: { code: 'INTERNAL_ERROR', message: '本地服务未能完成请求；源项目与旧快照均未被修改。' } });
}

export async function createApp(options: CreateAppOptions = {}): Promise<AppRuntime> {
  const dataDirectory = path.resolve(options.dataDirectory ?? defaultDataDirectory());
  const store = await createSnapshotStore(dataDirectory);
  const signing = new SigningService(dataDirectory);
  const jobs = new ScanJobManager();
  const inspections = new Map<string, PendingInspection>();
  let importMutationQueue: Promise<void> = Promise.resolve();
  function runImportMutation<T>(operation: () => Promise<T>): Promise<T> {
    const result = importMutationQueue.then(operation);
    importMutationQueue = result.then(() => undefined, () => undefined);
    return result;
  }
  const csrfToken = options.csrfToken ?? randomBytes(24).toString('base64url');
  const app = express();

  app.disable('x-powered-by');
  app.use('/api', (request, response, next) => {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Pragma', 'no-cache');
    if (!isLoopbackHost(request.headers.host ?? '')) {
      sendError(response, new ApiError(403, 'LOOPBACK_ONLY', 'AI Context Hub 只接受本机回环地址请求。'));
      return;
    }
    const origin = request.headers.origin;
    if (origin && !safeOrigin(origin)) {
      sendError(response, new ApiError(403, 'ORIGIN_REJECTED', '请求来源不是允许的本机页面。'));
      return;
    }
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)
      && request.headers['x-context-hub-token'] !== csrfToken) {
      sendError(response, new ApiError(403, 'LOCAL_TOKEN_REQUIRED', '缺少本机请求令牌，请刷新 Context Hub 页面后重试。'));
      return;
    }
    next();
  });

  app.get('/api/health', (_request, response) => response.json({ ok: true, localOnly: true, persistence: !store.isReadOnly() }));
  app.get('/api/config', async (_request, response) => {
    response.json({
      rules: SCAN_RULES,
      samplePath: path.join(projectRoot, 'sample-project'),
      csrfToken,
      tokenizers: [{ id: 'o200k_base', label: 'o200k_base', exact: true, localOnly: true }],
      defaultBudget: { maxTokens: 8_000, policy: 'block' },
      signing: { algorithm: 'Ed25519', available: true, privateKeyExportable: false },
      importLimits: PACKAGE_IMPORT_LIMITS,
      storage: { readOnly: store.isReadOnly(), diagnostics: store.getDiagnostics().map(({ code, message }) => ({ code, message })) },
    });
  });

  app.get('/api/projects', async (_request, response, next) => {
    try { response.json((await store.listProjects()).map(toPublicProjectRecord)); }
    catch (error) { next(error); }
  });

  app.get('/api/projects/:projectId', async (request, response, next) => {
    try {
      const project = await store.getProject(request.params.projectId);
      if (!project) throw new ApiError(404, 'PROJECT_NOT_FOUND', '未找到该项目。');
      const snapshot = await store.getLatestSnapshot(project.id);
      if (!snapshot) throw new ApiError(404, 'SNAPSHOT_NOT_FOUND', '该项目还没有可用快照。');
      response.json({ project: toPublicProjectRecord(project), snapshot: toPublicSnapshotView(snapshot) });
    } catch (error) { next(error); }
  });

  app.get('/api/projects/:projectId/snapshots/:snapshotId', async (request, response, next) => {
    try {
      const project = await store.getProject(request.params.projectId);
      if (!project) throw new ApiError(404, 'PROJECT_NOT_FOUND', '未找到该项目。');
      const snapshot = await store.getSnapshot(project.id, request.params.snapshotId);
      if (!snapshot) throw new ApiError(404, 'SNAPSHOT_NOT_FOUND', '未找到该不可变快照。');
      response.json({ project: toPublicProjectRecord(project), snapshot: toPublicSnapshotView(snapshot) });
    } catch (error) { next(error); }
  });

  // File.text() is received as raw JSON text. No server-side file path or URI is ever opened.
  app.post(
    '/api/packages/inspect',
    express.text({ type: ['application/json', 'text/plain'], limit: `${PACKAGE_IMPORT_LIMITS.rawBytes}b` }),
    async (request, response, next) => {
      try {
        if (typeof request.body !== 'string') throw new ApiError(415, 'JSON_TEXT_REQUIRED', '请选择 Context Package JSON 文件。');
        const inspected = await inspectContextPackage(request.body, signing);
        pruneInspections(inspections);
        const inspectionId = randomUUID();
        inspections.set(inspectionId, {
          ...inspected,
          createdAt: Date.now(),
        });
        response.json({ inspectionId, inspection: inspected.inspection });
      } catch (error) { next(error); }
    },
  );

  app.use(express.json({ limit: '256kb' }));

  app.post('/api/packages/import', async (request, response, next) => {
    try {
      pruneInspections(inspections);
      const inspectionId = String(request.body?.inspectionId ?? '');
      const pending = inspections.get(inspectionId);
      if (!pending) throw new ApiError(410, 'INSPECTION_EXPIRED', '导入预览已过期，请重新选择文件检查。');
      const outcome = await runImportMutation(async () => {
        // Re-check identity inside one process-wide critical section. Inspection is advisory;
        // this commit-time check is what makes concurrent confirmations atomic.
        const locator = pending.result.rootPath;
        const projectId = stableProjectId('context-package', locator);
        const existing = await store.getProject(projectId);
        if (existing) {
          const latest = await store.getLatestSnapshot(projectId);
          const storedDigest = latest?.packageDigest ?? (latest ? `legacy:${normalizedEntriesDigest(latest.result)}` : '');
          const pendingDigest = latest?.packageDigest
            ? pending.identityDigest
            : `legacy:${normalizedEntriesDigest(pending.result)}`;
          if (latest && storedDigest === pendingDigest) {
            inspections.delete(inspectionId);
            return {
              status: 200,
              body: {
                project: toPublicProjectRecord(existing),
                snapshot: toPublicSnapshotView(latest),
                diff: latest.diff,
                deduplicated: true,
              },
            };
          }
          throw new ApiError(409, 'PACKAGE_ID_COLLISION', '相同 packageId 已存在不同内容；为避免身份混淆，本次导入已阻断。');
        }
        const saved = await store.saveSnapshot(pending.result, null, {
          locator,
          signatureVerification: pending.inspection.signatureVerification,
          packageDigest: pending.identityDigest,
        });
        inspections.delete(inspectionId);
        return { status: 201, body: publicEnvelope(saved) };
      });
      response.status(outcome.status).json(outcome.body);
    } catch (error) { next(error); }
  });

  app.post('/api/scans', async (request, response, next) => {
    try {
      const requestedProjectId = typeof request.body?.projectId === 'string' ? request.body.projectId : '';
      const requestedPath = typeof request.body?.path === 'string' ? request.body.path.trim() : '';
      if (!requestedProjectId && (!requestedPath || !path.isAbsolute(requestedPath))) {
        throw new ApiError(422, 'ABSOLUTE_PATH_REQUIRED', '请输入本地项目的绝对路径。');
      }
      let privateProject: ProjectRecord | null = null;
      let scanPath = requestedPath;
      let previousIndex = undefined;
      if (requestedProjectId) {
        privateProject = await store.getProject(requestedProjectId);
        if (!privateProject) throw new ApiError(404, 'PROJECT_NOT_FOUND', '未找到要刷新的项目。');
        if (privateProject.sourceKind !== 'local-project') {
          throw new ApiError(422, 'PACKAGE_REFRESH_UNSUPPORTED', '导入包是不可变来源；请重新导入新包。');
        }
        const baseSnapshotId = typeof request.body?.baseSnapshotId === 'string' ? request.body.baseSnapshotId : '';
        if (baseSnapshotId && baseSnapshotId !== privateProject.latestSnapshotId) {
          throw new ApiError(409, 'STALE_SNAPSHOT', '项目已有更新快照，请先重新打开最新版本。');
        }
        scanPath = privateProject.locator;
        previousIndex = (await store.getLatestSnapshot(privateProject.id))?.index ?? undefined;
      }
      try {
        // This runs before discovery and before the lazily initialized store writes anything.
        await assertStoreOutsideProject(dataDirectory, scanPath);
      } catch (error) {
        if (error instanceof Error && error.message.includes('重叠')) {
          throw new ApiError(422, 'STATE_DIR_INSIDE_PROJECT', '本地状态目录不能与被扫描项目重叠；扫描未开始，项目未被写入。');
        }
        // A previously persisted project may have been moved or become unreadable. Preserve
        // the asynchronous refresh contract so the job records failure and the old snapshot stays open.
        if (privateProject) {
          // The scanner will produce the stable failed-job result below.
        } else {
          throw new ApiError(422, 'PROJECT_PATH_UNAVAILABLE', '无法安全读取该项目路径，扫描未开始。');
        }
      }
      const jobKey = privateProject?.id ?? `path:${path.resolve(scanPath)}`;
      let initial: ScanJobView;
      try {
        initial = jobs.create(jobKey, async ({ signal, report }) => {
          const execution = await scanProjectWithIndex(scanPath, {
            ...options.scanOptions,
            previousIndex: previousIndex ?? undefined,
            signal,
            onProgress: report,
          });
          if (execution.result.stats.performance.truncated) return { partialResult: execution.result };
          report({ phase: 'persist', processed: 0, total: 1, percent: 96, message: '正在原子保存不可变快照…' });
          const envelope = await store.saveSnapshot(execution.result, execution.index, { signal, verifySource: execution.verifySource });
          return { envelope };
        });
      } catch (error) {
        if (error instanceof Error && error.name === 'SCAN_ALREADY_RUNNING') {
          throw new ApiError(409, 'SCAN_ALREADY_RUNNING', error.message);
        }
        throw error;
      }
      response.status(202).json({ jobId: initial.id, ...publicJob(initial) });
    } catch (error) { next(error); }
  });

  app.get('/api/scans/:jobId', (request, response, next) => {
    try {
      const job = jobs.get(request.params.jobId);
      if (!job) throw new ApiError(404, 'SCAN_JOB_NOT_FOUND', '未找到该扫描任务。');
      response.json(publicJob(job));
    } catch (error) { next(error); }
  });

  app.delete('/api/scans/:jobId', (request, response, next) => {
    try {
      const job = jobs.cancel(request.params.jobId);
      if (!job) throw new ApiError(404, 'SCAN_JOB_NOT_FOUND', '未找到该扫描任务。');
      response.json(publicJob(job));
    } catch (error) { next(error); }
  });

  app.post('/api/export', async (request, response, next) => {
    try {
      const projectId = String(request.body?.projectId ?? '');
      const snapshotId = String(request.body?.snapshotId ?? '');
      const selectedIds = parseSelectedIds(request.body?.selectedIds);
      const format = String(request.body?.format ?? '') as ExportFormat;
      if (!['json', 'agents'].includes(format)) throw new ApiError(422, 'INVALID_FORMAT', '导出格式必须是 json 或 agents。');
      const budget = parseBudget(request.body?.budget);
      const project = await store.getProject(projectId);
      if (!project) throw new ApiError(404, 'PROJECT_NOT_FOUND', '未找到该项目。');
      const snapshot = await store.getSnapshot(projectId, snapshotId);
      if (!snapshot) throw new ApiError(404, 'SNAPSHOT_NOT_FOUND', '未找到该不可变快照。');
      const exportResult = withExportSources(snapshot.result, project);
      const expectedRevision = typeof request.body?.selectionRevision === 'string' ? request.body.selectionRevision : '';
      if (expectedRevision && isSelectionRevisionStale(exportResult, selectedIds, expectedRevision)) {
        throw new ApiError(409, 'STALE_SELECTION', '条目选择或快照已变化，请重新生成导出预览。');
      }
      const preview = await createExportPreview(
        exportResult,
        selectedIds,
        format,
        budget,
        signing,
        request.body?.sign === true,
      );
      response.json(preview);
    } catch (error) { next(error); }
  });

  app.use('/api', (_request, response) => {
    sendError(response, new ApiError(404, 'API_NOT_FOUND', '未找到该本地 API。'));
  });

  if (options.serveStatic) {
    app.use(express.static(path.join(projectRoot, 'dist'), { etag: false }));
    app.get('/{*splat}', (_request, response) => response.sendFile(path.join(projectRoot, 'dist', 'index.html')));
  }

  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => sendError(response, error));
  return { app, store, csrfToken };
}

async function start(): Promise<void> {
  const runtime = await createApp({ serveStatic: process.argv.includes('--serve') });
  const port = Number(process.env.CONTEXT_HUB_PORT ?? 43101);
  runtime.app.listen(port, '127.0.0.1', () => {
    console.log(`Context Hub local service: http://127.0.0.1:${port}`);
  });
}

const invokedPath = process.argv[1] ? path.resolve(process.argv[1]) : '';
if (invokedPath === fileURLToPath(import.meta.url)) {
  await start();
}
