import { mkdir, mkdtemp, rename, rm, stat, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppRuntime } from '../server/index.js';
import type { ContextPackage, ScanJobStatus, ScanOptions } from '../server/types.js';
import { requestExpress } from './helpers/in-process-express.js';

const TEST_TOKEN = 'fixed-context-hub-test-token';
const terminalStatuses = new Set<ScanJobStatus>(['completed', 'partial', 'cancelled', 'failed']);
const temporaryDirectories: string[] = [];

interface TestRuntime {
  app: AppRuntime['app'];
}

interface PublicEntry {
  id: string;
  logicalKey: string;
  title: string;
  content: string;
  source: { relativePath: string; uri: string; revision: string };
}

interface PublicDiff {
  fromSnapshotId: string | null;
  toSnapshotId: string;
  added: Array<{ logicalKey: string; source: string }>;
  removed: Array<{ logicalKey: string; source: string }>;
  changed: Array<{ logicalKey: string; source: string }>;
  unchanged: number;
  files: { added: string[]; removed: string[]; changed: string[]; unchanged: number };
}

interface PublicSnapshot {
  metadata: {
    id: string;
    projectId: string;
    parentSnapshotId: string | null;
    cacheHits: number;
  };
  diff: PublicDiff;
  result: {
    projectName: string;
    entries: PublicEntry[];
    stats: { performance: { cacheHits: number } };
    rootPath?: string;
  };
}

interface PublicProject {
  id: string;
  name: string;
  latestSnapshotId: string;
  locator?: string;
}

interface CompletedScanResult {
  project: PublicProject;
  snapshot: PublicSnapshot;
  diff: PublicDiff;
}

interface ScanJobBody {
  id: string;
  status: ScanJobStatus;
  progress: { percent: number };
  error?: { code: string; message: string };
  result?: CompletedScanResult;
  partialResult?: {
    entries: PublicEntry[];
    stats: { performance: { truncated: boolean } };
    warnings: string[];
  };
}

interface ErrorBody {
  error: { code: string; message: string; details?: unknown };
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function sandbox(label: string): Promise<{ base: string; project: string; data: string }> {
  const base = await mkdtemp(path.join(os.tmpdir(), `context-hub-api-${label}-`));
  const project = path.join(base, 'project');
  const data = path.join(base, 'private-store');
  temporaryDirectories.push(base);
  await mkdir(project);
  return { base, project, data };
}

async function start(
  dataDirectory: string,
  scanOptions?: Pick<ScanOptions, 'maxFileBytes' | 'maxFiles' | 'maxDirectories' | 'maxFsEntries' | 'maxEntriesPerFile' | 'maxEntries' | 'maxRisks' | 'maxClaims' | 'maxTotalBytes' | 'concurrency'>,
): Promise<TestRuntime> {
  const runtime = await createApp({ dataDirectory, csrfToken: TEST_TOKEN, scanOptions });
  return { app: runtime.app };
}

async function stop(_runtime: TestRuntime): Promise<void> {}

async function jsonRequest<T>(
  runtime: TestRuntime,
  route: string,
  init: RequestInit = {},
  withToken = true,
): Promise<{ response: Response; body: T }> {
  const headers = new Headers(init.headers);
  if (init.body !== undefined && !headers.has('content-type')) headers.set('content-type', 'application/json');
  if (withToken && init.method && !['GET', 'HEAD', 'OPTIONS'].includes(init.method)) {
    headers.set('x-context-hub-token', TEST_TOKEN);
  }
  const response = await requestExpress(runtime.app, route, { ...init, headers });
  return { response, body: await response.json() as T };
}

async function requestWithHost(runtime: TestRuntime, host: string): Promise<{ status: number; body: ErrorBody }> {
  const response = await requestExpress(runtime.app, '/api/health', { headers: { host } });
  return { status: response.status, body: await response.json() as ErrorBody };
}

async function postJson<T>(runtime: TestRuntime, route: string, body: unknown): Promise<{ response: Response; body: T }> {
  return jsonRequest<T>(runtime, route, { method: 'POST', body: JSON.stringify(body) });
}

async function inspectRaw(runtime: TestRuntime, raw: string): Promise<{ response: Response; body: Record<string, unknown> | ErrorBody }> {
  return jsonRequest<Record<string, unknown> | ErrorBody>(runtime, '/api/packages/inspect', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: raw,
  });
}

async function waitForJob(runtime: TestRuntime, id: string, timeoutMs = 10_000): Promise<ScanJobBody> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const { response, body } = await jsonRequest<ScanJobBody>(runtime, `/api/scans/${id}`);
    expect(response.status).toBe(200);
    if (terminalStatuses.has(body.status)) return body;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`扫描任务 ${id} 在 ${timeoutMs}ms 内未结束。`);
}

async function scan(runtime: TestRuntime, request: { path?: string; projectId?: string; baseSnapshotId?: string }): Promise<ScanJobBody> {
  const started = await postJson<ScanJobBody>(runtime, '/api/scans', request);
  expect(started.response.status).toBe(202);
  expect(['queued', 'running']).toContain(started.body.status);
  return waitForJob(runtime, started.body.id);
}

function expectCompleted(job: ScanJobBody): asserts job is ScanJobBody & { result: CompletedScanResult } {
  expect(job.status, JSON.stringify(job.error)).toBe('completed');
  expect(job.progress.percent).toBe(100);
  expect(job.result).toBeDefined();
}

function packageFixture(overrides: Partial<ContextPackage> = {}): ContextPackage {
  return {
    schemaVersion: '0.1',
    packageId: '11111111-1111-4111-8111-111111111111',
    name: 'foreign-context',
    kind: 'repository',
    createdAt: '2026-08-13T00:00:00.000Z',
    producer: { name: 'api-integration-fixture', version: '1.0.0' },
    items: [{
      id: 'foreign-rule',
      type: 'instruction',
      title: '外部测试约定',
      content: '提交前运行 npm test。',
      scope: 'project',
      source: {
        uri: 'file:///Users/alice/private-project/AGENTS.md',
        revision: 'foreign-revision-1',
        locator: '第 4 行',
      },
      validity: { observedAt: '2026-08-12T00:00:00.000Z', expiresAt: null, confidence: 0.9 },
      sensitivity: 'internal',
      tags: ['quality'],
    }],
    warnings: [],
    ...overrides,
  };
}

describe.sequential('本地 API 集成契约', () => {
  it('只接受回环 Host/Origin，且所有变更请求必须携带本机 CSRF 令牌', async () => {
    const { data } = await sandbox('boundary');
    const runtime = await start(data);

    const healthy = await jsonRequest<{ ok: boolean; localOnly: boolean }>(runtime, '/api/health');
    expect(healthy.response.status).toBe(200);
    expect(healthy.body).toEqual(expect.objectContaining({ ok: true, localOnly: true }));

    const badHost = await requestWithHost(runtime, 'not-loopback.example');
    expect(badHost.status).toBe(403);
    expect(badHost.body.error.code).toBe('LOOPBACK_ONLY');

    const badOrigin = await jsonRequest<ErrorBody>(runtime, '/api/health', { headers: { origin: 'https://not-loopback.example' } });
    expect(badOrigin.response.status).toBe(403);
    expect(badOrigin.body.error.code).toBe('ORIGIN_REJECTED');

    const withoutToken = await jsonRequest<ErrorBody>(runtime, '/api/scans', {
      method: 'POST',
      body: JSON.stringify({ path: '/tmp' }),
    }, false);
    expect(withoutToken.response.status).toBe(403);
    expect(withoutToken.body.error.code).toBe('LOCAL_TOKEN_REQUIRED');
  });

  it('状态目录与项目重叠时在扫描前拒绝，且连初始 manifest 都不写入', async () => {
    const { project } = await sandbox('state-overlap');
    const nestedData = path.join(project, '.context-hub-private');
    const runtime = await start(nestedData);
    await expect(stat(nestedData)).rejects.toMatchObject({ code: 'ENOENT' });

    const rejected = await postJson<ErrorBody>(runtime, '/api/scans', { path: project });
    expect(rejected.response.status).toBe(422);
    expect(rejected.body.error.code).toBe('STATE_DIR_INSIDE_PROJECT');
    await expect(stat(nestedData)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('首次扫描异步完成，重建应用后仍可读取，所有项目/快照响应隐藏绝对根与 file URI', async () => {
    const { project, data } = await sandbox('persist');
    await writeFile(path.join(project, 'AGENTS.md'), '# 测试命令\n\n提交前运行 npm test。\n', 'utf8');
    const firstRuntime = await start(data);
    const completed = await scan(firstRuntime, { path: project });
    expectCompleted(completed);
    const projectId = completed.result.project.id;
    const snapshotId = completed.result.snapshot.metadata.id;

    const scanPayload = JSON.stringify(completed);
    expect(scanPayload).not.toContain(project);
    expect(scanPayload).not.toContain('file://');
    expect(completed.result.project).not.toHaveProperty('locator');
    expect(completed.result.snapshot.result.rootPath ?? '').toBe('');
    expect(completed.result.snapshot.result.entries[0].source.uri).toMatch(/^context-hub:\/\/local\//);

    await stop(firstRuntime);
    const reloadedRuntime = await start(data);
    const projects = await jsonRequest<PublicProject[]>(reloadedRuntime, '/api/projects');
    expect(projects.response.status).toBe(200);
    expect(projects.body).toEqual([expect.objectContaining({ id: projectId, latestSnapshotId: snapshotId })]);
    expect(projects.body[0]).not.toHaveProperty('locator');

    const latest = await jsonRequest<{ project: PublicProject; snapshot: PublicSnapshot }>(reloadedRuntime, `/api/projects/${projectId}`);
    const historical = await jsonRequest<{ project: PublicProject; snapshot: PublicSnapshot }>(reloadedRuntime, `/api/projects/${projectId}/snapshots/${snapshotId}`);
    expect(latest.response.status).toBe(200);
    expect(historical.response.status).toBe(200);
    expect(latest.body.snapshot.metadata.id).toBe(snapshotId);
    expect(historical.body.snapshot.result.entries[0].content).toContain('npm test');
    for (const payload of [latest.body, historical.body]) {
      const serialized = JSON.stringify(payload);
      expect(serialized).not.toContain(project);
      expect(serialized).not.toContain('file://');
      expect(payload.project).not.toHaveProperty('locator');
      expect(payload.snapshot.result).not.toHaveProperty('rootPath');
    }
  });

  it('刷新复用未变文件并返回可审计 diff，新增/修改/删除都不丢失', async () => {
    const { project, data } = await sandbox('refresh');
    await Promise.all([
      writeFile(path.join(project, 'AGENTS.md'), '# 构建规则\n\n使用旧构建命令。\n', 'utf8'),
      writeFile(path.join(project, 'STABLE.md'), '# 稳定知识\n\n这一文件保持不变。\n', 'utf8'),
      writeFile(path.join(project, 'OLD.md'), '# 待删除知识\n\n刷新后应消失。\n', 'utf8'),
    ]);
    const runtime = await start(data);
    const first = await scan(runtime, { path: project });
    expectCompleted(first);

    await Promise.all([
      writeFile(path.join(project, 'AGENTS.md'), '# 构建规则\n\n使用新的、更长的构建命令 npm run build。\n', 'utf8'),
      writeFile(path.join(project, 'NEW.md'), '# 新增知识\n\n刷新后应出现。\n', 'utf8'),
      unlink(path.join(project, 'OLD.md')),
    ]);
    const refreshed = await scan(runtime, {
      projectId: first.result.project.id,
      baseSnapshotId: first.result.snapshot.metadata.id,
    });
    expectCompleted(refreshed);

    const diff = refreshed.result.diff;
    expect(refreshed.result.snapshot.metadata.parentSnapshotId).toBe(first.result.snapshot.metadata.id);
    expect(refreshed.result.snapshot.result.stats.performance.cacheHits).toBeGreaterThanOrEqual(1);
    expect(diff.changed.map((item) => item.source)).toContain('AGENTS.md');
    expect(diff.added.map((item) => item.source)).toContain('NEW.md');
    expect(diff.removed.map((item) => item.source)).toContain('OLD.md');
    expect(diff.files).toEqual({
      added: ['NEW.md'],
      removed: ['OLD.md'],
      changed: ['AGENTS.md'],
      unchanged: 1,
    });
  });

  it('达到结构化条目上限的刷新只返回 partial，旧 latest 与快照数量保持不变', async () => {
    const { project, data } = await sandbox('partial-refresh');
    await writeFile(path.join(project, 'AGENTS.md'), '# 初始规则\n\n这是完整旧快照。\n', 'utf8');
    const runtime = await start(data, { maxEntriesPerFile: 8, maxEntries: 8 });
    const first = await scan(runtime, { path: project });
    expectCompleted(first);
    const projectId = first.result.project.id;
    const snapshotId = first.result.snapshot.metadata.id;

    const manySections = Array.from({ length: 12 }, (_, index) => `# 规则 ${index}\n\n正文 ${index}。`).join('\n');
    await writeFile(path.join(project, 'AGENTS.md'), `${manySections}\n`, 'utf8');
    const partial = await scan(runtime, { projectId, baseSnapshotId: snapshotId });
    expect(partial.status).toBe('partial');
    expect(partial.result).toBeUndefined();
    expect(partial.partialResult?.stats.performance.truncated).toBe(true);
    expect(partial.partialResult?.entries).toHaveLength(8);
    expect(partial.partialResult?.warnings.join('\n')).toContain('每文件 8 个结构化条目上限');

    const latest = await jsonRequest<{ project: PublicProject; snapshot: PublicSnapshot }>(runtime, `/api/projects/${projectId}`);
    expect(latest.response.status).toBe(200);
    expect(latest.body.project.latestSnapshotId).toBe(snapshotId);
    expect(latest.body.snapshot.metadata.id).toBe(snapshotId);
    expect(latest.body.snapshot.result.entries).toHaveLength(1);
    expect(latest.body.snapshot.result.entries[0].content).toContain('完整旧快照');
    const projects = await jsonRequest<Array<PublicProject & { snapshots: unknown[] }>>(runtime, '/api/projects');
    expect(projects.body.find((project) => project.id === projectId)?.snapshots).toHaveLength(1);
  });

  it('候选文件读取失败不会被误判为删除，partial 响应不泄漏绝对路径且 latest 不变', async () => {
    const { project, data } = await sandbox('unreadable-refresh');
    const source = path.join(project, 'AGENTS.md');
    await writeFile(source, '# 初始规则\n\n旧条目必须保留。\n', 'utf8');
    const runtime = await start(data, { maxFileBytes: 128 });
    const first = await scan(runtime, { path: project });
    expectCompleted(first);
    const projectId = first.result.project.id;
    const snapshotId = first.result.snapshot.metadata.id;

    await writeFile(source, `# 过大候选\n\n${'x'.repeat(512)}\n`, 'utf8');
    const partial = await scan(runtime, { projectId, baseSnapshotId: snapshotId });
    expect(partial.status).toBe('partial');
    expect(partial.partialResult?.stats.performance.truncated).toBe(true);
    expect(partial.partialResult?.warnings.join('\n')).toContain('FILE_TOO_LARGE');
    expect(JSON.stringify(partial)).not.toContain(project);

    const latest = await jsonRequest<{ project: PublicProject; snapshot: PublicSnapshot }>(runtime, `/api/projects/${projectId}`);
    expect(latest.body.project.latestSnapshotId).toBe(snapshotId);
    expect(latest.body.snapshot.metadata.id).toBe(snapshotId);
    expect(latest.body.snapshot.result.entries[0].content).toContain('旧条目必须保留');
    const projects = await jsonRequest<Array<PublicProject & { snapshots: unknown[] }>>(runtime, '/api/projects');
    expect(projects.body.find((item) => item.id === projectId)?.snapshots).toHaveLength(1);
  });

  it('旧快照导出不受源文件后续变化影响，并稳定阻断超预算与过期选择', async () => {
    const { project, data } = await sandbox('export');
    const sourceFile = path.join(project, 'AGENTS.md');
    await writeFile(sourceFile, '# 快照规则\n\n只应出现旧快照内容。\n', 'utf8');
    const runtime = await start(data);
    const first = await scan(runtime, { path: project });
    expectCompleted(first);
    const oldSnapshot = first.result.snapshot;
    const selectedIds = oldSnapshot.result.entries.map((entry) => entry.id);

    await writeFile(sourceFile, '# 快照规则\n\n这是扫描后才写入的新内容，不能污染旧快照。\n', 'utf8');
    const refreshed = await scan(runtime, {
      projectId: first.result.project.id,
      baseSnapshotId: oldSnapshot.metadata.id,
    });
    expectCompleted(refreshed);

    const exported = await postJson<{
      content: string;
      budget: { selectionRevision: string; exactTokens: number };
    }>(runtime, '/api/export', {
      projectId: first.result.project.id,
      snapshotId: oldSnapshot.metadata.id,
      selectedIds,
      format: 'json',
      budget: { maxTokens: 100_000, policy: 'block' },
    });
    expect(exported.response.status).toBe(200);
    expect(exported.body.content).toContain('只应出现旧快照内容');
    expect(exported.body.content).not.toContain('不能污染旧快照');
    const exportedPackage = JSON.parse(exported.body.content) as ContextPackage;
    expect(exportedPackage.items[0].source.uri).toMatch(/^file:\/\//);
    expect(exportedPackage.items[0].source.uri).toContain('AGENTS.md');

    const blocked = await postJson<ErrorBody>(runtime, '/api/export', {
      projectId: first.result.project.id,
      snapshotId: oldSnapshot.metadata.id,
      selectedIds,
      format: 'agents',
      budget: { maxTokens: 0, policy: 'block' },
    });
    expect(blocked.response.status).toBe(409);
    expect(blocked.body.error.code).toBe('TOKEN_BUDGET_EXCEEDED');

    const stale = await postJson<ErrorBody>(runtime, '/api/export', {
      projectId: first.result.project.id,
      snapshotId: oldSnapshot.metadata.id,
      selectedIds: [],
      selectionRevision: exported.body.budget.selectionRevision,
      format: 'agents',
      budget: { maxTokens: 100_000, policy: 'block' },
    });
    expect(stale.response.status).toBe(409);
    expect(stale.body.error.code).toBe('STALE_SELECTION');
  });

  it('Context Package 必须先检查再确认导入，重复导入幂等且公开响应不泄漏 file 来源', async () => {
    const { data } = await sandbox('import');
    const runtime = await start(data);
    const raw = JSON.stringify(packageFixture());

    const inspected = await inspectRaw(runtime, raw);
    expect(inspected.response.status).toBe(200);
    expect(inspected.body).toEqual(expect.objectContaining({
      inspectionId: expect.any(String),
      inspection: expect.objectContaining({ itemCount: 1 }),
    }));
    const firstInspectionId = String((inspected.body as Record<string, unknown>).inspectionId);
    const imported = await postJson<CompletedScanResult>(runtime, '/api/packages/import', { inspectionId: firstInspectionId });
    expect(imported.response.status).toBe(201);
    const projectId = imported.body.project.id;
    const snapshotId = imported.body.snapshot.metadata.id;

    const inspectedAgain = await inspectRaw(runtime, raw);
    expect(inspectedAgain.response.status).toBe(200);
    const secondInspectionId = String((inspectedAgain.body as Record<string, unknown>).inspectionId);
    const duplicate = await postJson<{
      project: PublicProject;
      snapshot: PublicSnapshot;
      deduplicated: boolean;
    }>(runtime, '/api/packages/import', { inspectionId: secondInspectionId });
    expect(duplicate.response.status).toBe(200);
    expect(duplicate.body.deduplicated).toBe(true);
    expect(duplicate.body.project.id).toBe(projectId);
    expect(duplicate.body.snapshot.metadata.id).toBe(snapshotId);

    const changedPackage = packageFixture();
    changedPackage.items[0].content = '保持 item id 与 revision 不变，但正文已经改变。';
    const changedInspection = await inspectRaw(runtime, JSON.stringify(changedPackage));
    expect(changedInspection.response.status).toBe(200);
    const changedInspectionId = String((changedInspection.body as Record<string, unknown>).inspectionId);
    const collision = await postJson<ErrorBody>(runtime, '/api/packages/import', { inspectionId: changedInspectionId });
    expect(collision.response.status).toBe(409);
    expect(collision.body.error.code).toBe('PACKAGE_ID_COLLISION');

    const metadataChanged = packageFixture();
    metadataChanged.producer.version = '2.0.0';
    const metadataInspection = await inspectRaw(runtime, JSON.stringify(metadataChanged));
    const metadataInspectionId = String((metadataInspection.body as Record<string, unknown>).inspectionId);
    const metadataCollision = await postJson<ErrorBody>(runtime, '/api/packages/import', { inspectionId: metadataInspectionId });
    expect(metadataCollision.response.status).toBe(409);
    expect(metadataCollision.body.error.code).toBe('PACKAGE_ID_COLLISION');

    const unknownChanged = packageFixture() as ContextPackage & Record<string, unknown>;
    unknownChanged.futureIdentityField = { revision: 2 };
    const unknownInspection = await inspectRaw(runtime, JSON.stringify(unknownChanged));
    const unknownInspectionId = String((unknownInspection.body as Record<string, unknown>).inspectionId);
    const unknownCollision = await postJson<ErrorBody>(runtime, '/api/packages/import', { inspectionId: unknownInspectionId });
    expect(unknownCollision.response.status).toBe(409);
    expect(unknownCollision.body.error.code).toBe('PACKAGE_ID_COLLISION');

    const latest = await jsonRequest<{ project: PublicProject; snapshot: PublicSnapshot }>(runtime, `/api/projects/${projectId}`);
    const serialized = JSON.stringify(latest.body);
    expect(latest.response.status).toBe(200);
    expect(serialized).not.toContain('/Users/alice/private-project');
    expect(serialized).not.toContain('file://');
    expect(latest.body.project).not.toHaveProperty('locator');
    expect(latest.body.snapshot.result).not.toHaveProperty('rootPath');
  });

  it('并发导入在提交时原子复核包身份：相同内容幂等，不同内容冲突', async () => {
    const { data } = await sandbox('concurrent-import');
    const runtime = await start(data);

    const sameRaw = JSON.stringify(packageFixture());
    const [sameInspectionA, sameInspectionB] = await Promise.all([
      inspectRaw(runtime, sameRaw),
      inspectRaw(runtime, sameRaw),
    ]);
    const [sameA, sameB] = await Promise.all([
      postJson<Record<string, unknown>>(runtime, '/api/packages/import', { inspectionId: String((sameInspectionA.body as Record<string, unknown>).inspectionId) }),
      postJson<Record<string, unknown>>(runtime, '/api/packages/import', { inspectionId: String((sameInspectionB.body as Record<string, unknown>).inspectionId) }),
    ]);
    expect([sameA.response.status, sameB.response.status].sort()).toEqual([200, 201]);

    const packageId = '22222222-2222-4222-8222-222222222222';
    const left = packageFixture({ packageId });
    const right = structuredClone(left);
    right.items[0].content = '保持同一 packageId，但内容不同。';
    const [leftInspection, rightInspection] = await Promise.all([
      inspectRaw(runtime, JSON.stringify(left)),
      inspectRaw(runtime, JSON.stringify(right)),
    ]);
    const [leftResult, rightResult] = await Promise.all([
      postJson<Record<string, unknown> | ErrorBody>(runtime, '/api/packages/import', { inspectionId: String((leftInspection.body as Record<string, unknown>).inspectionId) }),
      postJson<Record<string, unknown> | ErrorBody>(runtime, '/api/packages/import', { inspectionId: String((rightInspection.body as Record<string, unknown>).inspectionId) }),
    ]);
    expect([leftResult.response.status, rightResult.response.status].sort()).toEqual([201, 409]);
    const conflict = leftResult.response.status === 409 ? leftResult.body as ErrorBody : rightResult.body as ErrorBody;
    expect(conflict.error.code).toBe('PACKAGE_ID_COLLISION');

    const projects = await jsonRequest<Array<PublicProject & { snapshots: unknown[] }>>(runtime, '/api/projects');
    expect(projects.body).toHaveLength(2);
    expect(projects.body.every((project) => project.snapshots.length === 1)).toBe(true);
  });

  it('明文秘密和无效 schema 均稳定失败，错误正文不回显秘密', async () => {
    const { data } = await sandbox('import-errors');
    const runtime = await start(data);
    const secret = ['sk', 'this-is-a-fake-secret-value-123456789'].join('-');
    const unsafe = packageFixture();
    unsafe.items[0].content = `api_key = "${secret}"`;

    const firstSecretFailure = await inspectRaw(runtime, JSON.stringify(unsafe));
    const secondSecretFailure = await inspectRaw(runtime, JSON.stringify(unsafe));
    expect(firstSecretFailure.response.status).toBe(422);
    expect(firstSecretFailure.body).toEqual(secondSecretFailure.body);
    expect((firstSecretFailure.body as ErrorBody).error.code).toBe('PLAINTEXT_SECRET');
    expect(JSON.stringify(firstSecretFailure.body)).not.toContain(secret);

    const invalid = packageFixture();
    delete (invalid.items[0] as unknown as Record<string, unknown>).source;
    const firstSchemaFailure = await inspectRaw(runtime, JSON.stringify(invalid));
    const secondSchemaFailure = await inspectRaw(runtime, JSON.stringify(invalid));
    expect(firstSchemaFailure.response.status).toBe(422);
    expect(firstSchemaFailure.body).toEqual(secondSchemaFailure.body);
    expect((firstSchemaFailure.body as ErrorBody).error.code).toBe('SCHEMA_INVALID');
  });

  it('刷新失败只结束当前任务，仍保留上一次成功快照', async () => {
    const { base, project, data } = await sandbox('failed-refresh');
    await writeFile(path.join(project, 'AGENTS.md'), '# 可用规则\n\n旧快照必须保留。\n', 'utf8');
    const runtime = await start(data);
    const first = await scan(runtime, { path: project });
    expectCompleted(first);
    const projectId = first.result.project.id;
    const snapshotId = first.result.snapshot.metadata.id;

    await rename(project, path.join(base, 'project-moved-away'));
    const failed = await scan(runtime, { projectId, baseSnapshotId: snapshotId });
    expect(failed.status).toBe('failed');
    expect(failed.error).toEqual(expect.objectContaining({ code: 'SCAN_FAILED' }));
    expect(JSON.stringify(failed.error)).not.toContain(project);

    const latest = await jsonRequest<{ project: PublicProject; snapshot: PublicSnapshot }>(runtime, `/api/projects/${projectId}`);
    expect(latest.response.status).toBe(200);
    expect(latest.body.project.latestSnapshotId).toBe(snapshotId);
    expect(latest.body.snapshot.metadata.id).toBe(snapshotId);
    expect(latest.body.snapshot.result.entries[0].content).toContain('旧快照必须保留');
  });
});
