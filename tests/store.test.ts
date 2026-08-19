import { chmod, mkdir, mkdtemp, readFile, readdir, realpath, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  SnapshotStore,
  StoreCorruptionError,
  createSnapshotStore,
  stableProjectId,
  toPublicProjectRecord,
  toPublicSnapshotView,
} from '../server/store.js';
import type {
  ContextEntry,
  ContextRisk,
  ScanIndex,
  ScanResult,
  SourceKind,
} from '../server/types.js';

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

async function sandbox(label: string): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), `context-hub-store-${label}-`));
  temporaryDirectories.push(directory);
  return directory;
}

function entry(
  rootPath: string,
  logicalKey: string,
  revision: string,
  relativePath: string,
  content = `${logicalKey} content`,
): ContextEntry {
  return {
    id: `${logicalKey}-${revision}`,
    logicalKey,
    title: logicalKey,
    category: 'rule',
    packageType: 'instruction',
    scope: 'project',
    content,
    summary: content,
    source: {
      relativePath,
      uri: `file://${path.join(rootPath, relativePath)}`,
      locator: '第 1 行',
      startLine: 1,
      endLine: 1,
      revision,
      modifiedAt: '2026-08-12T00:00:00.000Z',
    },
    sensitivity: 'internal',
    tags: ['test'],
    riskIds: [],
    tokenCount: 4,
    tokenEncoding: 'o200k_base',
    tokenEstimate: 4,
  };
}

function risk(id: string, target: ContextEntry): ContextRisk {
  return {
    id,
    kind: 'semantic-conflict',
    severity: 'warning',
    title: '测试风险',
    description: '测试风险说明',
    sides: [{
      itemId: target.id,
      title: target.title,
      source: target.source.relativePath,
      locator: target.source.locator,
      excerpt: target.summary,
    }],
  };
}

function resultFixture(
  rootPath: string,
  entries: ContextEntry[],
  risks: ContextRisk[] = [],
  sourceKind: SourceKind = 'local-project',
  projectName = path.basename(rootPath) || 'imported',
): ScanResult {
  return {
    rootPath,
    projectName,
    sourceKind,
    scannedAt: '2026-08-12T00:00:00.000Z',
    entries,
    risks,
    warnings: [],
    analyzers: [{ id: 'test', version: '1', mode: 'local', privacy: 'local', status: 'ok' }],
    stats: {
      filesScanned: new Set(entries.map((item) => item.source.relativePath)).size,
      entries: entries.length,
      risks: risks.length,
      tokenCount: entries.length * 4,
      tokenEstimate: entries.length * 4,
      tokenEncoding: 'o200k_base',
      healthScore: 100,
      performance: {
        directoriesVisited: 1,
        fsEntriesVisited: entries.length,
        candidatesDiscovered: entries.length,
        filesRead: entries.length,
        cacheHits: 0,
        cacheMisses: entries.length,
        ignoredPaths: 0,
        totalBytesRead: entries.reduce((sum, item) => sum + Buffer.byteLength(item.content, 'utf8'), 0),
        durationMs: 3,
        truncated: false,
      },
    },
    rules: {
      included: ['*.md'],
      excludedDirectories: ['node_modules'],
      excludedFiles: ['.env'],
      maxFileBytes: 1_000_000,
      maxFiles: 100,
      maxDirectories: 100,
      maxFsEntries: 1_000,
      maxEntriesPerFile: 1_000,
      maxEntries: 5_000,
      maxRisks: 5_000,
      maxClaims: 20_000,
      maxTotalBytes: 32 * 1024 * 1024,
      concurrency: 2,
    },
  };
}

function indexFixture(entries: ContextEntry[]): ScanIndex {
  const grouped = new Map<string, ContextEntry[]>();
  for (const item of entries) grouped.set(item.source.relativePath, [...(grouped.get(item.source.relativePath) ?? []), item]);
  return {
    version: 1,
    rootRevision: 'root-revision',
    files: Object.fromEntries([...grouped].map(([relativePath, items]) => [relativePath, {
      statKey: `stat-${relativePath}`,
      revision: items[0].source.revision,
      entries: items,
    }])),
  };
}

describe('SnapshotStore', () => {
  it('持久化后可重载，并用稳定 ID 隔离多个本地项目与导入包', async () => {
    const base = await sandbox('reload');
    const projectA = path.join(base, 'project-a');
    const projectB = path.join(base, 'project-b');
    const data = path.join(base, 'private-store');
    await Promise.all([mkdir(projectA), mkdir(projectB)]);
    const firstStore = await createSnapshotStore(data);

    const a = entry(projectA, 'rule-a', 'a1', 'AGENTS.md');
    const b = entry(projectB, 'rule-b', 'b1', 'CLAUDE.md');
    const savedA = await firstStore.saveSnapshot(resultFixture(projectA, [a]), indexFixture([a]));
    const savedB = await firstStore.saveSnapshot(resultFixture(projectB, [b]), indexFixture([b]));
    const importedEntry = entry('', 'imported-rule', 'p1', 'imported/rule.md');
    importedEntry.source.uri = 'https://example.test/rule.md?private=drop';
    const imported = await firstStore.saveSnapshot(
      resultFixture('', [importedEntry], [], 'context-package', 'foreign-package'),
      null,
      { locator: 'package:11111111-1111-4111-8111-111111111111' },
    );

    const reloaded = await createSnapshotStore(data);
    expect(await reloaded.listProjects()).toHaveLength(3);
    expect((await reloaded.getLatestSnapshot(savedA.project.id))?.result.entries[0].content).toBe(a.content);
    expect((await reloaded.getLatestSnapshot(savedB.project.id))?.result.entries[0].content).toBe(b.content);
    expect(imported.project.id).toBe(stableProjectId('context-package', 'package:11111111-1111-4111-8111-111111111111'));
    expect(savedA.project.id).toBe(stableProjectId('local-project', await realpath(projectA)));
  });

  it('按 logicalKey 与来源 revision 计算条目、文件和风险差异', async () => {
    const base = await sandbox('diff');
    const project = path.join(base, 'project');
    const data = path.join(base, 'store');
    await mkdir(project);
    const store = await createSnapshotStore(data);
    const changedBefore = entry(project, 'changed', 'rev-1', 'changed.md');
    const removed = entry(project, 'removed', 'rev-1', 'removed.md');
    const unchanged = entry(project, 'unchanged', 'rev-stable', 'same.md');
    await store.saveSnapshot(
      resultFixture(project, [changedBefore, removed, unchanged], [risk('risk-old', removed)]),
      indexFixture([changedBefore, removed, unchanged]),
    );

    const changedAfter = entry(project, 'changed', 'rev-2', 'changed.md', 'new body');
    const added = entry(project, 'added', 'rev-1', 'added.md');
    const unchangedAfter = entry(project, 'unchanged', 'rev-stable', 'same.md', 'same cached body');
    const current = await store.saveSnapshot(
      resultFixture(project, [changedAfter, added, unchangedAfter], [risk('risk-new', added)]),
      indexFixture([changedAfter, added, unchangedAfter]),
    );

    expect(current.diff.added.map((item) => item.logicalKey)).toEqual(['added']);
    expect(current.diff.removed.map((item) => item.logicalKey)).toEqual(['removed']);
    expect(current.diff.changed.map((item) => item.logicalKey)).toEqual(['changed']);
    expect(current.diff.unchanged).toBe(1);
    expect(current.diff.files).toEqual({
      added: ['added.md'],
      removed: ['removed.md'],
      changed: ['changed.md'],
      unchanged: 1,
    });
    expect(current.diff.risks).toEqual({ added: 1, removed: 1 });
  });

  it('使用 0700 数据目录、0600 manifest/快照和无残留同目录临时文件', async () => {
    const base = await sandbox('permissions');
    const project = path.join(base, 'project');
    const data = path.join(base, 'store');
    await mkdir(project);
    await mkdir(data, { mode: 0o777 });
    await chmod(data, 0o777);
    const store = await createSnapshotStore(data);
    const item = entry(project, 'rule', 'rev-1', 'AGENTS.md');
    const saved = await store.saveSnapshot(resultFixture(project, [item]), indexFixture([item]));
    const projectStore = path.join(data, 'snapshots', saved.project.id);
    const snapshotFile = path.join(projectStore, `${saved.snapshot.id}.json`);

    expect((await stat(data)).mode & 0o777).toBe(0o700);
    expect((await stat(path.join(data, 'snapshots'))).mode & 0o777).toBe(0o700);
    expect((await stat(projectStore)).mode & 0o777).toBe(0o700);
    expect((await stat(path.join(data, 'manifest.json'))).mode & 0o777).toBe(0o600);
    expect((await stat(snapshotFile)).mode & 0o777).toBe(0o600);
    expect((await readdir(data)).some((name) => name.startsWith('.manifest.json.'))).toBe(false);
    expect((await readdir(projectStore)).some((name) => name.startsWith(`.${saved.snapshot.id}.json.`))).toBe(false);
  });

  it('manifest 损坏时只读降级、显式诊断且绝不覆盖原文件', async () => {
    const base = await sandbox('corrupt-manifest');
    const project = path.join(base, 'project');
    const data = path.join(base, 'store');
    await Promise.all([mkdir(project), mkdir(data)]);
    const manifest = path.join(data, 'manifest.json');
    await writeFile(manifest, '{definitely-not-json', { mode: 0o600 });
    const original = await readFile(manifest, 'utf8');
    const store = await createSnapshotStore(data);
    const item = entry(project, 'rule', 'rev-1', 'AGENTS.md');

    expect(store.isReadOnly()).toBe(true);
    expect(store.getDiagnostics()).toEqual([expect.objectContaining({ code: 'MANIFEST_CORRUPT' })]);
    await expect(store.saveSnapshot(resultFixture(project, [item]), indexFixture([item])))
      .rejects.toBeInstanceOf(StoreCorruptionError);
    expect(await readFile(manifest, 'utf8')).toBe(original);
  });

  it('损坏快照不会被伪装成未命中或静默覆盖，后续快照可安全降级保存', async () => {
    const base = await sandbox('corrupt-snapshot');
    const project = path.join(base, 'project');
    const data = path.join(base, 'store');
    await mkdir(project);
    const store = await createSnapshotStore(data);
    const firstEntry = entry(project, 'rule', 'rev-1', 'AGENTS.md');
    const first = await store.saveSnapshot(resultFixture(project, [firstEntry]), indexFixture([firstEntry]));
    const corruptFile = path.join(data, 'snapshots', first.project.id, `${first.snapshot.id}.json`);
    await writeFile(corruptFile, '{broken', { mode: 0o600 });

    await expect(store.getSnapshot(first.project.id, first.snapshot.id)).rejects.toMatchObject({ code: 'SNAPSHOT_CORRUPT' });
    expect(store.getDiagnostics()).toEqual([expect.objectContaining({ code: 'SNAPSHOT_CORRUPT' })]);
    const secondEntry = entry(project, 'rule', 'rev-2', 'AGENTS.md', 'changed');
    const second = await store.saveSnapshot(resultFixture(project, [secondEntry]), indexFixture([secondEntry]));
    expect(second.snapshot.parentSnapshotId).toBeNull();
    expect(await readFile(corruptFile, 'utf8')).toBe('{broken');
    expect((await store.getLatestSnapshot(first.project.id))?.metadata.id).toBe(second.snapshot.id);
  });

  it('拒绝位于扫描项目内的数据目录，并对普通视图移除 locator、rootPath 与 file URI', async () => {
    const base = await sandbox('boundary');
    const project = path.join(base, 'project');
    await mkdir(project);
    const nestedData = path.join(project, '.context-hub-private');
    const nestedStore = await createSnapshotStore(nestedData);
    await expect(stat(nestedData)).rejects.toMatchObject({ code: 'ENOENT' });
    const item = entry(project, 'rule', 'rev-1', 'AGENTS.md');
    await expect(nestedStore.saveSnapshot(resultFixture(project, [item]), indexFixture([item])))
      .rejects.toThrow('不能与被扫描项目重叠');
    await expect(stat(nestedData)).rejects.toMatchObject({ code: 'ENOENT' });

    const outsideStore = await createSnapshotStore(path.join(base, 'outside-store'));
    const saved = await outsideStore.saveSnapshot(resultFixture(project, [item]), indexFixture([item]));
    const stored = await outsideStore.getSnapshot(saved.project.id, saved.snapshot.id);
    expect(stored).not.toBeNull();
    const publicValue = {
      project: toPublicProjectRecord(saved.project),
      snapshot: toPublicSnapshotView(stored!),
    };
    const serialized = JSON.stringify(publicValue);
    expect(serialized).not.toContain(project);
    expect(serialized).not.toContain('rootPath":"' + project);
    expect(serialized).not.toContain('file://');
    expect(serialized).not.toContain('locator":"' + project);
    expect(publicValue.snapshot.result).not.toHaveProperty('rootPath');
    expect(publicValue.snapshot.result.entries[0].source.uri).toMatch(/^context-hub:\/\/local\//);
    expect(publicValue.project).not.toHaveProperty('locator');
  });

  it('取消是 manifest 提交门：中途取消不保留快照且不推进 latest', async () => {
    const base = await sandbox('abort-commit');
    const project = path.join(base, 'project');
    const data = path.join(base, 'store');
    await mkdir(project);
    const store = await createSnapshotStore(data);
    const item = entry(project, 'rule', 'rev-1', 'AGENTS.md');
    let reads = 0;
    const commitGate = {
      get aborted() {
        reads += 1;
        return reads >= 3;
      },
    } as AbortSignal;

    await expect(store.saveSnapshot(resultFixture(project, [item]), indexFixture([item]), { signal: commitGate }))
      .rejects.toMatchObject({ name: 'AbortError' });
    expect(await store.listProjects()).toEqual([]);
    await expect(stat(path.join(data, 'manifest.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    const snapshotRoot = path.join(data, 'snapshots');
    const projectDirectories = await readdir(snapshotRoot);
    expect(projectDirectories).toHaveLength(1);
    expect(await readdir(path.join(snapshotRoot, projectDirectories[0]))).toEqual([]);
  });

  it('来源终局校验是 manifest 提交门：漂移时删除未发布快照且 latest 不变', async () => {
    const base = await sandbox('source-commit-gate');
    const project = path.join(base, 'project');
    const data = path.join(base, 'store');
    await mkdir(project);
    const store = await createSnapshotStore(data);
    const item = entry(project, 'rule', 'rev-1', 'AGENTS.md');
    let validations = 0;

    await expect(store.saveSnapshot(resultFixture(project, [item]), indexFixture([item]), {
      async verifySource() {
        validations += 1;
        if (validations >= 3) throw new Error('SOURCE_CHANGED');
      },
    })).rejects.toThrow('SOURCE_CHANGED');

    expect(validations).toBe(3);
    expect(await store.listProjects()).toEqual([]);
    await expect(stat(path.join(data, 'manifest.json'))).rejects.toMatchObject({ code: 'ENOENT' });
    const snapshotRoot = path.join(data, 'snapshots');
    const projectDirectories = await readdir(snapshotRoot);
    expect(projectDirectories).toHaveLength(1);
    expect(await readdir(path.join(snapshotRoot, projectDirectories[0]))).toEqual([]);
  });

  it('最终 JSON 序列化超限时拒绝提交，不写快照且不推进 latest', async () => {
    const base = await sandbox('serialized-limit');
    const project = path.join(base, 'project');
    const data = path.join(base, 'store');
    await mkdir(project);
    const store = new SnapshotStore(data, { maxStoreFileBytes: 4_096 });
    await store.initialize();
    const item = entry(project, 'rule', 'rev-1', 'AGENTS.md', '\\"'.repeat(2_500));

    await expect(store.saveSnapshot(resultFixture(project, [item]), indexFixture([item])))
      .rejects.toMatchObject({ name: 'SnapshotTooLargeError' });
    expect(await store.listProjects()).toEqual([]);
    await expect(stat(path.join(data, 'manifest.json'))).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('历史保留上限最大 50，并按配置清理已失去 manifest 引用的旧快照', async () => {
    const base = await sandbox('retention');
    const project = path.join(base, 'project');
    const data = path.join(base, 'store');
    await mkdir(project);
    let tick = 0;
    const store = new SnapshotStore(data, {
      maxSnapshotsPerProject: 2,
      now: () => new Date(Date.UTC(2026, 7, 12, 0, 0, tick++)),
    });
    await store.initialize();
    const ids: string[] = [];
    for (let revision = 1; revision <= 3; revision += 1) {
      const item = entry(project, 'rule', `rev-${revision}`, 'AGENTS.md', `body ${revision}`);
      ids.push((await store.saveSnapshot(resultFixture(project, [item]), indexFixture([item]))).snapshot.id);
    }
    const projectId = stableProjectId('local-project', await realpath(project));
    expect(await store.listSnapshots(projectId)).toHaveLength(2);
    await expect(stat(path.join(data, 'snapshots', projectId, `${ids[0]}.json`))).rejects.toMatchObject({ code: 'ENOENT' });
    expect(new SnapshotStore(path.join(base, 'another'), { maxSnapshotsPerProject: 5_000 }).maxSnapshotsPerProject).toBe(50);
  });
});
