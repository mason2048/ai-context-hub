import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import { describe, expect, it, vi } from 'vitest';
import schema from '../context-package.schema.json';
import {
  createAgentsDraft,
  createContextPackage,
  createExportPreview,
  createSelectionRevision,
  isSelectionRevisionStale,
} from '../server/exporter.js';
import { scanProject } from '../server/scanner.js';
import { SigningService } from '../server/signing.js';
import { countTokens } from '../server/tokenizer.js';
import type { ContextEntry, ContextPackage, ContextRisk, ScanResult } from '../server/types.js';

vi.mock('../server/tokenizer.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../server/tokenizer.js')>();
  return { ...actual, countTokens: vi.fn(actual.countTokens) };
});

const here = path.dirname(fileURLToPath(import.meta.url));
const samplePath = path.resolve(here, '../sample-project');
const fakeSecret = 'context-hub-fixture-credential-890123456789';

function schemaValidator(): ReturnType<Ajv2020['compile']> {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  return ajv.compile(schema);
}

function budgetFixture(source: ScanResult): { result: ScanResult; selectedIds: string[]; expectedKept: string[] } {
  const template = source.entries.find((entry) => entry.packageType !== 'secret-warning')!;
  const makeEntry = (
    id: string,
    packageType: ContextEntry['packageType'],
    scope: ContextEntry['scope'],
    riskIds: string[],
    content: string,
    relativePath: string,
  ): ContextEntry => ({
    ...template,
    id,
    logicalKey: id,
    title: id,
    packageType,
    scope,
    riskIds,
    content,
    summary: content.slice(0, 80),
    sensitivity: packageType === 'secret-warning' ? 'secret' : 'internal',
    tags: packageType === 'secret-warning' ? ['secret-warning'] : ['rule'],
    source: {
      ...template.source,
      relativePath,
      uri: `file:///immutable/${relativePath}`,
      locator: '第 1 行',
      startLine: 1,
      endLine: 1,
      revision: `${id}-revision`,
    },
  });
  const secret = makeEntry('secret', 'secret-warning', 'task', ['risk-secret'], '已隐藏疑似密钥，原值已丢弃。', 'z-secret.md');
  const danger = makeEntry('danger', 'instruction', 'task', ['risk-danger'], '危险冲突必须先处理。', 'y-danger.md');
  const globalFirst = makeEntry('global-first', 'instruction', 'global', [], '甲 '.repeat(600), 'b-global.md');
  const globalSecond = makeEntry('global-second', 'instruction', 'global', [], '乙 '.repeat(600), 'a-global.md');
  const task = makeEntry('task', 'instruction', 'task', [], '任务级小项。', 'c-task.md');
  const side = (entry: ContextEntry) => ({
    itemId: entry.id,
    title: entry.title,
    source: entry.source.relativePath,
    locator: entry.source.locator,
    excerpt: entry.summary,
  });
  const risks: ContextRisk[] = [
    { id: 'risk-secret', kind: 'secret', severity: 'danger', title: '密钥', description: '已脱敏', sides: [side(secret)] },
    { id: 'risk-danger', kind: 'conflict', severity: 'danger', title: '冲突', description: '危险冲突', sides: [side(danger)] },
  ];
  // Deliberately disagree with request and source order. Priority must be:
  // secret -> danger -> global-second (user order) -> global-first -> task.
  const entries = [task, globalFirst, danger, globalSecond, secret];
  const selectedIds = [task.id, globalSecond.id, globalFirst.id, danger.id, secret.id];
  return {
    result: {
      ...source,
      entries,
      risks,
      warnings: [],
      stats: { ...source.stats, entries: entries.length, risks: risks.length },
    },
    selectedIds,
    expectedKept: [secret.id, danger.id, globalSecond.id],
  };
}

function largeBudgetFixture(source: ScanResult, count = 513): { result: ScanResult; selectedIds: string[] } {
  const template = source.entries.find((entry) => entry.packageType !== 'secret-warning')!;
  const risks: ContextRisk[] = [];
  const entries = Array.from({ length: count }, (_, index): ContextEntry => {
    const id = `large-${String(index).padStart(4, '0')}`;
    const packageType: ContextEntry['packageType'] = index % 101 === 0 ? 'secret-warning' : 'instruction';
    const riskId = index % 13 === 0 ? `large-risk-${index}` : null;
    const entry: ContextEntry = {
      ...template,
      id,
      logicalKey: id,
      title: `复杂度条目 ${index}`,
      packageType,
      scope: index % 3 === 0 ? 'global' : index % 3 === 1 ? 'project' : 'task',
      riskIds: riskId ? [riskId] : [],
      content: `条目 ${index} 的确定性正文。${'复杂上下文 '.repeat(8 + (index % 17))}`,
      summary: `复杂度回归条目 ${index}`,
      sensitivity: packageType === 'secret-warning' ? 'secret' : 'internal',
      tags: packageType === 'secret-warning' ? ['secret-warning'] : ['rule', `bucket-${index % 11}`],
      source: {
        ...template.source,
        relativePath: `rules/group-${index % 29}/${id}.md`,
        uri: `file:///immutable/rules/group-${index % 29}/${id}.md`,
        locator: `第 ${index + 1} 行`,
        startLine: index + 1,
        endLine: index + 1,
        revision: `${id}-revision`,
      },
    };
    if (riskId) {
      risks.push({
        id: riskId,
        kind: 'conflict',
        severity: index % 26 === 0 ? 'danger' : 'warning',
        title: `复杂度风险 ${index}`,
        description: '用于验证优先级排序只预计算一次风险等级。',
        sides: [{
          itemId: id,
          title: entry.title,
          source: entry.source.relativePath,
          locator: entry.source.locator,
          excerpt: entry.summary,
        }],
      });
    }
    return entry;
  });
  return {
    result: {
      ...source,
      entries,
      risks,
      warnings: [],
      stats: { ...source.stats, entries: entries.length, risks: risks.length },
    },
    // Reverse source order so the priority sort and selection-order tie-break
    // both do real work before binary prefix selection.
    selectedIds: entries.map((entry) => entry.id).reverse(),
  };
}

describe('导出预览与 Context Package v0.1', () => {
  it('用户取消条目后 JSON 与 AGENTS 草案同步移除', async () => {
    const result = await scanProject(samplePath);
    const removed = result.entries.find((entry) => entry.title === '代码提交约定');
    expect(removed).toBeDefined();
    const selectedIds = result.entries.filter((entry) => entry.id !== removed!.id).map((entry) => entry.id);
    const packageResult = createContextPackage(result, selectedIds, new Date('2026-08-12T00:00:00.000Z'));
    const agentsDraft = createAgentsDraft(result, selectedIds);
    expect(packageResult.items.some((entry) => entry.id === removed!.id)).toBe(false);
    expect(agentsDraft).not.toContain('代码提交约定');
  });

  it('导出的 JSON 通过 Context Package v0.1 schema，且所有条目可追溯', async () => {
    const result = await scanProject(samplePath);
    const packageResult = createContextPackage(result, result.entries.map((entry) => entry.id));
    const validate = schemaValidator();
    expect(validate(packageResult), JSON.stringify(validate.errors)).toBe(true);
    expect(packageResult.items.every((entry) => entry.source.uri && entry.source.locator && entry.source.revision)).toBe(true);
  });

  it('JSON 和 AGENTS 草案均不含完整假密钥，秘密只保留告警', async () => {
    const result = await scanProject(samplePath);
    const selectedIds = result.entries.map((entry) => entry.id);
    const serializedPackage = JSON.stringify(createContextPackage(result, selectedIds));
    const agentsDraft = createAgentsDraft(result, selectedIds);
    expect(serializedPackage).not.toContain(fakeSecret);
    expect(serializedPackage).toContain('secret-warning');
    expect(agentsDraft).not.toContain(fakeSecret);
    expect(agentsDraft).not.toContain('已隐藏疑似');
  });

  it('按 o200k_base 对实际完整预览正文精确计数，且预览可复现', async () => {
    const result = await scanProject(samplePath);
    const selectedIds = result.entries.map((entry) => entry.id);
    const first = await createExportPreview(result, selectedIds, 'json', { maxTokens: 1_000_000, policy: 'warn' });
    const second = await createExportPreview(result, selectedIds, 'json', { maxTokens: 1_000_000, policy: 'warn' });

    expect(first.budget.encoding).toBe('o200k_base');
    expect(first.budget.exactTokens).toBe(countTokens(first.content));
    expect(first.content).toBe(second.content);
    expect(first.budget.selectionRevision).toBe(second.budget.selectionRevision);
    expect(JSON.parse(first.content).items).toHaveLength(selectedIds.length);
  });

  it('warn 超限仍返回完整内容，block 超限抛出可机器识别的错误', async () => {
    const result = await scanProject(samplePath);
    const selectedIds = result.entries.map((entry) => entry.id);
    const warned = await createExportPreview(result, selectedIds, 'agents', { maxTokens: 1, policy: 'warn' });

    expect(warned.budget).toMatchObject({ exceeded: true, blocked: false, selectedIds });
    expect(warned.budget.exactTokens).toBe(countTokens(warned.content));
    await expect(createExportPreview(result, selectedIds, 'agents', { maxTokens: 1, policy: 'block' }))
      .rejects.toMatchObject({
        code: 'TOKEN_BUDGET_EXCEEDED',
        report: { policy: 'block', exceeded: true, blocked: true },
      });
  });

  it('auto-trim 严格按密钥告警、风险、scope 和用户选择顺序保留确定性前缀', async () => {
    const scanned = await scanProject(samplePath);
    const fixture = budgetFixture(scanned);
    const prefix = await createExportPreview(
      fixture.result,
      fixture.expectedKept,
      'json',
      { maxTokens: 1_000_000, policy: 'warn' },
    );
    // UUID tokenization can differ by a few tokens because the full request has
    // a different selection revision. The cushion is far smaller than another
    // 600-token entry.
    const maxTokens = prefix.budget.exactTokens + 100;
    const first = await createExportPreview(
      fixture.result,
      fixture.selectedIds,
      'json',
      { maxTokens, policy: 'auto-trim' },
    );
    const second = await createExportPreview(
      fixture.result,
      fixture.selectedIds,
      'json',
      { maxTokens, policy: 'auto-trim' },
    );

    expect(first.budget.selectedIds).toEqual(fixture.expectedKept);
    expect(first.budget.omittedIds).toEqual(['task', 'global-first']);
    expect(first.budget.autoTrimmed).toBe(true);
    expect(first.budget.exactTokens).toBe(countTokens(first.content));
    expect(first.budget.exactTokens).toBeLessThanOrEqual(maxTokens);
    expect(first).toEqual(second);
    expect((JSON.parse(first.content) as ContextPackage).items.map((item) => item.id))
      .toEqual(expect.arrayContaining(fixture.expectedKept));
  });

  it('auto-trim 含签名的固定正文开销也超限时必须 block', async () => {
    const keyDirectory = await mkdtemp(path.join(os.tmpdir(), 'context-hub-fixed-overhead-'));
    try {
      const result = await scanProject(samplePath);
      const signing = new SigningService(keyDirectory);
      await expect(createExportPreview(
        result,
        [],
        'json',
        { maxTokens: 0, policy: 'auto-trim' },
        signing,
        true,
      )).rejects.toMatchObject({
        code: 'TOKEN_BUDGET_EXCEEDED',
        report: { policy: 'auto-trim', selectedIds: [], blocked: true, exactTokens: expect.any(Number) },
      });
    } finally {
      await rm(keyDirectory, { recursive: true, force: true });
    }
  });

  it('513 条签名 auto-trim 仅做对数次完整渲染与精确计数', async () => {
    const keyDirectory = await mkdtemp(path.join(os.tmpdir(), 'context-hub-logarithmic-trim-'));
    try {
      const scanned = await scanProject(samplePath);
      const fixture = largeBudgetFixture(scanned);
      const signing = new SigningService(keyDirectory);
      const generous = { maxTokens: 10_000_000, policy: 'auto-trim' } as const;
      await signing.localKeyId();
      const tokenCounter = vi.mocked(countTokens);
      const signSpy = vi.spyOn(signing, 'sign');
      const verifySpy = vi.spyOn(signing, 'verify');
      try {
        tokenCounter.mockClear();
        const complete = await createExportPreview(
          fixture.result,
          fixture.selectedIds,
          'json',
          generous,
          signing,
          true,
        );
        expect(tokenCounter).toHaveBeenCalledTimes(1);
        expect(signSpy).toHaveBeenCalledTimes(1);
        expect(verifySpy).toHaveBeenCalledTimes(1);

        tokenCounter.mockClear(); signSpy.mockClear(); verifySpy.mockClear();
        const empty = await createExportPreview(fixture.result, [], 'json', generous, signing, true);
        expect(tokenCounter).toHaveBeenCalledTimes(1);
        expect(signSpy).toHaveBeenCalledTimes(1);
        expect(verifySpy).toHaveBeenCalledTimes(1);
        const maxTokens = empty.budget.exactTokens
          + Math.floor((complete.budget.exactTokens - empty.budget.exactTokens) * 0.55);
        expect(maxTokens).toBeGreaterThan(empty.budget.exactTokens);
        expect(maxTokens).toBeLessThan(complete.budget.exactTokens);

        tokenCounter.mockClear(); signSpy.mockClear(); verifySpy.mockClear();
        const trimmed = await createExportPreview(
          fixture.result,
          fixture.selectedIds,
          'json',
          { maxTokens, policy: 'auto-trim' },
          signing,
          true,
        );
        const renderCount = tokenCounter.mock.calls.length;
        const logarithmicBound = 2 + Math.ceil(Math.log2(fixture.selectedIds.length));

        expect(renderCount).toBeLessThanOrEqual(logarithmicBound);
        expect(signSpy).toHaveBeenCalledTimes(renderCount);
        expect(verifySpy).toHaveBeenCalledTimes(renderCount);
        expect(trimmed.budget.selectedIds.length).toBeGreaterThan(0);
        expect(trimmed.budget.selectedIds.length).toBeLessThan(fixture.selectedIds.length);
        expect(trimmed.budget.selectedIds).toEqual(
          complete.budget.selectedIds.slice(0, trimmed.budget.selectedIds.length),
        );
        const accepted = new Set(trimmed.budget.selectedIds);
        expect(trimmed.budget.omittedIds).toEqual(fixture.selectedIds.filter((id) => !accepted.has(id)));
        expect(trimmed.budget.exactTokens).toBeLessThanOrEqual(maxTokens);
        expect(trimmed.signature.status).toBe('valid-trusted');
        expect(trimmed.budget.exactTokens).toBe(countTokens(trimmed.content));

        const repeated = await createExportPreview(
          fixture.result,
          fixture.selectedIds,
          'json',
          { maxTokens, policy: 'auto-trim' },
          signing,
          true,
        );
        expect(repeated).toEqual(trimmed);
      } finally {
        signSpy.mockRestore();
        verifySpy.mockRestore();
      }
    } finally {
      await rm(keyDirectory, { recursive: true, force: true });
    }
  });

  it('selection revision 可稳定检测选择或已选快照内容变更', async () => {
    const result = await scanProject(samplePath);
    const selectedIds = result.entries.slice(0, 2).map((entry) => entry.id);
    const revision = createSelectionRevision(result, selectedIds);

    expect(createSelectionRevision(structuredClone(result), [...selectedIds])).toBe(revision);
    expect(isSelectionRevisionStale(result, selectedIds, revision)).toBe(false);
    expect(isSelectionRevisionStale(revision, result, selectedIds.slice(0, 1))).toBe(true);
    const changed = structuredClone(result);
    changed.entries.find((entry) => entry.id === selectedIds[0])!.content += '\n快照已变更';
    expect(isSelectionRevisionStale(changed, selectedIds, revision)).toBe(true);
  });

  it('导出只使用传入 ScanResult，源文件后续变化不会污染旧快照', async () => {
    const temporary = await mkdtemp(path.join(os.tmpdir(), 'context-hub-export-snapshot-'));
    const project = path.join(temporary, 'project');
    const sourceFile = path.join(project, 'AGENTS.md');
    try {
      await mkdir(project);
      await writeFile(sourceFile, '# 快照规则\n\n只应出现旧快照内容。\n', 'utf8');
      const oldSnapshot = await scanProject(project);
      const selectedIds = oldSnapshot.entries.map((entry) => entry.id);
      await writeFile(sourceFile, '# 快照规则\n\n这是扫描后才写入的新内容。\n', 'utf8');

      const preview = await createExportPreview(oldSnapshot, selectedIds, 'agents', { maxTokens: 10_000, policy: 'block' });
      expect(preview.content).toContain('只应出现旧快照内容');
      expect(preview.content).not.toContain('这是扫描后才写入的新内容');
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  });

  it('签名 JSON 包可复验，精确 Token 数包含签名后完整正文；AGENTS 始终不签名', async () => {
    const keyDirectory = await mkdtemp(path.join(os.tmpdir(), 'context-hub-signing-'));
    try {
      const result = await scanProject(samplePath);
      const selectedIds = result.entries.map((entry) => entry.id);
      const signing = new SigningService(keyDirectory);
      const signed = await createExportPreview(
        result,
        selectedIds,
        'json',
        { maxTokens: 1_000_000, policy: 'block' },
        signing,
        true,
      );
      const parsed = JSON.parse(signed.content) as ContextPackage;

      expect(signed.signature.status).toBe('valid-trusted');
      expect((await signing.verify(parsed)).status).toBe('valid-trusted');
      expect(signed.budget.exactTokens).toBe(countTokens(signed.content));
      expect(parsed.signature?.algorithm).toBe('Ed25519');
      const validate = schemaValidator();
      expect(validate(parsed), JSON.stringify(validate.errors)).toBe(true);

      const agents = await createExportPreview(
        result,
        selectedIds,
        'agents',
        { maxTokens: 1_000_000, policy: 'block' },
        signing,
        true,
      );
      expect(agents.signature.status).toBe('unsigned');
      expect(agents.content).not.toContain('Ed25519');
    } finally {
      await rm(keyDirectory, { recursive: true, force: true });
    }
  });

  it('精确预览和签名包均不泄露完整假密钥，并保留导入条目 validity', async () => {
    const result = await scanProject(samplePath);
    const first = result.entries[0] as ContextEntry & { validity: ContextPackage['items'][number]['validity'] };
    first.validity = { observedAt: '2025-01-02T03:04:05.000Z', expiresAt: '2027-01-02T03:04:05.000Z', confidence: 0.73 };
    const preview = await createExportPreview(
      result,
      result.entries.map((entry) => entry.id),
      'json',
      { maxTokens: 1_000_000, policy: 'block' },
    );
    const parsed = JSON.parse(preview.content) as ContextPackage;

    expect(preview.content).not.toContain(fakeSecret);
    expect(parsed.items.find((item) => item.id === first.id)?.validity).toEqual(first.validity);
    const validate = schemaValidator();
    expect(validate(parsed), JSON.stringify(validate.errors)).toBe(true);
  });

  it('导入的 web、memory 等包再次导出时保留协议 kind', async () => {
    const result = await scanProject(samplePath);
    result.sourceKind = 'context-package';
    result.entries.forEach((entry) => entry.tags.push('imported', 'kind:web'));

    const exported = createContextPackage(result, result.entries.map((entry) => entry.id));

    expect(exported.kind).toBe('web');
    const validate = schemaValidator();
    expect(validate(exported), JSON.stringify(validate.errors)).toBe(true);
  });
});
