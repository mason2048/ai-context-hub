import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { AnalyzerPipeline, LocalHttpAnalyzer, LocalSemanticAnalyzer } from '../server/analyzers.js';
import type { ContextEntry } from '../server/types.js';

const temporaryDirectories: string[] = [];
const ANALYZER_ENDPOINT = 'http://127.0.0.1:43199/analyze';

function entry(
  id: string,
  content: string,
  overrides: Omit<Partial<ContextEntry>, 'source'> & { source?: Partial<ContextEntry['source']> } = {},
): ContextEntry {
  const relativePath = overrides.source?.relativePath ?? `rules/${id}.md`;
  const { source: _sourceOverride, ...entryOverrides } = overrides;
  const source: ContextEntry['source'] = {
    relativePath,
    uri: overrides.source?.uri ?? `file:///private/project/${relativePath}`,
    locator: overrides.source?.locator ?? `第 ${id} 行`,
    startLine: overrides.source?.startLine ?? 1,
    endLine: overrides.source?.endLine ?? 1,
    revision: overrides.source?.revision ?? `sha256:${id}`,
    modifiedAt: overrides.source?.modifiedAt ?? '2026-08-13T00:00:00.000Z',
  };
  return {
    id,
    logicalKey: `logical:${id}`,
    title: `规则 ${id}`,
    category: 'rule',
    packageType: 'instruction',
    scope: 'project',
    content,
    summary: `摘要 ${id}`,
    source,
    sensitivity: 'internal',
    tags: ['rule'],
    riskIds: [],
    tokenCount: 1,
    tokenEncoding: 'o200k_base',
    tokenEstimate: 1,
    ...entryOverrides,
  };
}

function inProcessTransport(handler: (request: Request) => Response | Promise<Response>): typeof globalThis.fetch {
  return (async (
    input: Parameters<typeof globalThis.fetch>[0],
    init?: Parameters<typeof globalThis.fetch>[1],
  ) => handler(new Request(input, init))) as typeof globalThis.fetch;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

describe('LocalSemanticAnalyzer', () => {
  const analyzer = new LocalSemanticAnalyzer();

  it('将各包管理器的 run test 与短写视为等价命令', async () => {
    for (const manager of ['npm', 'pnpm', 'yarn', 'bun']) {
      const result = await analyzer.analyze([
        entry(`${manager}-run`, `必须运行 ${manager} run test。`),
        entry(`${manager}-short`, `必须运行 ${manager} test。`),
      ], '/private/project');

      expect(result.risks.filter((risk) => risk.kind === 'conflict'), manager).toEqual([]);
    }
  });

  it('检出包管理器、端口、版本与必须/禁止的语义冲突', async () => {
    const result = await analyzer.analyze([
      entry('pm-pnpm', '必须使用 pnpm。'),
      entry('pm-npm', '必须使用 npm。'),
      entry('port-3000', '默认端口为 3000。'),
      entry('port-4000', '默认端口为 4000。'),
      entry('node-20', 'Node 20。'),
      entry('node-22', 'Node 22。'),
      entry('publish-required', '必须发布稳定版本。'),
      entry('publish-forbidden', '禁止发布稳定版本。'),
    ], '/private/project');

    const semanticTitles = result.risks
      .filter((risk) => risk.kind === 'semantic-conflict')
      .map((risk) => risk.title);
    expect(semanticTitles).toEqual(expect.arrayContaining([
      expect.stringContaining('package-manager'),
      expect.stringContaining('port'),
      expect.stringContaining('node-version'),
      expect.stringContaining('action:发布稳定版本'),
    ]));
    for (const subject of ['package-manager', 'port', 'node-version', 'action:发布稳定版本']) {
      expect(result.risks.find((risk) => risk.title.includes(subject))?.sides).toHaveLength(2);
    }
  });

  it('提取 Node/Python 版本的 ^、~ 与开闭区间操作符', async () => {
    const incompatiblePairs = [
      { subject: 'node-version', left: 'Node ^20。', right: 'Node 22。' },
      { subject: 'node-version', left: 'Node ~20.1。', right: 'Node <20.1。' },
      { subject: 'python-version', left: 'Python >=3.11。', right: 'Python <3.11。' },
      { subject: 'python-version', left: 'Python >3.10。', right: 'Python <=3.10。' },
    ];

    for (const [index, pair] of incompatiblePairs.entries()) {
      const result = await analyzer.analyze([
        entry(`version-left-${index}`, pair.left),
        entry(`version-right-${index}`, pair.right),
      ], '/private/project');

      expect(
        result.risks.find((risk) => risk.title.includes(pair.subject)),
        `${pair.subject}: ${pair.left} vs ${pair.right}`,
      ).toMatchObject({
        kind: 'semantic-conflict',
        sides: expect.arrayContaining([
          expect.objectContaining({ itemId: `version-left-${index}` }),
          expect.objectContaining({ itemId: `version-right-${index}` }),
        ]),
      });
    }

    const compatible = await analyzer.analyze([
      entry('node-compatible-left', 'Node >=20。'),
      entry('node-compatible-right', 'Node >20。'),
    ], '/private/project');
    expect(compatible.risks.some((risk) => risk.title.includes('node-version'))).toBe(false);
  });

  it('包管理器否定要求只与同值必须要求冲突', async () => {
    const compatible = await analyzer.analyze([
      entry('forbid-npm', '禁止使用 npm。'),
      entry('require-pnpm', '必须使用 pnpm。'),
    ], '/private/project');
    expect(compatible.risks.some((risk) => risk.title.includes('package-manager'))).toBe(false);

    const incompatible = await analyzer.analyze([
      entry('forbid-npm', '禁止使用 npm。'),
      entry('require-npm', '必须使用 npm。'),
    ], '/private/project');
    expect(incompatible.risks.find((risk) => risk.title.includes('package-manager'))).toMatchObject({
      kind: 'semantic-conflict',
      sides: expect.arrayContaining([
        expect.objectContaining({ itemId: 'forbid-npm' }),
        expect.objectContaining({ itemId: 'require-npm' }),
      ]),
    });
  });

  it('开发与生产环境的不同要求不会被误报为冲突', async () => {
    const result = await analyzer.analyze([
      entry('dev-port', '开发环境默认端口为 3000，必须运行 npm dev。'),
      entry('prod-port', '生产环境默认端口为 4000，必须运行 pnpm dev。'),
    ], '/private/project');

    expect(result.risks.some((risk) => risk.kind === 'conflict' || risk.kind === 'semantic-conflict')).toBe(false);
  });

  it('只在实际重叠的 qualifier 内判断冲突', async () => {
    const result = await analyzer.analyze([
      entry('dev-npm-a', '开发环境必须使用 npm。'),
      entry('dev-npm-b', '开发环境必须使用 npm。'),
      entry('prod-pnpm', '生产环境必须使用 pnpm。'),
    ], '/private/project');

    expect(result.risks.some((risk) => risk.title.includes('package-manager'))).toBe(false);
  });

  it('失效引用检查不沿项目内符号链接探测项目外文件', async () => {
    const base = await mkdtemp(path.join(os.tmpdir(), 'context-hub-analyzer-symlink-'));
    temporaryDirectories.push(base);
    const root = path.join(base, 'project');
    const outside = path.join(base, 'outside');
    await Promise.all([mkdir(path.join(root, 'docs'), { recursive: true }), mkdir(outside, { recursive: true })]);
    await writeFile(path.join(outside, 'exists.md'), '项目外文件', 'utf8');
    await symlink(outside, path.join(root, 'linked-outside'));

    const result = await analyzer.analyze([
      entry('reference', '[外部文件](../linked-outside/exists.md)', { source: { relativePath: 'docs/rules.md' } }),
    ], root);

    expect(result.risks).toEqual([expect.objectContaining({
      kind: 'broken-reference',
      sides: [expect.objectContaining({ excerpt: '../linked-outside/exists.md' })],
    })]);
  });

  it('海量失效引用受分析硬上限约束并明确标记 truncated', async () => {
    const result = await new LocalSemanticAnalyzer(7).analyze([
      entry('many-references', Array.from({ length: 30 }, (_, index) => `[缺失 ${index}](missing-${index}.md)`).join('\n')),
    ], '/private/project');

    expect(result.truncated).toBe(true);
    expect(result.risks).toHaveLength(7);
    expect(result.warnings.join('\n')).toContain('7 个风险/引用安全上限');
  });

  it('海量互不冲突声明受独立硬上限约束并明确标记 truncated', async () => {
    const entries = Array.from({ length: 40 }, (_, index) => (
      entry(`unique-action-${index}`, `必须执行互不相同的动作 ${index}。`)
    ));
    const result = await new LocalSemanticAnalyzer(100, 7).analyze(entries, '/private/project');

    expect(result.risks).toEqual([]);
    expect(result.truncated).toBe(true);
    expect(result.warnings).toEqual([expect.stringContaining('7 条声明安全上限')]);
  });

  it('同一主题出现三个互斥值时只生成一个包含全部来源的风险', async () => {
    const result = await analyzer.analyze([
      entry('port-3000', '默认端口为 3000。'),
      entry('port-4000', '默认端口为 4000。'),
      entry('port-5000', '默认端口为 5000。'),
    ], '/private/project');

    const portRisks = result.risks.filter((risk) => risk.kind === 'semantic-conflict' && risk.title.includes('port'));
    expect(portRisks).toHaveLength(1);
    expect(portRisks[0].sides).toHaveLength(3);
    expect(portRisks[0].sides.map((side) => side.itemId).sort()).toEqual(['port-3000', 'port-4000', 'port-5000']);
  });
});

describe('LocalHttpAnalyzer 与 AnalyzerPipeline', () => {
  it('只允许无凭据的 HTTP(S) 回环地址并拒绝外部端点', () => {
    expect(() => new LocalHttpAnalyzer('http://127.0.0.1:43199/analyze')).not.toThrow();
    expect(() => new LocalHttpAnalyzer('http://localhost:43199/analyze')).not.toThrow();
    expect(() => new LocalHttpAnalyzer('https://example.com/analyze')).toThrow('只允许无凭据的本机 HTTP 回环地址');
    expect(() => new LocalHttpAnalyzer('http://127.0.0.1.evil.example/analyze')).toThrow('只允许无凭据的本机 HTTP 回环地址');
    expect(() => new LocalHttpAnalyzer('http://user:password@localhost:43199/analyze')).toThrow('只允许无凭据的本机 HTTP 回环地址');
  });

  it('回环调用不发送秘密、路径或 URI，并由宿主按 itemId 重建可信来源', async () => {
    let received: unknown;
    const transport = inProcessTransport(async (request) => {
      received = await request.json();
      return Response.json({
        risks: [{
          title: '远端发现冲突',
          description: '两个条目可能不兼容。',
          itemIds: ['safe-a', 'safe-b'],
          source: 'REMOTE-FORGED-PATH',
          sides: [{ source: 'REMOTE-FORGED-PATH' }],
        }],
      });
    });
    const fakeSecret = ['sk', 'test-51FakeAnalyzerSecret890123456789'].join('-');
    const privateRoot = '/Users/private-owner/sensitive-project';
    const safeA = entry('safe-a', '使用稳定接口。', {
      title: '安全条目 A',
      summary: '宿主摘要 A',
      source: { relativePath: 'private/a.md', uri: 'file:///Users/private-owner/sensitive-project/private/a.md', locator: '第 7 行' },
    });
    const safeB = entry('safe-b', '使用兼容接口。', {
      title: '安全条目 B',
      summary: '宿主摘要 B',
      source: { relativePath: 'private/b.md', uri: 'file:///Users/private-owner/sensitive-project/private/b.md', locator: '第 9 行' },
    });
    const warning = entry('secret-warning', '原值已经丢弃。', { packageType: 'secret-warning' });
    const tainted = entry('tainted', `调试值为 ${fakeSecret}。`);

    const result = await new LocalHttpAnalyzer(ANALYZER_ENDPOINT, 5_000, transport).analyze([safeA, safeB, warning, tainted], privateRoot);
    const payload = received as { schemaVersion: string; entries: Array<Record<string, unknown>> };
    expect(payload.schemaVersion).toBe('1');
    expect(payload.entries.map((item) => item.id)).toEqual(['safe-a', 'safe-b']);
    expect(Object.keys(payload.entries[0]).sort()).toEqual(['content', 'id', 'scope', 'tags', 'title']);
    const serializedRequest = JSON.stringify(payload);
    expect(serializedRequest).not.toContain(fakeSecret);
    expect(serializedRequest).not.toContain(privateRoot);
    expect(serializedRequest).not.toContain('private/a.md');
    expect(serializedRequest).not.toContain('file://');

    expect(result.descriptor.status).toBe('ok');
    expect(result.risks).toHaveLength(1);
    expect(result.risks[0].sides).toEqual([
      { itemId: 'safe-a', title: '安全条目 A', source: 'private/a.md', locator: '第 7 行', excerpt: '宿主摘要 A' },
      { itemId: 'safe-b', title: '安全条目 B', source: 'private/b.md', locator: '第 9 行', excerpt: '宿主摘要 B' },
    ]);
    expect(JSON.stringify(result)).not.toContain('REMOTE-FORGED-PATH');
  });

  it('拒绝回环端点的重定向，正文不会被转发到第二个接收器', async () => {
    let redirectedRequests = 0;
    const receiver = 'http://127.0.0.1:43199/receiver';
    const transport = inProcessTransport(async (request) => {
      if (request.url === receiver) {
        redirectedRequests += 1;
        return Response.json({ risks: [] });
      }
      await request.text();
      expect(request.redirect).toBe('error');
      throw new TypeError('fetch failed: redirect mode is error');
    });
    const entries = [entry('port-3000', '默认端口为 3000。'), entry('port-4000', '默认端口为 4000。')];
    const pipeline = new AnalyzerPipeline(new LocalSemanticAnalyzer(), new LocalHttpAnalyzer(ANALYZER_ENDPOINT, 5_000, transport));

    const result = await pipeline.analyze(entries, '/private/project');

    expect(redirectedRequests).toBe(0);
    expect(result.descriptor.status).toBe('degraded');
    expect(result.risks.some((risk) => risk.analyzerId === 'local-semantic')).toBe(true);
  });

  it('可选分析器返回非法结构时保留本地基线并明确降级', async () => {
    const transport = inProcessTransport(async (request) => {
      await request.text();
      return Response.json({ risks: 'not-an-array' });
    });
    const entries = [entry('port-3000', '默认端口为 3000。'), entry('port-4000', '默认端口为 4000。')];
    const pipeline = new AnalyzerPipeline(new LocalSemanticAnalyzer(), new LocalHttpAnalyzer(ANALYZER_ENDPOINT, 5_000, transport));

    const result = await pipeline.analyze(entries, '/private/project');

    expect(result.descriptor.status).toBe('degraded');
    expect(result.warnings).toEqual([expect.stringContaining('ANALYZER_INVALID_OUTPUT')]);
    expect(result.risks.some((risk) => risk.analyzerId === 'local-semantic' && risk.title.includes('port'))).toBe(true);
  });

  it('可选分析器超时时保留本地基线并明确降级', async () => {
    const transport = inProcessTransport(async (request) => {
      await request.text();
      return new Promise<Response>((_resolve, reject) => {
        const abort = () => reject(request.signal.reason);
        if (request.signal.aborted) abort();
        else request.signal.addEventListener('abort', abort, { once: true });
      });
    });
    const entries = [entry('port-3000', '默认端口为 3000。'), entry('port-4000', '默认端口为 4000。')];
    const pipeline = new AnalyzerPipeline(new LocalSemanticAnalyzer(), new LocalHttpAnalyzer(ANALYZER_ENDPOINT, 10, transport));

    const result = await pipeline.analyze(entries, '/private/project');

    expect(result.descriptor.status).toBe('degraded');
    expect(result.warnings).toEqual([expect.stringContaining('ANALYZER_TIMEOUT')]);
    expect(result.risks.some((risk) => risk.analyzerId === 'local-semantic' && risk.title.includes('port'))).toBe(true);
  });

  it('用户主动取消会原样向上传播，而不是伪装成可选分析器降级', async () => {
    let markRequestSeen!: () => void;
    const requestSeen = new Promise<void>((resolve) => { markRequestSeen = resolve; });
    const transport = inProcessTransport(async (request) => {
      await request.text();
      markRequestSeen();
      return new Promise<Response>((_resolve, reject) => {
        const abort = () => reject(request.signal.reason);
        if (request.signal.aborted) abort();
        else request.signal.addEventListener('abort', abort, { once: true });
      });
    });
    const controller = new AbortController();
    const reason = new Error('USER_ABORT');
    const pipeline = new AnalyzerPipeline(new LocalSemanticAnalyzer(), new LocalHttpAnalyzer(ANALYZER_ENDPOINT, 5_000, transport));
    const pending = pipeline.analyze([entry('safe-a', '普通规则。'), entry('safe-b', '另一条普通规则。')], '/private/project', controller.signal);

    await requestSeen;
    controller.abort(reason);

    await expect(pending).rejects.toBe(reason);
  });
});
