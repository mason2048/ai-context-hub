import { mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { renameSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { scanProjectWithIndex } from '../server/scanner.js';

const roots: string[] = [];

async function project(label: string): Promise<string> {
  const root = await mkdtemp(path.join(os.tmpdir(), `context-hub-scan-${label}-`));
  roots.push(root);
  return root;
}

async function put(root: string, relative: string, content: string): Promise<void> {
  const target = path.join(root, relative);
  await mkdir(path.dirname(target), { recursive: true });
  await writeFile(target, content, 'utf8');
}

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('P2 扫描器', () => {
  it('识别 Cursor 当前 .mdc 规则与旧版 .cursorrules', async () => {
    const root = await project('cursor-rules');
    await put(root, '.cursor/rules/typescript.mdc', '---\ndescription: TypeScript 规则\n---\n\n# Cursor TypeScript\n\n必须保持严格类型。');
    await put(root, '.cursorrules', '# Cursor 旧规则\n\n提交前必须运行 npm test。');

    const { result } = await scanProjectWithIndex(root);
    const bySource = new Map(result.entries.map((entry) => [entry.source.relativePath, entry]));
    expect(bySource.get('.cursor/rules/typescript.mdc')).toMatchObject({ category: 'rule', title: 'Cursor TypeScript' });
    expect(bySource.get('.cursorrules')).toMatchObject({ category: 'rule', title: 'Cursor 旧规则' });
  });

  it('遵循根与嵌套 .gitignore 的相对/锚定/negation 语义', async () => {
    const root = await project('nested-ignore');
    await put(root, '.gitignore', '*.md\n!AGENTS.md\ndocs/*\n!docs/keep.md\nblocked/\n!blocked/AGENTS.md\n');
    await put(root, 'AGENTS.md', '# 根规则\n\n保留根规则。');
    await put(root, 'ignored.md', '# 根忽略\n\n不应出现。');
    await put(root, 'docs/keep.md', '# 保留知识\n\n由 negation 恢复。');
    await put(root, 'docs/drop.md', '# 丢弃知识\n\n不应出现。');
    await put(root, 'blocked/AGENTS.md', '# 无法复活\n\n父目录被排除后不应遍历。');
    await put(root, 'packages/.gitignore', '!AGENTS.md\n');
    await put(root, 'packages/AGENTS.md', '# 子规则\n\n深层规则覆盖根忽略。');
    await put(root, 'packages/deep/AGENTS.md', '# 深层子规则\n\n无斜杠 negation 可匹配后代。');

    const { result } = await scanProjectWithIndex(root);
    const sources = new Set(result.entries.map((entry) => entry.source.relativePath));
    expect(sources).toEqual(new Set(['AGENTS.md', 'docs/keep.md', 'packages/AGENTS.md', 'packages/deep/AGENTS.md']));
  });

  it('嵌套 /pattern 只锚定当前目录，安全硬排除不能被 negation 绕过', async () => {
    const root = await project('anchored-ignore');
    await put(root, '.gitignore', '!node_modules/**\n');
    await put(root, 'packages/.gitignore', '/only.md\n');
    await put(root, 'packages/only.md', '# 锚定忽略\n\n不应出现。');
    await put(root, 'packages/deep/only.md', '# 深层保留\n\n应该出现。');
    await put(root, 'node_modules/pkg/AGENTS.md', '# 安全排除\n\n不得通过 negation 恢复。');
    const { result } = await scanProjectWithIndex(root);
    const sources = result.entries.map((entry) => entry.source.relativePath);
    expect(sources).toContain('packages/deep/only.md');
    expect(sources).not.toContain('packages/only.md');
    expect(sources.some((source) => source.startsWith('node_modules/'))).toBe(false);
  });

  it('增量刷新仍重新发现目录，但复用所有未变文件的净化解析结果', async () => {
    const root = await project('incremental');
    await put(root, 'AGENTS.md', '# 测试规范\n\n运行 npm test。');
    await put(root, 'CLAUDE.md', '# 提交规范\n\n提交前检查 diff。');
    const cold = await scanProjectWithIndex(root);
    const warm = await scanProjectWithIndex(root, { previousIndex: cold.index });
    expect(warm.result.stats.performance.cacheHits).toBe(2);
    expect(warm.result.stats.performance.filesRead).toBe(0);
    expect(warm.result.entries.map((entry) => entry.id)).toEqual(cold.result.entries.map((entry) => entry.id));

    await put(root, 'docs/new.md', '# 新知识\n\n新增文件必须被发现。');
    const added = await scanProjectWithIndex(root, { previousIndex: warm.index });
    expect(added.result.stats.performance.cacheHits).toBe(2);
    expect(added.result.stats.performance.filesRead).toBe(1);
    expect(added.result.entries.some((entry) => entry.source.relativePath === 'docs/new.md')).toBe(true);

    const before = added.result.entries.find((entry) => entry.source.relativePath === 'AGENTS.md')!;
    await put(root, 'AGENTS.md', '# 测试规范\n\n运行 pnpm test。');
    const changed = await scanProjectWithIndex(root, { previousIndex: added.index });
    const after = changed.result.entries.find((entry) => entry.source.relativePath === 'AGENTS.md')!;
    expect(after.logicalKey).toBe(before.logicalKey);
    expect(after.id).not.toBe(before.id);
    expect(changed.result.stats.performance.cacheMisses).toBe(1);
  });

  it('输出不受 worker 并发完成顺序影响，token 使用 o200k_base 精确计数', async () => {
    const root = await project('deterministic');
    for (let index = 0; index < 40; index += 1) {
      await put(root, `docs/${String(index).padStart(2, '0')}.md`, `# 条目 ${index}\n\n这是第 ${index} 条知识。`);
    }
    const serial = await scanProjectWithIndex(root, { concurrency: 1 });
    const parallel = await scanProjectWithIndex(root, { concurrency: 8 });
    expect(parallel.result.entries.map((entry) => [entry.id, entry.logicalKey])).toEqual(serial.result.entries.map((entry) => [entry.id, entry.logicalKey]));
    expect(parallel.result.stats.tokenEncoding).toBe('o200k_base');
    expect(parallel.result.stats.tokenCount).toBe(parallel.result.entries.reduce((sum, entry) => sum + entry.tokenCount, 0));
  });

  it('达到安全上限时明确标记 truncated，而不是声称完整成功', async () => {
    const root = await project('limits');
    for (let index = 0; index < 4; index += 1) await put(root, `docs/${index}.md`, `# ${index}\n\n正文 ${index}`);
    const { result } = await scanProjectWithIndex(root, { maxFiles: 2 });
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.warnings.join('\n')).toContain('结果已明确标记为不完整');
    expect(result.stats.filesScanned).toBe(2);
  });

  it('已因文件上限 partial 时仍复核新增 .gitignore，且不回显新排除正文', async () => {
    const root = await project('partial-ignore-churn');
    await put(root, 'a-private.md', '# 私有\n\nPRIVATE-PARTIAL-MARKER');
    await put(root, 'z-other.md', '# 其他\n\n普通内容');
    let changed = false;
    const { result } = await scanProjectWithIndex(root, {
      maxFiles: 1,
      onProgress(progress) {
        if (changed || progress.phase !== 'discover' || progress.percent !== 5) return;
        changed = true;
        writeFileSync(path.join(root, '.gitignore'), 'a-private.md\n', 'utf8');
      },
    });

    expect(changed).toBe(true);
    expect(result.stats.performance.truncated).toBe(true);
    expect(JSON.stringify(result)).not.toContain('PRIVATE-PARTIAL-MARKER');
    expect(result.warnings.join('\n')).toMatch(/IGNORE_CHANGED|DIRECTORY_CHANGED/);
  });

  it('流式目录发现受文件系统条目硬上限约束', async () => {
    const root = await project('fs-entry-limit');
    for (let index = 0; index < 30; index += 1) {
      await put(root, `irrelevant-${String(index).padStart(2, '0')}.txt`, '非候选文件');
    }
    const { result } = await scanProjectWithIndex(root, { maxFsEntries: 10 });
    expect(result.stats.performance.fsEntriesVisited).toBe(10);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.stats.performance.candidatesDiscovered).toBe(0);
    expect(result.warnings.join('\n')).toContain('10 个文件系统条目');
  });

  it('无法安全读取的 .gitignore 必须 fail closed 并标记不完整', async () => {
    const root = await project('oversized-gitignore');
    await put(root, '.gitignore', `private.md\n${'# padding\n'.repeat(30_000)}`);
    await put(root, 'private.md', '# 私有上下文\n\nPRIVATE-CONTEXT-MARKER');
    const { result } = await scanProjectWithIndex(root);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.entries).toEqual([]);
    expect(result.warnings.join('\n')).toContain('.gitignore（FILE_TOO_LARGE）');
    expect(JSON.stringify(result)).not.toContain('PRIVATE-CONTEXT-MARKER');
  });

  it('扫描期间新增 .gitignore 时 fail closed，不把新排除内容当完整结果保存', async () => {
    const root = await project('ignore-churn');
    await mkdir(path.join(root, 'a'));
    await mkdir(path.join(root, 'z'));
    await put(root, 'private.md', '# 私有\n\nPRIVATE-IGNORE-CHURN-MARKER');
    let changed = false;
    const { result } = await scanProjectWithIndex(root, {
      async onProgress(progress) {
        if (changed || progress.phase !== 'discover' || progress.processed !== 2) return;
        changed = true;
        await writeFile(path.join(root, '.gitignore'), 'private.md\n', 'utf8');
      },
    });

    expect(changed).toBe(true);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.warnings.join('\n')).toMatch(/IGNORE_CHANGED|DIRECTORY_CHANGED/);
    expect(JSON.stringify(result)).not.toContain('PRIVATE-IGNORE-CHURN-MARKER');
  });

  it('目录枚举期间新增候选文件时 fail closed，避免提交遗漏文件的快照', async () => {
    const root = await project('directory-churn');
    await mkdir(path.join(root, 'a'));
    await mkdir(path.join(root, 'z'));
    let changed = false;
    const { result } = await scanProjectWithIndex(root, {
      onProgress(progress) {
        if (changed || progress.phase !== 'discover' || progress.processed !== 2) return;
        changed = true;
        writeFileSync(path.join(root, 'NEW.md'), '# 新增\n\n扫描期间新增的规则。', 'utf8');
      },
    });

    expect(changed).toBe(true);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.warnings.join('\n')).toContain('DIRECTORY_CHANGED');
    expect(result.entries).toEqual([]);
  });

  it('单文件海量标题受每文件条目硬上限约束', async () => {
    const root = await project('per-file-entry-limit');
    const content = Array.from({ length: 40 }, (_, index) => `# 小节 ${index}\n\n正文 ${index}。`).join('\n');
    await put(root, 'AGENTS.md', content);
    const { result } = await scanProjectWithIndex(root, { maxEntriesPerFile: 12, maxEntries: 30 });
    expect(result.entries).toHaveLength(12);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.warnings.join('\n')).toContain('每文件 12 个结构化条目上限');
  });

  it('多文件条目总量受全局硬上限约束且不会继续调度全部候选', async () => {
    const root = await project('global-entry-limit');
    for (let file = 0; file < 6; file += 1) {
      const sections = Array.from({ length: 4 }, (_, section) => `# F${file}-${section}\n\n正文。`).join('\n');
      await put(root, `docs/${file}.md`, sections);
    }
    const { result } = await scanProjectWithIndex(root, { maxEntriesPerFile: 10, maxEntries: 9, concurrency: 2 });
    expect(result.entries).toHaveLength(9);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.stats.performance.filesRead).toBeLessThan(6);
    expect(result.warnings.join('\n')).toContain('全局 9 个结构化条目上限');
  });

  it('正文总量上限按最终快照计算，warm cache 不能绕过', async () => {
    const root = await project('total-bytes');
    await put(root, 'AGENTS.md', `# 规则\n\n${'a'.repeat(1_200)}`);
    const cold = await scanProjectWithIndex(root, { maxTotalBytes: 2_000 });
    expect(cold.result.stats.performance.truncated).toBe(false);
    expect(cold.result.stats.performance.totalBytesRead).toBeGreaterThan(1_000);

    await put(root, 'docs/new.md', `# 新规则\n\n${'b'.repeat(1_200)}`);
    const warm = await scanProjectWithIndex(root, { previousIndex: cold.index, maxTotalBytes: 2_000 });
    expect(warm.result.stats.performance.cacheHits).toBe(1);
    expect(warm.result.stats.performance.truncated).toBe(true);
    expect(warm.result.stats.performance.totalBytesRead).toBeGreaterThan(2_000);
    expect(warm.result.warnings.join('\n')).toContain('2000 字节候选正文');
  });

  it('候选在发现后增长时按批次提前停止，不读取全部候选', async () => {
    const root = await project('growth-after-discovery');
    for (let index = 0; index < 10; index += 1) {
      await put(root, `docs/${String(index).padStart(2, '0')}.md`, '# 小');
    }
    let expanded = false;
    const { result } = await scanProjectWithIndex(root, {
      maxTotalBytes: 1_000,
      concurrency: 2,
      onProgress(progress) {
        if (expanded || progress.phase !== 'discover' || progress.percent !== 5) return;
        expanded = true;
        for (let index = 0; index < 10; index += 1) {
          void writeFile(path.join(root, `docs/${String(index).padStart(2, '0')}.md`), `# 变大\n\n${'x'.repeat(400)}`, 'utf8');
        }
      },
    });

    expect(expanded).toBe(true);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.stats.performance.filesRead).toBeLessThan(result.stats.performance.candidatesDiscovered);
    expect(result.stats.performance.totalBytesRead).toBeGreaterThan(1_000);
    expect(result.warnings.join('\n')).toContain('快照安全上限');
  });

  it('分析风险达到硬上限时标记不完整并截断风险清单', async () => {
    const root = await project('risk-limit');
    await put(root, 'KNOWLEDGE.md', Array.from({ length: 40 }, (_, index) => `[缺失 ${index}](missing-${index}.md)`).join('\n'));
    const { result } = await scanProjectWithIndex(root, {
      maxRisks: 9,
      analyzer: new (await import('../server/analyzers.js')).LocalSemanticAnalyzer(9),
    });

    expect(result.risks).toHaveLength(9);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.warnings.join('\n')).toContain('9 个风险/引用上限');
  });

  it('默认分析器使用扫描规则中的语义声明上限', async () => {
    const root = await project('claim-limit');
    const content = Array.from({ length: 20 }, (_, index) => `# 规则 ${index}\n\n必须执行互不相同的动作 ${index}。`).join('\n');
    await put(root, 'AGENTS.md', content);
    const { result } = await scanProjectWithIndex(root, { maxClaims: 7, maxEntries: 30 });

    expect(result.rules.maxClaims).toBe(7);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.warnings.join('\n')).toContain('7 条声明安全上限');
  });

  it('祖先目录被替换为外部符号链接时 fail closed 且不读取外部内容', async () => {
    const root = await project('ancestor-symlink-race');
    const outside = await project('ancestor-symlink-outside');
    await mkdir(path.join(root, 'a'));
    await mkdir(path.join(root, 'z'));
    await put(outside, 'EXTERNAL.md', '# 外部\n\nPRIVATE-OUTSIDE-PROJECT-MARKER');
    let swapped = false;
    const { result } = await scanProjectWithIndex(root, {
      async onProgress(progress) {
        if (swapped || progress.phase !== 'discover' || progress.processed !== 2) return;
        swapped = true;
        await rm(path.join(root, 'z'), { recursive: true, force: true });
        await symlink(outside, path.join(root, 'z'));
      },
    });

    expect(swapped).toBe(true);
    expect(result.stats.performance.truncated).toBe(true);
    expect(JSON.stringify(result)).not.toContain('PRIVATE-OUTSIDE-PROJECT-MARKER');
    expect(result.entries.some((entry) => entry.source.relativePath.startsWith('z/'))).toBe(false);
    expect(result.warnings.join('\n')).toMatch(/SYMLINK_PATH|PATH_CHANGED|ENOENT/);
  });

  it('发现后祖先被替换为另一普通目录时丢弃替换内容并标记不完整', async () => {
    const root = await project('ancestor-directory-race');
    const replacement = await project('ancestor-directory-replacement');
    await mkdir(path.join(root, 'a'));
    await put(root, 'z/AGENTS.md', '# 原规则\n\n原始项目正文。');
    await put(replacement, 'AGENTS.md', '# 替换规则\n\nPRIVATE-REPLACEMENT-DIRECTORY-MARKER');
    const oldDirectory = path.join(root, 'z-old');
    let swapped = false;
    const { result } = await scanProjectWithIndex(root, {
      onProgress(progress) {
        if (swapped || progress.phase !== 'discover' || progress.processed !== 3) return;
        swapped = true;
        renameSync(path.join(root, 'z'), oldDirectory);
        renameSync(replacement, path.join(root, 'z'));
      },
    });
    roots.push(oldDirectory);

    expect(swapped).toBe(true);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.entries).toEqual([]);
    expect(JSON.stringify(result)).not.toContain('PRIVATE-REPLACEMENT-DIRECTORY-MARKER');
    expect(result.warnings.join('\n')).toContain('DIRECTORY_CHANGED');
  });

  it('分析阶段整个根目录被普通目录替换时终局校验丢弃正文', async () => {
    const root = await project('root-directory-race');
    const replacement = await project('root-directory-replacement');
    await put(root, 'AGENTS.md', '# 原规则\n\n[依赖](needed.md)');
    await put(replacement, 'needed.md', '# 外部\n\nPRIVATE-ROOT-REPLACEMENT-MARKER');
    const oldRoot = `${root}-old`;
    let swapped = false;
    const { result } = await scanProjectWithIndex(root, {
      onProgress(progress) {
        if (swapped || progress.phase !== 'analyze') return;
        swapped = true;
        renameSync(root, oldRoot);
        renameSync(replacement, root);
      },
    });
    roots.push(oldRoot);

    expect(swapped).toBe(true);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.entries).toEqual([]);
    expect(result.risks).toEqual([]);
    expect(JSON.stringify(result)).not.toContain('PRIVATE-ROOT-REPLACEMENT-MARKER');
    expect(result.warnings.join('\n')).toContain('ROOT_CHANGED');
  });

  it('分析阶段新增 .gitignore 时终局校验不回显新排除正文', async () => {
    const root = await project('late-ignore-churn');
    await put(root, 'AGENTS.md', '# 私有规则\n\nPRIVATE-LATE-IGNORE-MARKER');
    let changed = false;
    const { result } = await scanProjectWithIndex(root, {
      onProgress(progress) {
        if (changed || progress.phase !== 'analyze') return;
        changed = true;
        writeFileSync(path.join(root, '.gitignore'), 'AGENTS.md\n', 'utf8');
      },
    });

    expect(changed).toBe(true);
    expect(result.stats.performance.truncated).toBe(true);
    expect(result.entries).toEqual([]);
    expect(JSON.stringify(result)).not.toContain('PRIVATE-LATE-IGNORE-MARKER');
    expect(result.warnings.join('\n')).toMatch(/IGNORE_CHANGED|DIRECTORY_CHANGED/);
  });

  it('通用本地语义分析规范化等价命令，并聚合互斥命令双方', async () => {
    const root = await project('semantics');
    await put(root, 'AGENTS.md', '# 测试命令\n\n必须运行 npm run test。\n\n# 端口\n\n默认端口为 3000。');
    await put(root, 'CLAUDE.md', '# 测试命令\n\n必须运行 npm test。\n\n# 端口\n\n默认端口为 4000。');
    const equivalent = await scanProjectWithIndex(root);
    expect(equivalent.result.risks.some((risk) => risk.kind === 'conflict')).toBe(false);
    const portRisk = equivalent.result.risks.find((risk) => risk.kind === 'semantic-conflict' && risk.title.includes('port'));
    expect(portRisk?.sides).toHaveLength(2);

    await put(root, 'CLAUDE.md', '# 测试命令\n\n必须运行 pnpm test。');
    const conflict = await scanProjectWithIndex(root, { previousIndex: equivalent.index });
    const risk = conflict.result.risks.find((item) => item.kind === 'conflict');
    expect(risk?.sides.map((side) => side.excerpt).sort()).toEqual(['npm test', 'pnpm test']);
  });

  it('AbortSignal 取消不会返回部分结果', async () => {
    const root = await project('abort');
    await put(root, 'AGENTS.md', '# 规则\n\n正文。');
    const controller = new AbortController();
    controller.abort(new Error('用户取消'));
    await expect(scanProjectWithIndex(root, { signal: controller.signal })).rejects.toMatchObject({ name: 'AbortError' });
  });
});
