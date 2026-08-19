import { createHash } from 'node:crypto';
import { readFile, readdir, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { scanProject } from '../server/scanner.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const samplePath = path.resolve(here, '../sample-project');
const fakeSecret = 'context-hub-fixture-credential-890123456789';

async function directoryFingerprint(root: string): Promise<string> {
  const rows: string[] = [];
  async function walk(directory: string) {
    const children = await readdir(directory, { withFileTypes: true });
    children.sort((a, b) => a.name.localeCompare(b.name));
    for (const child of children) {
      const absolute = path.join(directory, child.name);
      const relative = path.relative(root, absolute);
      if (child.isDirectory()) await walk(absolute);
      else if (child.isFile()) {
        const info = await stat(absolute);
        const content = await readFile(absolute);
        rows.push(`${relative}:${info.size}:${info.mtimeMs}:${createHash('sha256').update(content).digest('hex')}`);
      }
    }
  }
  await walk(root);
  return createHash('sha256').update(rows.join('\n')).digest('hex');
}

describe('只读项目扫描', () => {
  it('识别所有标准示例文件，且每个条目都有来源、定位和 revision', async () => {
    const result = await scanProject(samplePath);
    const recognizedSources = new Set(result.entries.map((entry) => entry.source.relativePath));
    const expectedSources = [
      'AGENTS.md', 'CLAUDE.md', '.github/copilot-instructions.md',
      'skills/release/SKILL.md', 'docs/architecture.md', 'docs/ops.md',
      'docs/style-copy.md', '.mcp.json',
    ];
    expect(expectedSources.filter((source) => recognizedSources.has(source))).toHaveLength(expectedSources.length);
    expect(result.stats.filesScanned).toBe(expectedSources.length);
    expect(result.entries.every((entry) => entry.source.relativePath && entry.source.locator && /^[a-f0-9]{64}$/.test(entry.source.revision))).toBe(true);
    expect(recognizedSources.has('node_modules/ignored-rule/AGENTS.md')).toBe(false);
  });

  it('成对检出相反测试命令、完全重复、失效引用和秘密', async () => {
    const result = await scanProject(samplePath);
    const conflict = result.risks.find((risk) => risk.kind === 'conflict');
    expect(conflict?.sides).toHaveLength(2);
    expect(conflict?.sides.map((side) => side.excerpt).sort()).toEqual(['npm test', 'pnpm test']);
    expect(result.risks.some((risk) => risk.kind === 'duplicate' && risk.sides.length >= 2)).toBe(true);
    expect(result.risks.some((risk) => risk.kind === 'broken-reference')).toBe(true);
    expect(result.risks.some((risk) => risk.kind === 'secret')).toBe(true);
  });

  it('在 API 可返回的数据中不保留假密钥完整值', async () => {
    const result = await scanProject(samplePath);
    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(fakeSecret);
    expect(serialized).toContain('已脱敏');
  });

  it('扫描前后示例输入目录逐文件指纹完全不变', async () => {
    const before = await directoryFingerprint(samplePath);
    await scanProject(samplePath);
    const after = await directoryFingerprint(samplePath);
    expect(after).toBe(before);
  });
});
