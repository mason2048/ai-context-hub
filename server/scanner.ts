import { createHash } from 'node:crypto';
import { lstat, open, opendir, realpath, stat } from 'node:fs/promises';
import type { Dirent, Stats } from 'node:fs';
import { constants as fsConstants } from 'node:fs';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import ignore, { type Ignore } from 'ignore';
import { AnalyzerPipeline, LocalSemanticAnalyzer } from './analyzers.js';
import { findSecrets, isSecretFile } from './security.js';
import { countEntryTokens, TOKEN_ENCODING } from './tokenizer.js';
import type {
  Analyzer,
  ContextEntry,
  ContextRisk,
  FileIndexEntry,
  ItemCategory,
  ItemScope,
  RiskSide,
  ScanExecution,
  ScanIndex,
  ScanOptions,
  ScanProgress,
  ScanResult,
  ScanRules,
} from './types.js';

const SCANNER_CACHE_REVISION = 'scanner-v2:parser-v4:secret-v3:o200k-base';

export const SCAN_RULES: ScanRules = {
  included: [
    'AGENTS.md / CLAUDE.md / copilot-instructions.md',
    '.cursor/rules/**（含 .mdc）/ .cursorrules / .claude/rules/** / rules/**',
    '**/SKILL.md',
    'Markdown 知识文件（*.md, *.mdx）',
    'MCP 配置元数据（.mcp.json, mcp.json）',
  ],
  excludedDirectories: [
    '.git', 'node_modules', 'vendor', 'dist', 'build', '.next', 'out',
    'coverage', '.cache', '.venv', 'venv', '__pycache__', 'private', 'secrets',
  ],
  excludedFiles: [
    '.env / .env.*', '*.pem', '*.key', '*.p12', '*.pfx', 'id_rsa*',
    '二进制文件', '根目录及嵌套 .gitignore 中的路径',
  ],
  maxFileBytes: 1_000_000,
  maxFiles: 5_000,
  maxDirectories: 20_000,
  // Bounds streamed directory discovery even when a flat directory contains
  // millions of irrelevant files. Partial scans are never persisted.
  maxFsEntries: 100_000,
  maxEntriesPerFile: 1_000,
  maxEntries: 5_000,
  maxRisks: 5_000,
  maxClaims: 20_000,
  // result + incremental index duplicate entry metadata, so keep serialized snapshots well below 128 MiB.
  maxTotalBytes: 32 * 1024 * 1024,
  concurrency: 8,
};

const hardExcludedDirectories = new Set(SCAN_RULES.excludedDirectories);

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function toPosix(value: string): string {
  return value.split(path.sep).join('/');
}

function abortIfNeeded(signal?: AbortSignal): void {
  if (signal?.aborted) {
    const error = signal.reason instanceof Error ? signal.reason : new Error('扫描已取消。');
    error.name = 'AbortError';
    throw error;
  }
}

function emitProgress(options: ScanOptions, progress: ScanProgress): void {
  options.onProgress?.(progress);
}

function isCandidate(relativePath: string): boolean {
  const normalized = toPosix(relativePath);
  const basename = path.basename(relativePath).toLowerCase();
  if (basename === '.mcp.json' || basename === 'mcp.json') return true;
  if (basename === '.cursorrules') return true;
  if (basename === 'agents.md' || basename === 'claude.md' || basename === 'skill.md') return true;
  if (normalized.toLowerCase() === '.github/copilot-instructions.md') return true;
  if (/\.(md|mdx)$/i.test(basename)) return true;
  return /(^|\/)(?:\.cursor\/rules|\.claude\/rules|rules)\//i.test(normalized)
    && /\.(md|mdx|mdc|txt|json|ya?ml)$/i.test(basename);
}

function categoryFor(relativePath: string): ItemCategory {
  const normalized = toPosix(relativePath).toLowerCase();
  const basename = path.basename(normalized);
  if (basename === '.mcp.json' || basename === 'mcp.json') return 'tool';
  if (basename === 'skill.md' || normalized.includes('/skills/')) return 'skill';
  if (
    basename === 'agents.md' || basename === 'claude.md' || basename === '.cursorrules'
    || normalized === '.github/copilot-instructions.md'
    || normalized.includes('/rules/') || normalized.startsWith('rules/')
  ) return 'rule';
  return 'knowledge';
}

function scopeFor(category: ItemCategory): ItemScope {
  return category === 'skill' ? 'task' : 'project';
}

function summaryFor(content: string): string {
  const compact = content.replace(/[`*_>#\[\]]/g, '').replace(/\s+/g, ' ').trim();
  return compact.length > 116 ? `${compact.slice(0, 113)}…` : compact;
}

interface Section {
  title: string;
  content: string;
  startLine: number;
  endLine: number;
  occurrence: number;
}

function sectionsFromMarkdown(content: string, fallbackTitle: string, maxSections: number): { sections: Section[]; truncated: boolean } {
  const lines = content.split(/\r?\n/);
  const headings: Array<{ index: number; title: string }> = [];
  let truncated = false;
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index];
    const match = line.match(/^#{1,6}\s+(.+?)\s*#*$/);
    if (!match) continue;
    headings.push({ index, title: match[1].trim() });
    // One look-ahead heading gives the last retained section an exact end line
    // without materializing attacker-controlled heading counts.
    if (headings.length > maxSections) { truncated = true; break; }
  }
  const raw = headings.length === 0
    ? [{ title: fallbackTitle, content: content.trim(), startLine: 1, endLine: lines.length }]
    : headings.slice(0, maxSections).map((heading, position) => {
      const endIndex = (headings[position + 1]?.index ?? lines.length) - 1;
      return { title: heading.title, content: lines.slice(heading.index + 1, endIndex + 1).join('\n').trim(), startLine: heading.index + 1, endLine: endIndex + 1 };
    }).filter((section) => section.content.length > 0);
  const seen = new Map<string, number>();
  const sections = raw.map((section) => {
    const normalizedTitle = section.title.toLowerCase().trim();
    const occurrence = (seen.get(normalizedTitle) ?? 0) + 1;
    seen.set(normalizedTitle, occurrence);
    return { ...section, occurrence };
  });
  return { sections, truncated };
}

function safeMcpMetadata(content: string): Section[] {
  try {
    const parsed = JSON.parse(content) as { mcpServers?: Record<string, unknown> };
    const names = Object.keys(parsed.mcpServers ?? {});
    return [{
      title: 'MCP 工具配置',
      content: names.length > 0
        ? `已声明 MCP 服务：${names.join('、')}。出于安全考虑，不展示或执行命令、参数与环境变量。`
        : '检测到 MCP 配置文件，但未发现 mcpServers 元数据。',
      startLine: 1,
      endLine: content.split(/\r?\n/).length,
      occurrence: 1,
    }];
  } catch {
    return [{ title: 'MCP 工具配置（无法解析）', content: '检测到 MCP 配置文件，但 JSON 无法解析。原始内容未执行。', startLine: 1, endLine: content.split(/\r?\n/).length, occurrence: 1 }];
  }
}

function makeEntry(input: Omit<ContextEntry, 'tokenCount' | 'tokenEncoding' | 'tokenEstimate'>): ContextEntry {
  const tokenCount = countEntryTokens(input.title, input.content);
  return { ...input, tokenCount, tokenEncoding: TOKEN_ENCODING, tokenEstimate: tokenCount };
}

function sideFor(entry: ContextEntry, excerpt = entry.summary): RiskSide {
  return { itemId: entry.id, title: entry.title, source: entry.source.relativePath, locator: entry.source.locator, excerpt };
}

interface IgnoreFrame { baseDir: string; matcher: Ignore; revision: string }
interface IgnoreFrameRead { frame: IgnoreFrame | null; errorCode?: string }
interface RootIdentity { dev: number; ino: number }

function ignoredByFrames(relativePath: string, isDirectory: boolean, frames: IgnoreFrame[]): boolean {
  let ignored = false;
  for (const frame of frames) {
    const local = toPosix(path.posix.relative(frame.baseDir || '.', relativePath));
    if (local.startsWith('../') || local === '..' || local === '') continue;
    const result = frame.matcher.test(isDirectory ? `${local}/` : local);
    if (result.ignored) ignored = true;
    if (result.unignored) ignored = false;
  }
  return ignored;
}

async function assertSafePath(
  rootPath: string,
  relativePath: string,
  rootIdentity: RootIdentity,
  expected: 'file' | 'directory',
  signal?: AbortSignal,
): Promise<Stats> {
  abortIfNeeded(signal);
  if (path.isAbsolute(relativePath)) throw new Error('PATH_OUTSIDE_ROOT');
  const target = path.resolve(rootPath, relativePath || '.');
  if (target !== rootPath && !target.startsWith(`${rootPath}${path.sep}`)) throw new Error('PATH_OUTSIDE_ROOT');

  const rootInfo = await lstat(rootPath);
  if (rootInfo.isSymbolicLink() || !rootInfo.isDirectory()
    || rootInfo.dev !== rootIdentity.dev || rootInfo.ino !== rootIdentity.ino) throw new Error('ROOT_CHANGED');

  let current = rootPath;
  let info = rootInfo;
  const segments = relativePath.split(/[\\/]+/).filter(Boolean);
  for (let index = 0; index < segments.length; index += 1) {
    abortIfNeeded(signal);
    current = path.join(current, segments[index]);
    info = await lstat(current);
    if (info.isSymbolicLink()) throw new Error('SYMLINK_PATH');
    if (index < segments.length - 1 && !info.isDirectory()) throw new Error('NOT_DIRECTORY');
  }
  if (expected === 'file' && !info.isFile()) throw new Error('NOT_REGULAR_FILE');
  if (expected === 'directory' && !info.isDirectory()) throw new Error('NOT_DIRECTORY');
  const resolved = await realpath(current);
  if (resolved !== target) throw new Error('PATH_CHANGED');
  return info;
}

async function secureReadFile(
  filePath: string,
  maxBytes: number,
  signal?: AbortSignal,
  guard?: { rootPath: string; relativePath: string; rootIdentity: RootIdentity },
): Promise<{ content: string; statKey: string; revision: string; modifiedAt: string }> {
  abortIfNeeded(signal);
  const guardedBefore = guard
    ? await assertSafePath(guard.rootPath, guard.relativePath, guard.rootIdentity, 'file', signal)
    : null;
  const noFollow = 'O_NOFOLLOW' in fsConstants ? fsConstants.O_NOFOLLOW : 0;
  const handle = await open(filePath, fsConstants.O_RDONLY | noFollow);
  try {
    const before = await handle.stat();
    if (!before.isFile()) throw new Error('NOT_REGULAR_FILE');
    if (before.size > maxBytes) throw new Error('FILE_TOO_LARGE');
    abortIfNeeded(signal);
    const buffer = await handle.readFile();
    const after = await handle.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) throw new Error('UNSTABLE_FILE');
    if (guardedBefore && (guardedBefore.dev !== before.dev || guardedBefore.ino !== before.ino)) throw new Error('PATH_CHANGED');
    if (guard) {
      const guardedAfter = await assertSafePath(guard.rootPath, guard.relativePath, guard.rootIdentity, 'file', signal);
      if (guardedAfter.dev !== before.dev || guardedAfter.ino !== before.ino) throw new Error('PATH_CHANGED');
    }
    if (buffer.length > maxBytes) throw new Error('FILE_TOO_LARGE');
    const content = buffer.toString('utf8');
    if (content.includes('\0')) throw new Error('BINARY_FILE');
    const revision = digest(content);
    const statKey = `${SCANNER_CACHE_REVISION}:${before.dev}:${before.ino}:${before.size}:${before.mtimeMs}:${before.ctimeMs}`;
    return { content, statKey, revision, modifiedAt: before.mtime.toISOString() };
  } finally {
    await handle.close();
  }
}

async function readIgnoreFrame(rootPath: string, relativeDirectory: string, rootIdentity: RootIdentity, signal?: AbortSignal): Promise<IgnoreFrameRead> {
  const relativeFile = relativeDirectory ? `${relativeDirectory}/.gitignore` : '.gitignore';
  try {
    const value = await secureReadFile(path.join(rootPath, relativeFile), 256_000, signal, { rootPath, relativePath: relativeFile, rootIdentity });
    return { frame: { baseDir: relativeDirectory || '.', matcher: ignore().add(value.content), revision: value.revision } };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { frame: null };
    return { frame: null, errorCode: stableReadErrorCode(error) };
  }
}

interface Discovery {
  candidates: string[];
  candidateBytes: number;
  totalCandidateBytes: number;
  ignoreRevisions: string[];
  directoriesVisited: number;
  fsEntriesVisited: number;
  ignoredPaths: number;
  truncated: boolean;
  warnings: string[];
  ignoreStates: Array<{ directory: string; revision: string | null }>;
  directoryStates: DirectoryState[];
}

interface DirectoryState extends RootIdentity {
  directory: string;
  mtimeMs: number;
  ctimeMs: number;
}

function directoryState(directory: string, info: Stats): DirectoryState {
  return { directory, dev: info.dev, ino: info.ino, mtimeMs: info.mtimeMs, ctimeMs: info.ctimeMs };
}

function sameDirectoryState(left: DirectoryState, right: Stats): boolean {
  return left.dev === right.dev && left.ino === right.ino
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

async function validateCandidateAncestors(
  rootPath: string,
  relativePath: string,
  rootIdentity: RootIdentity,
  directoryStates: ReadonlyMap<string, DirectoryState>,
  signal?: AbortSignal,
): Promise<void> {
  const rootExpected = directoryStates.get('');
  if (!rootExpected) throw new Error('DIRECTORY_CHANGED');
  const rootCurrent = await assertSafePath(rootPath, '', rootIdentity, 'directory', signal);
  if (!sameDirectoryState(rootExpected, rootCurrent)) throw new Error('DIRECTORY_CHANGED');
  let currentDirectory = '';
  const parent = toPosix(path.posix.dirname(relativePath));
  for (const segment of parent.split('/').filter((value) => value && value !== '.')) {
    currentDirectory = currentDirectory ? `${currentDirectory}/${segment}` : segment;
    const expected = directoryStates.get(currentDirectory);
    if (!expected) throw new Error('DIRECTORY_CHANGED');
    const current = await assertSafePath(rootPath, currentDirectory, rootIdentity, 'directory', signal);
    if (!sameDirectoryState(expected, current)) throw new Error('DIRECTORY_CHANGED');
  }
}

async function discoverCandidates(rootPath: string, rootIdentity: RootIdentity, options: ScanOptions): Promise<Discovery> {
  // ScanOptions is also a test seam, not a way to widen the product's hard
  // safety envelope. Callers may lower a limit but cannot raise it.
  const maxFiles = Math.max(1, Math.min(options.maxFiles ?? SCAN_RULES.maxFiles, SCAN_RULES.maxFiles));
  const maxDirectories = Math.max(1, Math.min(options.maxDirectories ?? SCAN_RULES.maxDirectories, SCAN_RULES.maxDirectories));
  const maxFsEntries = Math.max(1, Math.min(options.maxFsEntries ?? SCAN_RULES.maxFsEntries, SCAN_RULES.maxFsEntries));
  const maxTotalBytes = Math.max(1, Math.min(options.maxTotalBytes ?? SCAN_RULES.maxTotalBytes, SCAN_RULES.maxTotalBytes));
  const candidates: string[] = [];
  const ignoreRevisions: string[] = [];
  const warnings: string[] = [];
  const ignoreStates: Array<{ directory: string; revision: string | null }> = [];
  const directoryStates = new Map<string, DirectoryState>();
  let directoriesVisited = 0;
  let fsEntriesVisited = 0;
  let ignoredPaths = 0;
  let truncated = false;
  let candidateBytes = 0;
  let totalCandidateBytes = 0;
  let stopped = false;
  let membershipUnstable = false;

  function stop(): void {
    stopped = true;
    truncated = true;
  }

  async function walk(relativeDirectory: string, inheritedFrames: IgnoreFrame[]): Promise<void> {
    abortIfNeeded(options.signal);
    if (stopped) return;
    if (directoriesVisited >= maxDirectories || candidates.length >= maxFiles) { stop(); return; }
    directoriesVisited += 1;
    let membershipBefore: Stats;
    try {
      membershipBefore = await assertSafePath(rootPath, relativeDirectory, rootIdentity, 'directory', options.signal);
      directoryStates.set(relativeDirectory, directoryState(relativeDirectory, membershipBefore));
    } catch (error) {
      warnings.push(`无法安全进入目录：${relativeDirectory || '.'}（${stableReadErrorCode(error)}）；结果已标记为不完整。`);
      stop();
      return;
    }
    const ignoreRead = await readIgnoreFrame(rootPath, relativeDirectory, rootIdentity, options.signal);
    if (ignoreRead.errorCode) {
      warnings.push(`无法安全读取忽略规则：${relativeDirectory ? `${relativeDirectory}/.gitignore` : '.gitignore'}（${ignoreRead.errorCode}）；结果已标记为不完整。`);
      stop();
      return;
    }
    const frame = ignoreRead.frame;
    ignoreStates.push({ directory: relativeDirectory, revision: frame?.revision ?? null });
    const frames = frame ? [...inheritedFrames, frame] : inheritedFrames;
    if (frame) ignoreRevisions.push(`${relativeDirectory}:${frame.revision}`);
    // `readdir()` materializes the whole directory before any product limit can
    // run. Stream entries and retain only the globally bounded prefix, then sort
    // that bounded set for deterministic complete scans.
    const children: Dirent[] = [];
    try {
      const directoryBefore = await assertSafePath(rootPath, relativeDirectory, rootIdentity, 'directory', options.signal);
      const directory = await opendir(path.join(rootPath, relativeDirectory));
      for await (const child of directory) {
        abortIfNeeded(options.signal);
        if (fsEntriesVisited >= maxFsEntries) { stop(); break; }
        fsEntriesVisited += 1;
        children.push(child);
      }
      const directoryAfter = await assertSafePath(rootPath, relativeDirectory, rootIdentity, 'directory', options.signal);
      if (directoryAfter.dev !== directoryBefore.dev || directoryAfter.ino !== directoryBefore.ino
        || directoryAfter.mtimeMs !== directoryBefore.mtimeMs || directoryAfter.ctimeMs !== directoryBefore.ctimeMs) {
        throw new Error('DIRECTORY_CHANGED');
      }
    } catch (error) {
      warnings.push(`无法读取目录：${relativeDirectory || '.'}（${stableReadErrorCode(error)}）；结果已标记为不完整。`);
      stop();
      return;
    }
    children.sort((a, b) => a.name.localeCompare(b.name));
    for (const child of children) {
      abortIfNeeded(options.signal);
      if (stopped) break;
      if (child.name === '.gitignore') continue;
      const relative = toPosix(path.posix.join(relativeDirectory, child.name));
      if (child.isSymbolicLink()) { ignoredPaths += 1; continue; }
      if (child.isDirectory()) {
        if (hardExcludedDirectories.has(child.name.toLowerCase()) || ignoredByFrames(relative, true, frames)) { ignoredPaths += 1; continue; }
        if (directoriesVisited >= maxDirectories) { stop(); break; }
        await walk(relative, frames);
      } else if (child.isFile()) {
        if (isSecretFile(child.name) || ignoredByFrames(relative, false, frames)) { ignoredPaths += 1; continue; }
        if (isCandidate(relative)) {
          if (candidates.length >= maxFiles) { stop(); break; }
          try {
            const info = await assertSafePath(rootPath, relative, rootIdentity, 'file', options.signal);
            totalCandidateBytes += info.size;
            if (candidateBytes + info.size > maxTotalBytes) { stop(); break; }
            candidateBytes += info.size;
          } catch (error) {
            warnings.push(`无法读取候选文件状态：${relative}（${stableReadErrorCode(error)}）；结果已标记为不完整。`);
            stop();
            break;
          }
          candidates.push(relative);
        }
      }
    }
    try {
      const membershipAfter = await assertSafePath(rootPath, relativeDirectory, rootIdentity, 'directory', options.signal);
      if (membershipAfter.dev !== membershipBefore.dev || membershipAfter.ino !== membershipBefore.ino
        || membershipAfter.mtimeMs !== membershipBefore.mtimeMs || membershipAfter.ctimeMs !== membershipBefore.ctimeMs) {
        throw new Error('DIRECTORY_CHANGED');
      }
    } catch (error) {
      warnings.push(`扫描期间目录成员发生变化：${relativeDirectory || '.'}（${stableReadErrorCode(error)}）；结果已标记为不完整。`);
      membershipUnstable = true;
      stop();
      return;
    }
    emitProgress(options, { phase: 'discover', processed: directoriesVisited, total: null, percent: 5, message: `已遍历 ${directoriesVisited} 个目录，发现 ${candidates.length} 个候选文件` });
  }

  await walk('', []);
  if (membershipUnstable) {
    // Discovery membership changed or hit a security boundary. Do not parse or
    // return plaintext from a candidate set that is already known incomplete.
    candidates.splice(0);
    candidateBytes = 0;
  }
  // Ignore membership is security-sensitive. Revalidate both existing and
  // initially absent ignore files even when another limit already made the
  // scan partial, so partial responses cannot expose newly excluded plaintext.
  for (const state of ignoreStates) {
    const current = await readIgnoreFrame(rootPath, state.directory, rootIdentity, options.signal);
    if (current.errorCode || (current.frame?.revision ?? null) !== state.revision) {
      warnings.push(`扫描期间忽略规则发生变化：${state.directory ? `${state.directory}/.gitignore` : '.gitignore'}（${current.errorCode ?? 'IGNORE_CHANGED'}）；结果已标记为不完整。`);
      candidates.splice(0);
      candidateBytes = 0;
      membershipUnstable = true;
      stop();
      break;
    }
  }
  if (truncated) warnings.push(`扫描达到安全上限：最多 ${maxFiles} 个候选文件、${maxDirectories} 个目录、${maxFsEntries} 个文件系统条目、${maxTotalBytes} 字节候选正文；结果已明确标记为不完整。`);
  return { candidates, candidateBytes, totalCandidateBytes, ignoreRevisions, directoriesVisited, fsEntriesVisited, ignoredPaths, truncated, warnings, ignoreStates, directoryStates: [...directoryStates.values()] };
}

async function validateSnapshotSource(
  rootPath: string,
  rootIdentity: RootIdentity,
  discovery: Pick<Discovery, 'directoryStates' | 'ignoreStates'>,
  index: ScanIndex,
  signal?: AbortSignal,
): Promise<void> {
  const expectedDirectories = new Map(discovery.directoryStates.map((state) => [state.directory, state]));
  for (const expected of discovery.directoryStates) {
    const current = await assertSafePath(rootPath, expected.directory, rootIdentity, 'directory', signal);
    if (!sameDirectoryState(expected, current)) throw new Error('DIRECTORY_CHANGED');
  }
  for (const state of discovery.ignoreStates) {
    const current = await readIgnoreFrame(rootPath, state.directory, rootIdentity, signal);
    if (current.errorCode || (current.frame?.revision ?? null) !== state.revision) throw new Error(current.errorCode ?? 'IGNORE_CHANGED');
  }
  for (const [relativePath, file] of Object.entries(index.files)) {
    const info = await assertSafePath(rootPath, relativePath, rootIdentity, 'file', signal);
    let currentDirectory = '';
    for (const segment of toPosix(path.posix.dirname(relativePath)).split('/').filter((value) => value && value !== '.')) {
      currentDirectory = currentDirectory ? `${currentDirectory}/${segment}` : segment;
      const expected = expectedDirectories.get(currentDirectory);
      if (!expected) throw new Error('DIRECTORY_CHANGED');
      const current = await assertSafePath(rootPath, currentDirectory, rootIdentity, 'directory', signal);
      if (!sameDirectoryState(expected, current)) throw new Error('DIRECTORY_CHANGED');
    }
    const statKey = `${SCANNER_CACHE_REVISION}:${info.dev}:${info.ino}:${info.size}:${info.mtimeMs}:${info.ctimeMs}`;
    if (statKey !== file.statKey) throw new Error('SOURCE_CHANGED');
  }
}

interface ParsedFile { relativePath: string; index: FileIndexEntry | null; entries: ContextEntry[]; warning?: string; cacheHit: boolean; contentBytes: number; truncated: boolean }

function stableReadErrorCode(error: unknown): string {
  const nodeCode = (error as NodeJS.ErrnoException | undefined)?.code;
  if (typeof nodeCode === 'string' && /^[A-Z0-9_]{2,40}$/.test(nodeCode)) return nodeCode;
  if (error instanceof Error && [
    'NOT_REGULAR_FILE', 'NOT_DIRECTORY', 'FILE_TOO_LARGE', 'BINARY_FILE', 'UNSTABLE_FILE',
    'PATH_OUTSIDE_ROOT', 'PATH_CHANGED', 'ROOT_CHANGED', 'SYMLINK_PATH',
    'DIRECTORY_CHANGED', 'IGNORE_CHANGED', 'SOURCE_CHANGED',
  ].includes(error.message)) return error.message;
  return 'READ_ERROR';
}

async function parseCandidate(
  rootPath: string,
  relativePath: string,
  previous: FileIndexEntry | undefined,
  rootIdentity: RootIdentity,
  directoryStates: ReadonlyMap<string, DirectoryState>,
  maxFileBytes: number,
  maxEntriesPerFile: number,
  options: ScanOptions,
): Promise<ParsedFile> {
  const absolutePath = path.join(rootPath, relativePath);
  try {
    await validateCandidateAncestors(rootPath, relativePath, rootIdentity, directoryStates, options.signal);
    // Cheap stat lets a warm scan avoid reading unchanged content. secureReadFile revalidates on misses.
    const info = await assertSafePath(rootPath, relativePath, rootIdentity, 'file', options.signal);
    const statKey = `${SCANNER_CACHE_REVISION}:${info.dev}:${info.ino}:${info.size}:${info.mtimeMs}:${info.ctimeMs}`;
    if (previous?.statKey === statKey) {
      const truncated = previous.entries.length > maxEntriesPerFile;
      const entries = previous.entries.slice(0, maxEntriesPerFile).map((entry) => ({ ...entry, riskIds: [] }));
      const confirmed = await assertSafePath(rootPath, relativePath, rootIdentity, 'file', options.signal);
      if (confirmed.dev !== info.dev || confirmed.ino !== info.ino
        || confirmed.size !== info.size || confirmed.mtimeMs !== info.mtimeMs || confirmed.ctimeMs !== info.ctimeMs) throw new Error('PATH_CHANGED');
      await validateCandidateAncestors(rootPath, relativePath, rootIdentity, directoryStates, options.signal);
      return {
        relativePath,
        index: { ...previous, entries },
        entries,
        cacheHit: true,
        // This is the indexed plaintext footprint, not only physical I/O for this refresh.
        contentBytes: entries.reduce((sum, entry) => sum + Buffer.byteLength(entry.content, 'utf8'), 0),
        truncated,
        ...(truncated ? { warning: `文件 ${relativePath} 超过每文件 ${maxEntriesPerFile} 个结构化条目上限；结果已标记为不完整。` } : {}),
      };
    }
    const value = await secureReadFile(absolutePath, maxFileBytes, options.signal, { rootPath, relativePath, rootIdentity });
    await validateCandidateAncestors(rootPath, relativePath, rootIdentity, directoryStates, options.signal);
    const category = categoryFor(relativePath);
    const findings = findSecrets(value.content, maxEntriesPerFile + 1);
    const sectionResult = category === 'tool'
      ? { sections: safeMcpMetadata(value.content), truncated: false }
      : sectionsFromMarkdown(value.content, path.basename(relativePath), maxEntriesPerFile);
    const entries: ContextEntry[] = [];
    let truncated = findings.length > maxEntriesPerFile || sectionResult.truncated;
    for (const finding of findings.slice(0, maxEntriesPerFile)) {
      const logicalKey = `secret-${digest(`${relativePath}:${finding.line}:${finding.label}`).slice(0, 16)}`;
      const content = `在 ${relativePath} 第 ${finding.line} 行检测到疑似${finding.label}。原值已脱敏，且不会进入导出正文。`;
      entries.push(makeEntry({
        id: `${logicalKey}-${digest(content).slice(0, 8)}`, logicalKey, title: `已隐藏疑似${finding.label}`, category: 'knowledge', packageType: 'secret-warning', scope: 'project', content,
        summary: `疑似${finding.label}已脱敏`,
        source: { relativePath, uri: pathToFileURL(absolutePath).href, locator: `第 ${finding.line} 行`, startLine: finding.line, endLine: finding.line, revision: value.revision, modifiedAt: value.modifiedAt },
        sensitivity: 'secret', tags: ['secret-warning', category], riskIds: [],
      }));
    }
    for (const section of sectionResult.sections) {
      if (findings.some((finding) => finding.line >= section.startLine && finding.line <= section.endLine)) continue;
      const content = section.content.trim();
      if (!content) continue;
      if (entries.length >= maxEntriesPerFile) { truncated = true; break; }
      const logicalKey = `item-${digest(`${relativePath}:${category}:${section.title.toLowerCase().trim()}:${section.occurrence}`).slice(0, 16)}`;
      const packageType = category === 'rule' ? 'instruction' : category === 'skill' ? 'workflow' : 'reference';
      entries.push(makeEntry({
        id: `${logicalKey}-${digest(content).slice(0, 8)}`, logicalKey, title: section.title, category, packageType, scope: scopeFor(category), content, summary: summaryFor(content),
        source: { relativePath, uri: pathToFileURL(absolutePath).href, locator: `第 ${section.startLine}–${section.endLine} 行`, startLine: section.startLine, endLine: section.endLine, revision: value.revision, modifiedAt: value.modifiedAt },
        sensitivity: 'internal', tags: [category], riskIds: [],
      }));
    }
    const index = { statKey: value.statKey, revision: value.revision, entries };
    return {
      relativePath,
      index,
      entries,
      cacheHit: false,
      contentBytes: Buffer.byteLength(value.content, 'utf8'),
      truncated,
      ...(truncated ? { warning: `文件 ${relativePath} 超过每文件 ${maxEntriesPerFile} 个结构化条目上限；结果已标记为不完整。` } : {}),
    };
  } catch (error) {
    const code = stableReadErrorCode(error);
    // A discovered candidate that cannot be read stably makes membership
    // incomplete. Never turn a transient EACCES/churn/symlink race—or a newly
    // policy-ineligible former candidate—into a persisted deletion.
    return { relativePath, index: null, entries: [], warning: `候选文件未能安全、稳定读取：${relativePath}（${code}）；结果已标记为不完整。`, cacheHit: false, contentBytes: 0, truncated: true };
  }
}

export async function scanProjectWithIndex(inputPath: string, options: ScanOptions = {}): Promise<ScanExecution> {
  const startedAt = performance.now();
  if (!inputPath || !path.isAbsolute(inputPath)) throw new Error('请输入本地项目的绝对路径。');
  const rootPath = await realpath(inputPath);
  const rootInfo = await stat(rootPath);
  if (!rootInfo.isDirectory()) throw new Error('所选路径不是目录。');
  abortIfNeeded(options.signal);
  emitProgress(options, { phase: 'discover', processed: 0, total: null, percent: 0, message: '正在应用安全策略与嵌套 .gitignore…' });
  // Discovery is always reconciled against the filesystem. Incremental mode only
  // reuses sanitized parse results after a fresh membership/stat check, so new and
  // deleted files cannot be missed when directory timestamps or watcher events lie.
  const rootIdentity = { dev: rootInfo.dev, ino: rootInfo.ino };
  const discovery = await discoverCandidates(rootPath, rootIdentity, options);
  const directoryStates = new Map(discovery.directoryStates.map((state) => [state.directory, state]));
  const quickRootRevision = digest(`${rootPath}:${rootInfo.dev}:${rootInfo.ino}:${SCANNER_CACHE_REVISION}:${discovery.ignoreRevisions.sort().join('|')}`);
  const concurrency = Math.max(1, Math.min(options.concurrency ?? SCAN_RULES.concurrency, 32));
  const maxFileBytes = Math.max(1, Math.min(options.maxFileBytes ?? SCAN_RULES.maxFileBytes, SCAN_RULES.maxFileBytes));
  const maxFiles = Math.max(1, Math.min(options.maxFiles ?? SCAN_RULES.maxFiles, SCAN_RULES.maxFiles));
  const maxDirectories = Math.max(1, Math.min(options.maxDirectories ?? SCAN_RULES.maxDirectories, SCAN_RULES.maxDirectories));
  const maxFsEntries = Math.max(1, Math.min(options.maxFsEntries ?? SCAN_RULES.maxFsEntries, SCAN_RULES.maxFsEntries));
  const maxEntriesPerFile = Math.max(1, Math.min(options.maxEntriesPerFile ?? SCAN_RULES.maxEntriesPerFile, SCAN_RULES.maxEntriesPerFile));
  const maxEntries = Math.max(1, Math.min(options.maxEntries ?? SCAN_RULES.maxEntries, SCAN_RULES.maxEntries));
  const maxRisks = Math.max(1, Math.min(options.maxRisks ?? SCAN_RULES.maxRisks, SCAN_RULES.maxRisks));
  const maxClaims = Math.max(1, Math.min(options.maxClaims ?? SCAN_RULES.maxClaims, SCAN_RULES.maxClaims));
  const maxTotalBytes = Math.max(1, Math.min(options.maxTotalBytes ?? SCAN_RULES.maxTotalBytes, SCAN_RULES.maxTotalBytes));
  let processed = 0;
  let acceptedEntryCount = 0;
  let acceptedContentBytes = 0;
  let observedContentBytes = 0;
  let filesRead = 0;
  let cacheHits = 0;
  let entryLimitExceeded = false;
  let contentByteLimitExceeded = false;
  const parsed: ParsedFile[] = [];
  // Parse in deterministic path-ordered batches. This preserves bounded
  // concurrency without allowing 5,000 files × 1,000 sections to accumulate
  // before the global structured-entry limit is checked.
  for (
    let offset = 0;
    offset < discovery.candidates.length && !entryLimitExceeded && !contentByteLimitExceeded;
    offset += concurrency
  ) {
    abortIfNeeded(options.signal);
    const paths = discovery.candidates.slice(offset, offset + concurrency);
    const batch = await Promise.all(paths.map((relativePath) => parseCandidate(
      rootPath,
      relativePath,
      options.previousIndex?.files[relativePath],
      rootIdentity,
      directoryStates,
      maxFileBytes,
      maxEntriesPerFile,
      options,
    )));
    // A candidate can grow after discovery. Account at the batch boundary so
    // the next batch is never scheduled once the real indexed footprint hits
    // the cap. Peak temporary content is bounded by concurrency × maxFileBytes.
    observedContentBytes += batch.reduce((sum, file) => sum + file.contentBytes, 0);
    filesRead += batch.filter((file) => !file.cacheHit).length;
    cacheHits += batch.filter((file) => file.cacheHit).length;
    for (let index = 0; index < batch.length; index += 1) {
      const file = batch[index];
      processed += 1;
      if (acceptedContentBytes + file.contentBytes > maxTotalBytes) {
        contentByteLimitExceeded = true;
        break;
      }
      acceptedContentBytes += file.contentBytes;
      const remaining = maxEntries - acceptedEntryCount;
      if (file.entries.length > remaining) {
        const entries = file.entries.slice(0, Math.max(0, remaining));
        parsed.push({
          ...file,
          entries,
          index: file.index ? { ...file.index, entries } : null,
          truncated: true,
          warning: `扫描超过全局 ${maxEntries} 个结构化条目上限；结果已标记为不完整。`,
        });
        acceptedEntryCount += entries.length;
        entryLimitExceeded = true;
      } else {
        parsed.push(file);
        acceptedEntryCount += file.entries.length;
        if (file.truncated) entryLimitExceeded = true;
        if (
          acceptedEntryCount >= maxEntries
          && (index + 1 < batch.length || offset + batch.length < discovery.candidates.length)
        ) entryLimitExceeded = true;
      }
      emitProgress(options, { phase: 'read', processed, total: discovery.candidates.length, percent: discovery.candidates.length ? 5 + Math.round(processed / discovery.candidates.length * 65) : 70, message: `已处理 ${processed}/${discovery.candidates.length} 个候选文件` });
      if (entryLimitExceeded) break;
    }
  }
  abortIfNeeded(options.signal);
  const effectiveSnapshotBytes = Math.max(observedContentBytes, discovery.totalCandidateBytes);
  const totalBytesExceeded = contentByteLimitExceeded || effectiveSnapshotBytes > maxTotalBytes;
  const warnings = [
    ...discovery.warnings,
    ...parsed.flatMap((file) => file.warning ? [file.warning] : []),
    ...(entryLimitExceeded && !parsed.some((file) => file.warning?.includes('结构化条目上限'))
      ? [`扫描达到全局 ${maxEntries} 个结构化条目上限；结果已标记为不完整且不会覆盖旧快照。`] : []),
    ...(totalBytesExceeded
      ? [`扫描最终正文合计至少 ${effectiveSnapshotBytes} 字节，超过 ${maxTotalBytes} 字节快照安全上限；结果已标记为不完整且不会覆盖旧快照。`] : []),
  ];
  let entries = parsed.flatMap((file) => file.entries).sort((a, b) => `${a.source.relativePath}:${a.source.startLine}:${a.logicalKey}`.localeCompare(`${b.source.relativePath}:${b.source.startLine}:${b.logicalKey}`));
  const index: ScanIndex = {
    version: 1,
    rootRevision: quickRootRevision,
    files: Object.fromEntries(parsed.filter((file): file is ParsedFile & { index: FileIndexEntry } => file.index !== null).map((file) => [file.relativePath, file.index])),
  };
  let sourceChanged = false;
  try {
    await validateSnapshotSource(rootPath, rootIdentity, discovery, index, options.signal);
  } catch (error) {
    const code = stableReadErrorCode(error);
    warnings.push(`扫描来源在分析前发生变化（${code}）；候选正文已丢弃，结果不会覆盖旧快照。`);
    sourceChanged = true;
    entries = [];
    index.files = {};
  }
  const analyzer: Analyzer = options.analyzer ?? new AnalyzerPipeline(new LocalSemanticAnalyzer(maxRisks, maxClaims));
  emitProgress(options, { phase: 'analyze', processed: 0, total: entries.length, percent: 75, message: '正在运行本地语义与引用分析…' });
  // Progress callbacks are intentionally observable to callers and can race
  // with the filesystem. Revalidate again after emitting and before any
  // reference analyzer is allowed to touch a path.
  if (!sourceChanged) {
    try {
      await validateSnapshotSource(rootPath, rootIdentity, discovery, index, options.signal);
    } catch (error) {
      const code = stableReadErrorCode(error);
      warnings.push(`扫描来源在分析前发生变化（${code}）；候选正文已丢弃，结果不会覆盖旧快照。`);
      sourceChanged = true;
      entries = [];
      index.files = {};
    }
  }
  const analysis = await analyzer.analyze(entries, rootPath, options.signal);
  warnings.push(...analysis.warnings);
  const secretRisks: ContextRisk[] = entries.filter((entry) => entry.packageType === 'secret-warning').map((entry) => ({
    id: `risk-${entry.logicalKey}`, kind: 'secret', severity: 'danger', title: '检测到疑似秘密信息', description: '原值已在服务端丢弃，条目只能作为脱敏告警导出。', sides: [sideFor(entry, '[已脱敏]')], analyzerId: 'secret-detector',
  }));
  const combinedRisks = [...secretRisks, ...analysis.risks].sort((a, b) => a.id.localeCompare(b.id));
  const riskLimitExceeded = analysis.truncated === true || combinedRisks.length > maxRisks;
  const risks = combinedRisks.slice(0, maxRisks);
  if (riskLimitExceeded) warnings.push(`分析达到 ${maxRisks} 个风险/引用上限；结果已标记为不完整且不会覆盖旧快照。`);
  const entryById = new Map(entries.map((entry) => [entry.id, entry]));
  for (const risk of risks) for (const side of risk.sides) entryById.get(side.itemId)?.riskIds.push(risk.id);
  const tokenCount = entries.reduce((sum, entry) => sum + entry.tokenCount, 0);
  const durationMs = Math.round(performance.now() - startedAt);
  const healthScore = Math.max(0, 100 - risks.reduce((score, risk) => score + (risk.severity === 'danger' ? 10 : 5), 0));
  const result: ScanResult = {
    rootPath, projectName: path.basename(rootPath), sourceKind: 'local-project', scannedAt: new Date().toISOString(), entries, risks, warnings,
    analyzers: [analysis.descriptor, { id: 'secret-detector', version: '2.0.0', mode: 'local', privacy: '原值不进入条目、快照或导出正文。', status: 'ok' }],
    stats: {
      filesScanned: Object.keys(index.files).length,
      entries: entries.length, risks: risks.length, tokenCount, tokenEstimate: tokenCount, tokenEncoding: TOKEN_ENCODING, healthScore,
      performance: { directoriesVisited: discovery.directoriesVisited, fsEntriesVisited: discovery.fsEntriesVisited, candidatesDiscovered: discovery.candidates.length, filesRead, cacheHits, cacheMisses: filesRead, ignoredPaths: discovery.ignoredPaths, totalBytesRead: effectiveSnapshotBytes, durationMs, truncated: discovery.truncated || totalBytesExceeded || entryLimitExceeded || riskLimitExceeded || sourceChanged || parsed.some((file) => file.truncated) },
    },
    rules: { ...SCAN_RULES, maxFileBytes, maxFiles, maxDirectories, maxFsEntries, maxEntriesPerFile, maxEntries, maxRisks, maxClaims, maxTotalBytes, concurrency },
  };
  try {
    await validateSnapshotSource(rootPath, rootIdentity, discovery, index, options.signal);
  } catch (error) {
    const code = stableReadErrorCode(error);
    result.warnings.push(`扫描来源在完成前发生变化（${code}）；结果已标记为不完整且不会覆盖旧快照。`);
    result.entries = [];
    result.risks = [];
    result.stats.filesScanned = 0;
    result.stats.entries = 0;
    result.stats.risks = 0;
    result.stats.tokenCount = 0;
    result.stats.tokenEstimate = 0;
    result.stats.healthScore = 100;
    result.stats.performance.truncated = true;
    index.files = {};
    sourceChanged = true;
  }
  emitProgress(options, { phase: 'done', processed: result.entries.length, total: result.entries.length, percent: 100, message: `${result.stats.performance.truncated ? '扫描达到安全上限' : '扫描完成'}：${result.entries.length} 个条目，缓存命中 ${cacheHits} 个文件` });
  return {
    result,
    index,
    verifySource: async () => validateSnapshotSource(rootPath, rootIdentity, discovery, index, options.signal),
  };
}

export async function scanProject(inputPath: string, analyzerOrOptions?: Analyzer | ScanOptions): Promise<ScanResult> {
  const options: ScanOptions = analyzerOrOptions && 'analyze' in analyzerOrOptions ? { analyzer: analyzerOrOptions } : analyzerOrOptions ?? {};
  return (await scanProjectWithIndex(inputPath, options)).result;
}

/** Compatibility alias for previous imports. */
export class LocalRuleAnalyzer extends LocalSemanticAnalyzer {}

export { AnalyzerPipeline, LocalSemanticAnalyzer } from './analyzers.js';
export type { Analyzer } from './types.js';
