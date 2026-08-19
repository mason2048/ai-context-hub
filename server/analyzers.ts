import { createHash } from 'node:crypto';
import { lstat } from 'node:fs/promises';
import path from 'node:path';
import { containsSecret } from './security.js';
import type {
  AnalysisResult,
  Analyzer,
  AnalyzerDescriptor,
  ContextEntry,
  ContextRisk,
  RiskSide,
} from './types.js';

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function normalized(value: string): string {
  return value.toLowerCase().replace(/[“”"'`]/g, '').replace(/\s+/g, ' ').trim();
}

function sideFor(entry: ContextEntry, excerpt = entry.summary): RiskSide {
  return {
    itemId: entry.id,
    title: entry.title,
    source: entry.source.relativePath,
    locator: entry.source.locator,
    excerpt,
  };
}

interface Claim {
  subject: string;
  value: string;
  entry: ContextEntry;
  excerpt: string;
  polarity: 'require' | 'forbid';
  qualifier: string;
}

const commandPatterns: Array<{ subject: string; pattern: RegExp }> = [
  { subject: 'test-command', pattern: /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?test(?:\s+[^\n`。；;]*)?/gi },
  { subject: 'build-command', pattern: /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?build(?:\s+[^\n`。；;]*)?/gi },
  { subject: 'lint-command', pattern: /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?lint(?:\s+[^\n`。；;]*)?/gi },
  { subject: 'dev-command', pattern: /\b(?:npm|pnpm|yarn|bun)\s+(?:run\s+)?dev(?:\s+[^\n`。；;]*)?/gi },
];

function normalizeCommand(value: string): string {
  return normalized(value).replace(/^(npm|pnpm|yarn|bun) run /, '$1 ').replace(/\s+/g, ' ');
}

function claimQualifier(entry: ContextEntry): string {
  const content = normalized(entry.content);
  const environment = /(?:production|prod|生产环境)/.test(content)
    ? 'prod'
    : /(?:development|dev|开发环境)/.test(content)
      ? 'dev'
      : /(?:test environment|测试环境)/.test(content)
        ? 'test'
        : 'any';
  const workspace = content.match(/(?:workspace|工作区)\s*[:：=]?\s*[`"']?([\w./-]{1,80})/i)?.[1]?.toLowerCase() ?? 'any';
  return `${environment}:${workspace}:${entry.scope}`;
}

function commandPolarity(content: string, matchIndex: number): Claim['polarity'] {
  const prefix = content.slice(Math.max(0, matchIndex - 28), matchIndex);
  return /(?:禁止|不得|不要|do not|must not|never)\s*[^\n。；;]*$/i.test(prefix) ? 'forbid' : 'require';
}

function isExampleContext(content: string): boolean {
  return /(?:示例|例如|比如|历史|曾经|example|for example|previously)/i.test(content);
}

function extractClaims(entry: ContextEntry, maxClaims: number): { claims: Claim[]; truncated: boolean } {
  if (entry.packageType === 'secret-warning' || isExampleContext(entry.content)) return { claims: [], truncated: false };
  const claims: Claim[] = [];
  const qualifier = claimQualifier(entry);
  const add = (claim: Claim): boolean => {
    if (claims.length >= maxClaims) return false;
    claims.push(claim);
    return true;
  };
  for (const { subject, pattern } of commandPatterns) {
    pattern.lastIndex = 0;
    const seen = new Set<string>();
    for (const match of entry.content.matchAll(pattern)) {
      const value = normalizeCommand(match[0]);
      const polarity = commandPolarity(entry.content, match.index ?? 0);
      const key = `${value}:${polarity}`;
      if (seen.has(key)) continue;
      seen.add(key);
      if (!add({ subject, value, entry, excerpt: value, polarity, qualifier })) return { claims, truncated: true };
    }
  }

  const packageManager = entry.content.match(/(?:必须(?:使用)?|统一(?:使用)?|只能(?:使用)?|应当(?:使用)?|使用|use|must use|only use)\s*[:：]?\s*\b(npm|pnpm|yarn|bun)\b/i);
  if (packageManager) {
    const polarity = commandPolarity(entry.content, packageManager.index ?? 0);
    if (!add({ subject: 'package-manager', value: packageManager[1].toLowerCase(), entry, excerpt: packageManager[0], polarity, qualifier })) return { claims, truncated: true };
  }

  const port = entry.content.match(/(?:默认)?(?:端口|port)\s*(?:为|是|[:：=])?\s*(\d{2,5})\b/i);
  if (port && !add({ subject: 'port', value: port[1], entry, excerpt: port[0], polarity: 'require', qualifier })) return { claims, truncated: true };

  const branch = entry.content.match(/(?:默认分支|default branch)\s*(?:为|是|[:：=])?\s*[`"']?([\w./-]+)/i);
  if (branch && !add({ subject: 'default-branch', value: branch[1].toLowerCase(), entry, excerpt: branch[0], polarity: 'require', qualifier })) return { claims, truncated: true };

  const formatter = entry.content.match(/(?:格式化工具|formatter)\s*(?:为|是|使用|[:：=])?\s*[`"']?(prettier|biome|eslint|black|ruff)/i);
  if (formatter && !add({ subject: 'formatter', value: formatter[1].toLowerCase(), entry, excerpt: formatter[0], polarity: 'require', qualifier })) return { claims, truncated: true };

  const nodeVersion = entry.content.match(/\b(?:node(?:\.js)?)(?:\s+version|\s*版本)?\s*(?:必须(?:为|是)?|requires?|require|使用|use|[:：=])?\s*((?:[~^]|[<>]=?)?\s*(?:\d+\.x|\d+(?:\.\d+){0,2}))(?![\w.])/i);
  if (nodeVersion && !add({ subject: 'node-version', value: nodeVersion[1].replace(/\s+/g, ''), entry, excerpt: nodeVersion[0], polarity: 'require', qualifier })) return { claims, truncated: true };

  const pythonVersion = entry.content.match(/\bpython(?:\s+version|\s*版本)?\s*(?:必须(?:为|是)?|requires?|require|使用|use|[:：=])?\s*((?:[~^]|[<>]=?)?\s*(?:\d+\.x|\d+(?:\.\d+){0,2}))(?![\w.])/i);
  if (pythonVersion && !add({ subject: 'python-version', value: pythonVersion[1].replace(/\s+/g, ''), entry, excerpt: pythonVersion[0], polarity: 'require', qualifier })) return { claims, truncated: true };

  for (const match of entry.content.matchAll(/(?:(?:禁止|不得|不要)\s*|(?:do not|must not|never)\s+)([^\n。；;]{2,80})/gi)) {
    const action = normalized(match[1]).replace(/^(?:to\s+|去)/, '').slice(0, 60);
    if (!add({ subject: `action:${action}`, value: action, entry, excerpt: match[0], polarity: 'forbid', qualifier })) return { claims, truncated: true };
  }
  for (const match of entry.content.matchAll(/(?:(?:必须|务必)\s*|(?:always|must)\s+)([^\n。；;]{2,80})/gi)) {
    const action = normalized(match[1]).replace(/^(?:to\s+|去)/, '').slice(0, 60);
    if (!add({ subject: `action:${action}`, value: action, entry, excerpt: match[0], polarity: 'require', qualifier })) return { claims, truncated: true };
  }
  return { claims, truncated: false };
}

interface VersionInterval { minimum: number; maximum: number; minimumOpen: boolean; maximumOpen: boolean }

function versionNumber(value: string): number {
  const [major = 0, minor = 0, patch = 0] = value.replace(/\.x$/i, '').split('.').map(Number);
  return major * 1_000_000 + minor * 1_000 + patch;
}

function versionInterval(value: string): VersionInterval | null {
  const match = value.match(/^([~^]|>=|>|<=|<)?(\d+(?:\.\d+){0,2}|\d+\.x)$/);
  if (!match) return null;
  const operator = match[1] ?? '';
  const number = versionNumber(match[2]);
  if (operator === '>=') return { minimum: number, maximum: Infinity, minimumOpen: false, maximumOpen: false };
  if (operator === '>') return { minimum: number, maximum: Infinity, minimumOpen: true, maximumOpen: false };
  if (operator === '<=') return { minimum: -Infinity, maximum: number, minimumOpen: false, maximumOpen: false };
  if (operator === '<') return { minimum: -Infinity, maximum: number, minimumOpen: false, maximumOpen: true };
  const major = Math.floor(number / 1_000_000);
  const nextMajor = (major + 1) * 1_000_000;
  if (operator === '^' || operator === '~' || /\.x$/i.test(match[2]) || !match[2].includes('.')) {
    return { minimum: number, maximum: nextMajor, minimumOpen: false, maximumOpen: true };
  }
  return { minimum: number, maximum: number, minimumOpen: false, maximumOpen: false };
}

function intervalsOverlap(left: VersionInterval, right: VersionInterval): boolean {
  const lower = Math.max(left.minimum, right.minimum);
  const upper = Math.min(left.maximum, right.maximum);
  if (lower < upper) return true;
  if (lower > upper) return false;
  const leftExcludes = (lower === left.minimum && left.minimumOpen) || (upper === left.maximum && left.maximumOpen);
  const rightExcludes = (lower === right.minimum && right.minimumOpen) || (upper === right.maximum && right.maximumOpen);
  return !leftExcludes && !rightExcludes;
}

function qualifiersOverlap(left: string, right: string): boolean {
  const [leftEnv, leftWorkspace, leftScope] = left.split(':');
  const [rightEnv, rightWorkspace, rightScope] = right.split(':');
  const environment = leftEnv === 'any' || rightEnv === 'any' || leftEnv === rightEnv;
  const workspace = leftWorkspace === 'any' || rightWorkspace === 'any' || leftWorkspace === rightWorkspace;
  const scope = leftScope === rightScope || leftScope === 'global' || rightScope === 'global';
  return environment && workspace && scope;
}

interface ClaimBucket {
  value: string;
  members: number[];
  interval: VersionInterval | null;
}

interface ClaimCell {
  required: Map<string, ClaimBucket>;
  forbidden: Map<string, ClaimBucket>;
}

function qualifierParts(qualifier: string): { environment: string; workspace: string; scope: string } {
  const [environment = 'any', workspace = 'any', scope = 'project'] = qualifier.split(':');
  return { environment, workspace, scope };
}

function cellsOverlap(left: string, right: string): boolean {
  const [leftEnvironment, leftScope] = left.split('\0');
  const [rightEnvironment, rightScope] = right.split('\0');
  return (leftEnvironment === 'any' || rightEnvironment === 'any' || leftEnvironment === rightEnvironment)
    && (leftScope === rightScope || leftScope === 'global' || rightScope === 'global');
}

/**
 * Builds conflict components from qualifier/value buckets. Environment and
 * scope have a small fixed cardinality; arbitrary workspaces are processed
 * independently and only compared with the wildcard workspace. This avoids
 * all-entry pairwise comparison while preserving multi-side risks.
 */
function conflictingClaimComponents(subject: string, claims: Claim[]): Claim[][] {
  const parent = claims.map((_, index) => index);
  const active = new Set<number>();
  const find = (value: number): number => {
    let current = value;
    while (parent[current] !== current) {
      parent[current] = parent[parent[current]];
      current = parent[current];
    }
    return current;
  };
  const union = (left: number, right: number): void => {
    const leftRoot = find(left);
    const rightRoot = find(right);
    if (leftRoot !== rightRoot) parent[rightRoot] = leftRoot;
  };
  const connect = (buckets: ClaimBucket[]): void => {
    const members = [...new Set(buckets.flatMap((bucket) => bucket.members))];
    if (new Set(members.map((index) => claims[index].entry.id)).size < 2) return;
    const first = members[0];
    for (const member of members) {
      active.add(member);
      union(first, member);
    }
  };
  const connectPair = (left: ClaimBucket, right: ClaimBucket): void => connect([left, right]);

  const workspaceCells = new Map<string, Map<string, ClaimCell>>();
  claims.forEach((claim, index) => {
    const qualifier = qualifierParts(claim.qualifier);
    const cells = workspaceCells.get(qualifier.workspace) ?? new Map<string, ClaimCell>();
    const cellKey = `${qualifier.environment}\0${qualifier.scope}`;
    const cell = cells.get(cellKey) ?? { required: new Map(), forbidden: new Map() };
    const polarityMap = claim.polarity === 'require' ? cell.required : cell.forbidden;
    const bucket = polarityMap.get(claim.value) ?? {
      value: claim.value,
      members: [],
      interval: subject.endsWith('-version') ? versionInterval(claim.value) : null,
    };
    bucket.members.push(index);
    polarityMap.set(claim.value, bucket);
    cells.set(cellKey, cell);
    workspaceCells.set(qualifier.workspace, cells);
  });

  const hasDifferentValue = (buckets: Map<string, ClaimBucket>, value: string): boolean => (
    buckets.size > (buckets.has(value) ? 1 : 0)
  );
  const disjoint = (left: ClaimBucket, right: ClaimBucket): boolean => {
    if (!left.interval || !right.interval) return left.value !== right.value;
    return !intervalsOverlap(left.interval, right.interval);
  };
  const versionParticipants = (source: Map<string, ClaimBucket>, target: Map<string, ClaimBucket>, same: boolean): ClaimBucket[] => {
    const candidates = [...target.values()].filter((bucket) => bucket.interval);
    if (candidates.length === 0) return [];
    const leftmostEnd = candidates.reduce((best, bucket) => (
      bucket.interval!.maximum < best.interval!.maximum ? bucket : best
    ));
    const rightmostStart = candidates.reduce((best, bucket) => (
      bucket.interval!.minimum > best.interval!.minimum ? bucket : best
    ));
    return [...source.values()].filter((bucket) => (
      (leftmostEnd !== bucket || !same) && disjoint(bucket, leftmostEnd)
    ) || (
      (rightmostStart !== bucket || !same) && disjoint(bucket, rightmostStart)
    ));
  };
  const processCellPair = (left: ClaimCell, right: ClaimCell, same: boolean): void => {
    if (subject.endsWith('-version')) {
      const participants = [
        ...versionParticipants(left.required, right.required, same),
        ...(same ? [] : versionParticipants(right.required, left.required, false)),
      ];
      if (participants.length > 1) connect(participants);
    } else if (same) {
      if (left.required.size > 1) connect([...left.required.values()]);
    } else {
      const participants = [
        ...[...left.required.values()].filter((bucket) => hasDifferentValue(right.required, bucket.value)),
        ...[...right.required.values()].filter((bucket) => hasDifferentValue(left.required, bucket.value)),
      ];
      if (participants.length > 1) connect(participants);
    }

    const connectOpposites = (required: Map<string, ClaimBucket>, forbidden: Map<string, ClaimBucket>): void => {
      const [smaller, larger] = required.size <= forbidden.size
        ? [required, forbidden]
        : [forbidden, required];
      for (const [value, bucket] of smaller) {
        const opposite = larger.get(value);
        if (opposite) connectPair(bucket, opposite);
      }
    };
    connectOpposites(left.required, right.forbidden);
    if (!same) connectOpposites(right.required, left.forbidden);
  };
  const processInternal = (cells: Map<string, ClaimCell>): void => {
    const values = [...cells.entries()].sort(([left], [right]) => left.localeCompare(right));
    for (let left = 0; left < values.length; left += 1) {
      for (let right = left; right < values.length; right += 1) {
        if (cellsOverlap(values[left][0], values[right][0])) {
          processCellPair(values[left][1], values[right][1], left === right);
        }
      }
    }
  };
  const processCross = (left: Map<string, ClaimCell>, right: Map<string, ClaimCell>): void => {
    for (const [leftKey, leftCell] of left) {
      for (const [rightKey, rightCell] of right) {
        if (cellsOverlap(leftKey, rightKey)) processCellPair(leftCell, rightCell, false);
      }
    }
  };

  const wildcard = workspaceCells.get('any');
  if (wildcard) processInternal(wildcard);
  for (const [workspace, cells] of workspaceCells) {
    if (workspace === 'any') continue;
    processInternal(cells);
    if (wildcard) processCross(cells, wildcard);
  }

  const components = new Map<number, Claim[]>();
  for (const index of active) {
    const root = find(index);
    const component = components.get(root) ?? [];
    component.push(claims[index]);
    components.set(root, component);
  }
  return [...components.values()].filter((component) => new Set(component.map((claim) => claim.entry.id)).size >= 2);
}

function relationRisks(entries: readonly ContextEntry[], maxClaims: number): { risks: ContextRisk[]; truncated: boolean } {
  const visible = entries.filter((entry) => entry.packageType !== 'secret-warning');
  const risks: ContextRisk[] = [];
  const duplicateGroups = new Map<string, ContextEntry[]>();
  for (const entry of visible) {
    const key = normalized(entry.content);
    if (key.length < 20) continue;
    const group = duplicateGroups.get(key) ?? [];
    group.push(entry);
    duplicateGroups.set(key, group);
  }
  for (const group of duplicateGroups.values()) {
    if (group.length < 2) continue;
    const ordered = [...group].sort((a, b) => a.logicalKey.localeCompare(b.logicalKey));
    risks.push({
      id: `duplicate-${digest(ordered.map((entry) => entry.logicalKey).join(':')).slice(0, 12)}`,
      kind: 'duplicate',
      severity: 'warning',
      title: '发现完全重复内容',
      description: '这些条目的规范化正文完全一致，建议只保留一个来源。',
      sides: ordered.map((entry) => sideFor(entry)),
      analyzerId: 'local-semantic',
    });
  }

  const bySubject = new Map<string, Claim[]>();
  let claimCount = 0;
  let truncated = false;
  for (const entry of visible) {
    const extracted = extractClaims(entry, maxClaims - claimCount);
    for (const claim of extracted.claims) {
      const group = bySubject.get(claim.subject) ?? [];
      group.push(claim);
      bySubject.set(claim.subject, group);
    }
    claimCount += extracted.claims.length;
    if (extracted.truncated || claimCount >= maxClaims) {
      truncated = true;
      break;
    }
  }
  for (const [subject, subjectClaims] of bySubject) {
    for (const component of conflictingClaimComponents(subject, subjectClaims)) {
      const values = new Set(component.filter((claim) => claim.polarity === 'require').map((claim) => claim.value));
      // One source can mention multiple alternatives; show it once and let the
      // user inspect the original text instead of manufacturing self-conflicts.
      const uniqueSides = new Map<string, RiskSide>();
      for (const claim of [...component].sort((left, right) => `${left.entry.logicalKey}:${left.value}:${left.polarity}`.localeCompare(`${right.entry.logicalKey}:${right.value}:${right.polarity}`))) {
        if (!uniqueSides.has(claim.entry.id)) uniqueSides.set(claim.entry.id, sideFor(claim.entry, `${claim.polarity === 'forbid' ? '禁止：' : ''}${claim.excerpt}`));
      }
      const orderedSides = [...uniqueSides.values()].sort((a, b) => `${a.source}:${a.locator}:${a.excerpt}`.localeCompare(`${b.source}:${b.locator}:${b.excerpt}`));
      if (orderedSides.length < 2) continue;
      const semantic = !subject.endsWith('-command');
      risks.push({
        id: `${semantic ? 'semantic' : 'conflict'}-${digest(`${subject}:${[...values].sort().join('|')}:${orderedSides.map((side) => side.itemId).join('|')}`).slice(0, 12)}`,
        kind: semantic ? 'semantic-conflict' : 'conflict',
        severity: semantic ? 'warning' : 'danger',
        title: semantic ? `检测到${subject}语义冲突` : `${subject.replace('-command', '')}命令存在硬冲突`,
        description: `同一上下文主题“${subject}”声明了互不兼容的要求，请在导出前确认。`,
        sides: orderedSides,
        analyzerId: 'local-semantic',
      });
    }
  }
  return { risks, truncated };
}

async function existsWithoutFollowingSymlinks(rootPath: string, target: string, signal?: AbortSignal): Promise<boolean> {
  const relative = path.relative(rootPath, target);
  if (!relative) return true;
  let current = rootPath;
  for (const segment of relative.split(path.sep)) {
    if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new DOMException('扫描已取消。', 'AbortError');
    current = path.join(current, segment);
    try {
      const info = await lstat(current);
      if (info.isSymbolicLink()) return false;
    } catch {
      return false;
    }
  }
  return true;
}

const MAX_LOCAL_RISKS = 5_000;
const MAX_LOCAL_CLAIMS = 20_000;

async function brokenReferenceRisks(
  entries: readonly ContextEntry[],
  rootPath: string,
  signal?: AbortSignal,
  maxRisks = MAX_LOCAL_RISKS,
): Promise<{ risks: ContextRisk[]; truncated: boolean }> {
  const candidates = new Map<string, Array<{ entry: ContextEntry; reference: string }>>();
  let totalReferences = 0;
  let truncated = false;
  for (const entry of entries) {
    for (const match of entry.content.matchAll(/\[[^\]]+\]\(([^)]+)\)/g)) {
      const raw = match[1].split('#')[0].trim();
      if (!raw || /^(?:https?:|mailto:|#)/i.test(raw)) continue;
      let reference: string;
      try { reference = decodeURIComponent(raw); } catch { reference = raw; }
      const target = path.resolve(path.dirname(path.join(rootPath, entry.source.relativePath)), reference);
      if (!target.startsWith(`${rootPath}${path.sep}`) && target !== rootPath) continue;
      if (totalReferences >= maxRisks || (!candidates.has(target) && candidates.size >= maxRisks)) {
        truncated = true;
        break;
      }
      const group = candidates.get(target) ?? [];
      group.push({ entry, reference });
      totalReferences += 1;
      candidates.set(target, group);
    }
    if (truncated) break;
  }
  const targets = [...candidates.keys()].sort();
  const missing = new Set<string>();
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(16, Math.max(1, targets.length)) }, async () => {
    while (cursor < targets.length) {
      const index = cursor;
      cursor += 1;
      const target = targets[index];
      if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new DOMException('扫描已取消。', 'AbortError');
      if (!await existsWithoutFollowingSymlinks(rootPath, target, signal)) missing.add(target);
    }
  }));
  const risks: ContextRisk[] = [];
  for (const target of targets) {
    if (!missing.has(target)) continue;
    for (const { entry, reference } of candidates.get(target) ?? []) {
      if (risks.length >= maxRisks) { truncated = true; break; }
      risks.push({
        id: `broken-${digest(`${entry.logicalKey}:${reference}`).slice(0, 12)}`,
        kind: 'broken-reference', severity: 'warning', title: '文件引用已失效',
        description: `引用目标不存在：${reference}`,
        sides: [sideFor(entry, reference)], analyzerId: 'local-semantic',
      });
    }
    if (truncated && risks.length >= maxRisks) break;
  }
  return { risks, truncated };
}

export class LocalSemanticAnalyzer implements Analyzer {
  readonly descriptor = {
    id: 'local-semantic', version: '2.0.0', mode: 'local' as const,
    privacy: '仅处理已脱敏条目；不联网。',
  };

  constructor(
    private readonly maxRisks = MAX_LOCAL_RISKS,
    private readonly maxClaims = MAX_LOCAL_CLAIMS,
  ) {}

  async analyze(entries: readonly ContextEntry[], rootPath: string, signal?: AbortSignal): Promise<AnalysisResult> {
    const [relations, references] = await Promise.all([
      Promise.resolve(relationRisks(entries, this.maxClaims)),
      brokenReferenceRisks(entries, rootPath, signal, this.maxRisks),
    ]);
    const combined = [...relations.risks, ...references.risks];
    const riskTruncated = references.truncated || combined.length > this.maxRisks;
    const truncated = relations.truncated || riskTruncated;
    const warnings: string[] = [];
    if (relations.truncated) warnings.push(`本地语义分析达到 ${this.maxClaims} 条声明安全上限。`);
    if (riskTruncated) warnings.push(`本地分析达到 ${this.maxRisks} 个风险/引用安全上限。`);
    return {
      risks: combined.slice(0, this.maxRisks),
      warnings,
      descriptor: { ...this.descriptor, status: 'ok' },
      truncated,
    };
  }
}

export class LocalHttpAnalyzer implements Analyzer {
  readonly descriptor: Omit<AnalyzerDescriptor, 'status'>;
  private readonly endpoint: URL;

  constructor(
    endpoint: string,
    private readonly timeoutMs = 5_000,
    private readonly transport: typeof globalThis.fetch = globalThis.fetch,
  ) {
    this.endpoint = new URL(endpoint);
    if (!['http:', 'https:'].includes(this.endpoint.protocol)
      || !['127.0.0.1', 'localhost', '::1'].includes(this.endpoint.hostname)
      || this.endpoint.username
      || this.endpoint.password) throw new Error('可选分析器只允许无凭据的本机 HTTP 回环地址。');
    this.descriptor = { id: 'local-http-semantic', version: '1.0.0', mode: 'local-http', privacy: '只向本机回环分析器发送已脱敏正文，不发送路径或 URI。' };
  }

  async analyze(entries: readonly ContextEntry[], _rootPath: string, signal?: AbortSignal): Promise<AnalysisResult> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(new Error('ANALYZER_TIMEOUT')), this.timeoutMs);
    const abort = () => controller.abort(signal?.reason);
    signal?.addEventListener('abort', abort, { once: true });
    try {
      const safeEntries = entries
        .filter((entry) => entry.packageType !== 'secret-warning' && !containsSecret(`${entry.title}\n${entry.content}\n${entry.tags.join('\n')}`))
        .slice(0, 2_000)
        .map((entry) => ({ id: entry.id, title: entry.title.slice(0, 240), content: entry.content.slice(0, 16_000), scope: entry.scope, tags: entry.tags.slice(0, 64).map((tag) => tag.slice(0, 120)) }));
      const response = await this.transport(this.endpoint, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ schemaVersion: '1', entries: safeEntries }), signal: controller.signal,
        // Never let a loopback adapter relay the sanitized payload elsewhere.
        redirect: 'error',
      });
      if (!response.ok) throw new Error(`ANALYZER_HTTP_${response.status}`);
      const raw = await response.json() as { risks?: unknown[] };
      if (!Array.isArray(raw.risks) || raw.risks.length > 100) throw new Error('ANALYZER_INVALID_OUTPUT');
      const byId = new Map(entries.map((entry) => [entry.id, entry]));
      const risks: ContextRisk[] = raw.risks.map<ContextRisk>((value) => {
        const item = value as { title?: unknown; description?: unknown; itemIds?: unknown };
        if (typeof item.title !== 'string' || typeof item.description !== 'string' || !Array.isArray(item.itemIds) || item.itemIds.length < 2) throw new Error('ANALYZER_INVALID_OUTPUT');
        const sides = item.itemIds.map((id) => byId.get(String(id))).filter((entry): entry is ContextEntry => Boolean(entry)).map((entry) => sideFor(entry));
        if (sides.length < 2) throw new Error('ANALYZER_UNKNOWN_ITEM');
        const title = item.title.slice(0, 120);
        const sideIds = sides.map((side) => side.itemId).sort();
        return { id: `adapter-${digest(`${title}:${sideIds.join(':')}`).slice(0, 12)}`, kind: 'semantic-conflict', severity: 'warning', title, description: item.description.slice(0, 500), sides: sides.sort((left, right) => left.itemId.localeCompare(right.itemId)), analyzerId: this.descriptor.id };
      }).sort((left, right) => left.id.localeCompare(right.id));
      return { risks, warnings: [], descriptor: { ...this.descriptor, status: 'ok' } };
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener('abort', abort);
    }
  }
}

export class AnalyzerPipeline implements Analyzer {
  readonly descriptor = { id: 'analyzer-pipeline', version: '1.0.0', mode: 'local' as const, privacy: '本地基线始终运行；可选适配器失败时安全降级。' };
  constructor(private readonly mandatory: Analyzer = new LocalSemanticAnalyzer(), private readonly optional?: Analyzer) {}

  async analyze(entries: readonly ContextEntry[], rootPath: string, signal?: AbortSignal): Promise<AnalysisResult> {
    const local = await this.mandatory.analyze(entries, rootPath, signal);
    if (!this.optional) return local;
    try {
      const extra = await this.optional.analyze(Object.freeze(entries.map((entry) => Object.freeze({ ...entry }))), rootPath, signal);
      const unique = new Map(local.risks.map((risk) => [risk.id, risk]));
      for (const risk of extra.risks) unique.set(risk.id, risk);
      return { risks: [...unique.values()], warnings: extra.warnings, descriptor: { ...this.descriptor, status: 'ok' }, truncated: local.truncated || extra.truncated };
    } catch (error) {
      if (signal?.aborted) throw signal.reason instanceof Error ? signal.reason : new DOMException('分析已取消。', 'AbortError');
      const code = error instanceof Error ? error.message : 'ANALYZER_FAILED';
      return { risks: local.risks, warnings: [`可选语义分析器已降级：${code}`], descriptor: { ...this.descriptor, status: 'degraded' }, truncated: local.truncated };
    }
  }
}
