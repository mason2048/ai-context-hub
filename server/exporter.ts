import { createHash, randomUUID } from 'node:crypto';
import type { SigningService } from './signing.js';
import { countTokens } from './tokenizer.js';
import type {
  BudgetConfig,
  BudgetReport,
  ContextEntry,
  ContextPackage,
  ContextPackageItem,
  ExportPreviewResult,
  ScanResult,
  SignatureVerification,
} from './types.js';

export type ExportFormat = 'json' | 'agents';

const unsignedSignature: SignatureVerification = {
  status: 'unsigned',
  keyId: null,
  message: '该导出未签名。',
};

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function uuidFromDigest(value: string): string {
  const bytes = Buffer.from(digest(value).slice(0, 32), 'hex');
  // A deterministic RFC 4122 UUID keeps repeated previews byte-for-byte stable.
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function uniqueSelectedIds(result: ScanResult, selectedIds: readonly string[]): string[] {
  const available = new Set(result.entries.map((entry) => entry.id));
  const seen = new Set<string>();
  return selectedIds.filter((id) => available.has(id) && !seen.has(id) && Boolean(seen.add(id)));
}

export function exportableEntries(entries: ContextEntry[], selectedIds: string[]): ContextEntry[] {
  const selected = new Set(selectedIds);
  return entries.filter((entry) => selected.has(entry.id));
}

type EntryWithImportedValidity = ContextEntry & { validity?: ContextPackageItem['validity'] };

function validityFor(entry: ContextEntry, result: ScanResult): ContextPackageItem['validity'] {
  const imported = (entry as EntryWithImportedValidity).validity;
  if (imported) {
    return {
      observedAt: imported.observedAt,
      expiresAt: imported.expiresAt,
      confidence: imported.confidence,
    };
  }
  return {
    observedAt: result.scannedAt,
    expiresAt: null,
    confidence: entry.packageType === 'secret-warning' ? 1 : 0.9,
  };
}

function packageKindFor(result: ScanResult): ContextPackage['kind'] {
  if (result.sourceKind !== 'context-package') return 'repository';
  const supported = new Set<ContextPackage['kind']>(['repository', 'web', 'memory', 'rule', 'mixed']);
  const kinds = new Set<ContextPackage['kind']>();
  for (const entry of result.entries) {
    for (const tag of entry.tags) {
      if (!tag.startsWith('kind:')) continue;
      const kind = tag.slice('kind:'.length) as ContextPackage['kind'];
      if (supported.has(kind)) kinds.add(kind);
    }
  }
  if (kinds.size === 1) return [...kinds][0];
  return 'mixed';
}

function buildContextPackage(
  result: ScanResult,
  selectedIds: string[],
  createdAt: Date,
  packageId: string,
): ContextPackage {
  const selected = exportableEntries(result.entries, selectedIds);
  return {
    schemaVersion: '0.1',
    packageId,
    name: `${result.projectName}-context`,
    kind: packageKindFor(result),
    createdAt: createdAt.toISOString(),
    producer: { name: 'ai-context-hub', version: '0.1.0' },
    items: selected.map((entry) => ({
      id: entry.id,
      type: entry.packageType,
      title: entry.title,
      content: entry.content,
      scope: entry.scope,
      source: {
        uri: entry.source.uri,
        revision: entry.source.revision,
        locator: entry.source.locator,
      },
      validity: validityFor(entry, result),
      sensitivity: entry.sensitivity,
      tags: entry.tags,
    })),
    warnings: [
      ...result.warnings,
      ...result.risks.map((risk) => `${risk.kind}: ${risk.title}`),
    ],
  };
}

/** Compatibility API. New preview code uses deterministic metadata internally. */
export function createContextPackage(result: ScanResult, selectedIds: string[], now = new Date()): ContextPackage {
  return buildContextPackage(result, selectedIds, now, randomUUID());
}

export function createAgentsDraft(result: ScanResult, selectedIds: string[]): string {
  const selected = exportableEntries(result.entries, selectedIds)
    .filter((entry) => entry.packageType !== 'secret-warning');
  const sections = selected.map((entry) => [
    `## ${entry.title}`,
    '',
    `> 来源：${entry.source.relativePath}（${entry.source.locator}） · revision ${entry.source.revision.slice(0, 12)}`,
    '',
    entry.content,
  ].join('\n'));
  return [
    '# AGENTS.md 草案',
    '',
    '> 由 AI Context Hub 本地生成。请审核冲突与来源后再手动采用；本工具不会写入原项目。',
    '',
    ...sections.flatMap((section) => [section, '']),
  ].join('\n').trimEnd() + '\n';
}

/**
 * Revision of the user's requested selection against an immutable scan result.
 * Rescanning identical content produces the same value; changed selection or
 * selected entry content/source produces a different value.
 */
export function createSelectionRevision(result: ScanResult, selectedIds: readonly string[]): string {
  const entriesById = new Map(result.entries.map((entry) => [entry.id, entry]));
  const selection = selectedIds.map((id) => {
    const entry = entriesById.get(id);
    if (!entry) return { id, missing: true };
    return {
      id,
      logicalKey: entry.logicalKey,
      title: entry.title,
      content: entry.content,
      scope: entry.scope,
      packageType: entry.packageType,
      source: {
        uri: entry.source.uri,
        locator: entry.source.locator,
        revision: entry.source.revision,
      },
    };
  });
  return `sha256:${digest(JSON.stringify({
    version: 1,
    projectName: result.projectName,
    rootPath: result.rootPath,
    sourceKind: result.sourceKind,
    selection,
  }))}`;
}

export function isSelectionRevisionStale(
  result: ScanResult,
  selectedIds: readonly string[],
  expectedRevision: string,
): boolean;
export function isSelectionRevisionStale(
  expectedRevision: string,
  result: ScanResult,
  selectedIds: readonly string[],
): boolean;
export function isSelectionRevisionStale(
  first: ScanResult | string,
  second: ScanResult | readonly string[],
  third: readonly string[] | string,
): boolean {
  const result = typeof first === 'string' ? second as ScanResult : first;
  const selectedIds = typeof first === 'string' ? third as readonly string[] : second as readonly string[];
  const expectedRevision = typeof first === 'string' ? first : third as string;
  return createSelectionRevision(result, selectedIds) !== expectedRevision;
}

function validateBudget(budget: BudgetConfig): void {
  if (!Number.isSafeInteger(budget.maxTokens) || budget.maxTokens < 0) {
    throw new RangeError('maxTokens 必须是大于或等于 0 的安全整数。');
  }
  if (!['warn', 'block', 'auto-trim'].includes(budget.policy)) {
    throw new RangeError('不支持的 Token 超限策略。');
  }
}

function autoTrimOrder(result: ScanResult, selectedIds: string[]): ContextEntry[] {
  const entriesById = new Map(result.entries.map((entry) => [entry.id, entry]));
  const risksById = new Map(result.risks.map((risk) => [risk.id, risk]));
  const originalOrder = new Map(selectedIds.map((id, index) => [id, index]));
  const scopeOrder = { global: 3, project: 2, task: 1 } as const;
  const ordered = selectedIds
    .map((id) => entriesById.get(id))
    .filter((entry): entry is ContextEntry => entry !== undefined);
  const severityById = new Map(ordered.map((entry) => [
    entry.id,
    entry.riskIds.reduce((severity, id) => {
      const risk = risksById.get(id);
      return Math.max(severity, risk?.severity === 'danger' ? 2 : risk?.severity === 'warning' ? 1 : 0);
    }, 0),
  ]));
  return ordered.sort((left, right) => {
      const secretDifference = Number(right.packageType === 'secret-warning') - Number(left.packageType === 'secret-warning');
      if (secretDifference) return secretDifference;
      const riskDifference = (severityById.get(right.id) ?? 0) - (severityById.get(left.id) ?? 0);
      if (riskDifference) return riskDifference;
      const scopeDifference = scopeOrder[right.scope] - scopeOrder[left.scope];
      if (scopeDifference) return scopeDifference;
      const selectionDifference = (originalOrder.get(left.id) ?? Number.MAX_SAFE_INTEGER)
        - (originalOrder.get(right.id) ?? Number.MAX_SAFE_INTEGER);
      if (selectionDifference) return selectionDifference;
      return `${left.source.relativePath}:${left.source.startLine}:${left.id}`
        .localeCompare(`${right.source.relativePath}:${right.source.startLine}:${right.id}`);
    });
}

interface RenderedPreview {
  content: string;
  filename: string;
  mediaType: string;
  signature: SignatureVerification;
}

async function renderPreview(
  result: ScanResult,
  selectedIds: string[],
  format: ExportFormat,
  selectionRevision: string,
  signingService?: SigningService,
  sign = false,
): Promise<RenderedPreview> {
  if (format === 'agents') {
    return {
      content: createAgentsDraft(result, selectedIds),
      filename: 'AGENTS.md',
      mediaType: 'text/markdown; charset=utf-8',
      signature: unsignedSignature,
    };
  }
  if (format !== 'json') throw new RangeError('导出格式必须是 json 或 agents。');
  const stableDate = new Date(result.scannedAt);
  if (Number.isNaN(stableDate.getTime())) throw new Error('扫描快照的 scannedAt 无效。');
  // Bind the package identity to both the requested selection revision and the
  // actually emitted subset (auto-trim can produce different subsets).
  const packageId = uuidFromDigest(`context-package-preview-v1:${selectionRevision}:${selectedIds.join('\0')}`);
  let packageValue = buildContextPackage(result, selectedIds, stableDate, packageId);
  let signature = unsignedSignature;
  if (sign) {
    if (!signingService) {
      const error = new Error('签名 JSON 导出需要 SigningService。') as Error & { code: string };
      error.code = 'SIGNING_SERVICE_REQUIRED';
      throw error;
    }
    packageValue = await signingService.sign(packageValue, stableDate);
    signature = await signingService.verify(packageValue);
  }
  return {
    content: `${JSON.stringify(packageValue, null, 2)}\n`,
    filename: `${result.projectName}-context.json`,
    mediaType: 'application/json; charset=utf-8',
    signature,
  };
}

export class TokenBudgetExceededError extends Error {
  readonly code = 'TOKEN_BUDGET_EXCEEDED' as const;

  constructor(readonly report: BudgetReport) {
    super(`完整导出预览需要 ${report.exactTokens} tokens，超过预算 ${report.maxTokens}。`);
    this.name = 'TokenBudgetExceededError';
  }
}

function budgetReport(
  budget: BudgetConfig,
  exactTokens: number,
  selectedIds: string[],
  omittedIds: string[],
  selectionRevision: string,
  autoTrimmed: boolean,
  blocked = false,
): BudgetReport {
  return {
    encoding: 'o200k_base',
    maxTokens: budget.maxTokens,
    exactTokens,
    policy: budget.policy,
    exceeded: exactTokens > budget.maxTokens,
    blocked,
    autoTrimmed,
    selectedIds,
    omittedIds,
    selectionRevision,
  };
}

/**
 * Builds an exact, complete export preview solely from the supplied ScanResult.
 * No source path is opened or rescanned by this module.
 */
export async function createExportPreview(
  result: ScanResult,
  selectedIds: string[],
  format: ExportFormat,
  budget: BudgetConfig,
  signingService?: SigningService,
  sign = false,
): Promise<ExportPreviewResult> {
  validateBudget(budget);
  const requestedIds = uniqueSelectedIds(result, selectedIds);
  const selectionRevision = createSelectionRevision(result, selectedIds);

  if (budget.policy !== 'auto-trim') {
    const rendered = await renderPreview(result, requestedIds, format, selectionRevision, signingService, sign);
    const exactTokens = countTokens(rendered.content);
    const report = budgetReport(budget, exactTokens, requestedIds, [], selectionRevision, false, budget.policy === 'block' && exactTokens > budget.maxTokens);
    if (report.blocked) throw new TokenBudgetExceededError(report);
    return { ...rendered, budget: report };
  }

  const orderedIds = autoTrimOrder(result, requestedIds).map((entry) => entry.id);
  // Render the complete requested set once. Most previews fit and return here;
  // an over-budget request also gives binary search its known failing boundary.
  const complete = await renderPreview(result, orderedIds, format, selectionRevision, signingService, sign);
  const completeTokens = countTokens(complete.content);
  if (completeTokens <= budget.maxTokens) {
    return {
      ...complete,
      budget: budgetReport(
        budget,
        completeTokens,
        orderedIds,
        [],
        selectionRevision,
        false,
      ),
    };
  }

  // With no requested entries, the complete body is also the fixed overhead.
  // Reuse its exact signed count instead of rendering it a second time.
  if (orderedIds.length === 0) {
    throw new TokenBudgetExceededError(budgetReport(
      budget,
      completeTokens,
      [],
      requestedIds,
      selectionRevision,
      true,
      true,
    ));
  }

  const empty = await renderPreview(result, [], format, selectionRevision, signingService, sign);
  const emptyTokens = countTokens(empty.content);
  if (emptyTokens > budget.maxTokens) {
    throw new TokenBudgetExceededError(budgetReport(
      budget,
      emptyTokens,
      [],
      requestedIds,
      selectionRevision,
      true,
      true,
    ));
  }

  // The fitting candidates form strict priority prefixes. The empty prefix is
  // known to fit and the complete prefix is known not to fit, so binary search
  // needs only O(log n) complete serializations, signatures and exact counts.
  let fittingLength = 0;
  let failingLength = orderedIds.length;
  let rendered = empty;
  let exactTokens = emptyTokens;
  while (fittingLength + 1 < failingLength) {
    const candidateLength = Math.floor((fittingLength + failingLength) / 2);
    const candidateIds = orderedIds.slice(0, candidateLength);
    const candidate = await renderPreview(result, candidateIds, format, selectionRevision, signingService, sign);
    const candidateTokens = countTokens(candidate.content);
    if (candidateTokens <= budget.maxTokens) {
      fittingLength = candidateLength;
      rendered = candidate;
      exactTokens = candidateTokens;
    } else {
      failingLength = candidateLength;
    }
  }

  const acceptedIds = orderedIds.slice(0, fittingLength);
  const accepted = new Set(acceptedIds);
  const omittedIds = requestedIds.filter((id) => !accepted.has(id));
  return {
    ...rendered,
    budget: budgetReport(
      budget,
      exactTokens,
      acceptedIds,
      omittedIds,
      selectionRevision,
      omittedIds.length > 0,
    ),
  };
}
