import { createHash } from 'node:crypto';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';
import schema from '../context-package.schema.json';
import { findSecrets } from './security.js';
import type { SigningService } from './signing.js';
import { countEntryTokens, TOKEN_ENCODING } from './tokenizer.js';
import type {
  ContextEntry,
  ContextPackage,
  ContextPackageItem,
  ItemCategory,
  ScanResult,
  SignatureVerification,
} from './types.js';

export const PACKAGE_IMPORT_LIMITS = Object.freeze({
  rawBytes: 5 * 1024 * 1024,
  items: 5_000,
  itemContentBytes: 1_000_000,
  totalContentBytes: 10_000_000,
  maxNestingDepth: 64,
});

export type PackageImportErrorCode =
  | 'RAW_TOO_LARGE'
  | 'INVALID_UTF8'
  | 'INVALID_JSON'
  | 'NESTING_TOO_DEEP'
  | 'UNSUPPORTED_SCHEMA_VERSION'
  | 'SCHEMA_INVALID'
  | 'TOO_MANY_ITEMS'
  | 'DUPLICATE_ITEM_ID'
  | 'ITEM_CONTENT_TOO_LARGE'
  | 'TOTAL_CONTENT_TOO_LARGE'
  | 'PLAINTEXT_SECRET'
  | 'INVALID_SIGNATURE';

export class PackageImportError extends Error {
  readonly name = 'PackageImportError';

  constructor(
    readonly code: PackageImportErrorCode,
    message: string,
    readonly details: readonly string[] = [],
  ) {
    super(message);
  }
}

export interface PackageInspection {
  accepted: true;
  schemaVersion: '0.1';
  packageId: string;
  name: string;
  kind: ContextPackage['kind'];
  producer: { name: string; version: string };
  rawBytes: number;
  itemCount: number;
  sensitiveItemCount: number;
  secretWarningCount: number;
  contentBytes: number;
  exactTokens: number;
  tokenEncoding: typeof TOKEN_ENCODING;
  sourceAccess: 'metadata-only';
  signatureVerification: SignatureVerification;
  /** Compatibility alias for callers that adopted the first import draft. */
  signature: SignatureVerification;
  warnings: string[];
  limits: typeof PACKAGE_IMPORT_LIMITS;
}

export interface PackageImportResult {
  inspection: PackageInspection;
  result: ScanResult;
  /** SHA-256 over the complete parsed package, including signature and unknown extension fields. */
  identityDigest: string;
}

type SignatureVerifier = Pick<SigningService, 'verify'>;

const ajv = new Ajv2020({ allErrors: true, strict: true });
addFormats(ajv);
const validatePackage = ajv.compile(schema);

const categoryByType: Record<ContextPackageItem['type'], ItemCategory> = {
  fact: 'knowledge',
  instruction: 'rule',
  preference: 'rule',
  workflow: 'skill',
  reference: 'knowledge',
  'secret-warning': 'knowledge',
};

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalIdentity(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new PackageImportError('INVALID_JSON', 'Context Package 含无法规范化的数字。');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalIdentity).join(',')}]`;
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalIdentity(value[key])}`).join(',')}}`;
  }
  throw new PackageImportError('INVALID_JSON', 'Context Package 含无法规范化的值。');
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, 'utf8');
}

function decodeRaw(raw: string | Buffer): { text: string; bytes: number } {
  const bytes = typeof raw === 'string' ? byteLength(raw) : raw.byteLength;
  if (bytes > PACKAGE_IMPORT_LIMITS.rawBytes) {
    throw new PackageImportError(
      'RAW_TOO_LARGE',
      `Context Package 超过 ${PACKAGE_IMPORT_LIMITS.rawBytes} 字节上限。`,
    );
  }
  if (typeof raw === 'string') return { text: raw.replace(/^\uFEFF/, ''), bytes };
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(raw).replace(/^\uFEFF/, '');
    return { text, bytes };
  } catch {
    throw new PackageImportError('INVALID_UTF8', 'Context Package 不是有效的 UTF-8 JSON。');
  }
}

function assertSafeNestingDepth(text: string): void {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const character of text) {
    if (inString) {
      if (escaped) escaped = false;
      else if (character === '\\') escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === '{' || character === '[') {
      depth += 1;
      if (depth > PACKAGE_IMPORT_LIMITS.maxNestingDepth) {
        throw new PackageImportError(
          'NESTING_TOO_DEEP',
          `Context Package 嵌套层级超过 ${PACKAGE_IMPORT_LIMITS.maxNestingDepth} 层上限。`,
        );
      }
    } else if (character === '}' || character === ']') {
      depth = Math.max(0, depth - 1);
    }
  }
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    throw new PackageImportError('INVALID_JSON', 'Context Package 不是有效的 JSON。');
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateSchema(value: unknown): asserts value is ContextPackage {
  if (isRecord(value) && value.schemaVersion !== '0.1') {
    throw new PackageImportError(
      'UNSUPPORTED_SCHEMA_VERSION',
      '仅支持 Context Package schemaVersion 0.1。',
    );
  }
  if (!validatePackage(value)) {
    const details = (validatePackage.errors ?? []).slice(0, 12).map((error) => {
      const location = error.instancePath || '/';
      return `${location}: ${error.message ?? '不符合 schema'}`;
    });
    throw new PackageImportError('SCHEMA_INVALID', 'Context Package 未通过 v0.1 schema 校验。', details);
  }
}

function validateSignatureShape(value: ContextPackage): void {
  if (!Object.prototype.hasOwnProperty.call(value, 'signature')) return;
  const signature = (value as ContextPackage & { signature?: unknown }).signature;
  if (!isRecord(signature)) {
    throw new PackageImportError('INVALID_SIGNATURE', '签名字段格式无效，导入已阻断。');
  }
  const requiredStrings = ['algorithm', 'canonicalization', 'keyId', 'createdAt', 'publicKey', 'value'];
  if (requiredStrings.some((key) => typeof signature[key] !== 'string' || signature[key].length === 0)) {
    throw new PackageImportError('INVALID_SIGNATURE', '签名字段格式无效，导入已阻断。');
  }
}

function validateLimits(value: ContextPackage): number {
  if (value.items.length > PACKAGE_IMPORT_LIMITS.items) {
    throw new PackageImportError(
      'TOO_MANY_ITEMS',
      `Context Package 最多允许 ${PACKAGE_IMPORT_LIMITS.items} 个条目。`,
    );
  }
  const ids = new Set<string>();
  let totalContentBytes = 0;
  for (const item of value.items) {
    if (ids.has(item.id)) {
      throw new PackageImportError('DUPLICATE_ITEM_ID', 'Context Package 中存在重复条目 ID。');
    }
    ids.add(item.id);
    const contentBytes = byteLength(item.content);
    if (contentBytes > PACKAGE_IMPORT_LIMITS.itemContentBytes) {
      throw new PackageImportError(
        'ITEM_CONTENT_TOO_LARGE',
        `单个条目正文超过 ${PACKAGE_IMPORT_LIMITS.itemContentBytes} 字节上限。`,
      );
    }
    totalContentBytes += contentBytes;
    if (totalContentBytes > PACKAGE_IMPORT_LIMITS.totalContentBytes) {
      throw new PackageImportError(
        'TOTAL_CONTENT_TOO_LARGE',
        `条目正文合计超过 ${PACKAGE_IMPORT_LIMITS.totalContentBytes} 字节上限。`,
      );
    }
  }
  return totalContentBytes;
}

function assertNoSecrets(text: string, value: ContextPackage): void {
  const findings = findSecrets(text);
  const labels = new Set(findings.map((finding) => finding.label));
  if (/["'](?:api[_-]?key|access[_-]?token|secret)["']\s*:\s*["'][A-Za-z0-9_./+=-]{20,}["']/i.test(text)) {
    labels.add('JSON 密钥字段');
  }
  for (const item of value.items) {
    try {
      const source = new URL(item.source.uri);
      if (source.username || source.password) labels.add('来源 URI 凭据');
    } catch {
      // A non-URL source identifier cannot carry URL userinfo.
    }
  }
  if (labels.size === 0) return;
  throw new PackageImportError(
    'PLAINTEXT_SECRET',
    'Context Package 含疑似明文秘密，导入已阻断；请在来源产品中替换为 secret-warning。',
    [...labels],
  );
}

function normalizedDisplayText(value: string, fallback: string, maximum = 160): string {
  const compact = value.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  const redacted = compact
    .replace(/file:\/\/\/[^\s)\]}]+/gi, '[file-source-redacted]')
    .replace(/(?:^|\s)(?:\/[\w.@%+~-]+){2,}(?=[:\s,;)]|$)/g, ' [absolute-path-redacted]')
    .replace(/(?:^|\s)[A-Za-z]:\\(?:[^\\\s]+\\)+[^\\\s]*/g, ' [absolute-path-redacted]')
    .trim();
  const usable = redacted || fallback;
  return usable.length > maximum ? `${usable.slice(0, maximum - 1)}…` : usable;
}

function safeTag(value: string, fallback: string): string {
  return normalizedDisplayText(value, fallback, 96).replace(/[\s,]+/g, '-').toLowerCase();
}

function basenameFromFileUrl(url: URL): string {
  const parts = url.pathname.split('/').filter(Boolean);
  let basename = parts.at(-1) ?? 'source';
  try { basename = decodeURIComponent(basename); } catch { /* Display the encoded basename. */ }
  return normalizedDisplayText(basename, 'source', 120).replace(/[\\/]/g, '_');
}

interface SafeSource {
  uri: string;
  relativePath: string;
}

function safeSourceMetadata(rawUri: string): SafeSource {
  try {
    const parsed = new URL(rawUri);
    if (parsed.protocol === 'file:') {
      const basename = basenameFromFileUrl(parsed);
      return {
        uri: `file:///[absolute-path-redacted]/${encodeURIComponent(basename)}`,
        relativePath: `imported-source/${basename}`,
      };
    }
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      parsed.username = '';
      parsed.password = '';
      parsed.search = '';
      parsed.hash = '';
      const safeUri = parsed.toString();
      const pathname = parsed.pathname.split('/').filter(Boolean).map((part) => {
        try { return decodeURIComponent(part); } catch { return part; }
      }).map((part) => normalizedDisplayText(part, 'source', 80).replace(/[\\/]/g, '_')).join('/');
      return {
        uri: safeUri.length > 1_024 ? `${parsed.origin}/[path-truncated]` : safeUri,
        relativePath: `remote/${normalizedDisplayText(parsed.hostname, 'remote', 120)}/${pathname || 'source'}`,
      };
    }
  } catch {
    // Non-URL source identifiers are represented by a one-way display handle.
  }
  const handle = digest(rawUri).slice(0, 16);
  return { uri: `context-package://source/${handle}`, relativePath: `imported-source/${handle}` };
}

function locatorLines(locator: string): { startLine: number; endLine: number } {
  const range = locator.match(/\b(\d{1,9})\s*(?:-|–|—|\.\.|至)\s*(\d{1,9})\b/);
  if (range) {
    const first = Math.max(1, Number(range[1]));
    const second = Math.max(1, Number(range[2]));
    return { startLine: Math.min(first, second), endLine: Math.max(first, second) };
  }
  const single = locator.match(/\b(\d{1,9})\b/);
  const line = single ? Math.max(1, Number(single[1])) : 1;
  return { startLine: line, endLine: line };
}

function normalizedRevision(revision: string): string {
  if (/^[A-Za-z0-9._:@+-]{1,256}$/.test(revision)) return revision;
  return `imported:${digest(revision)}`;
}

function summaryFor(content: string): string {
  const compact = content.replace(/[`*_>#\[\]]/g, '').replace(/\s+/g, ' ').trim();
  return compact.length > 116 ? `${compact.slice(0, 113)}…` : compact;
}

function normalizeEntry(
  item: ContextPackageItem,
  packageValue: ContextPackage,
): ContextEntry {
  const category = categoryByType[item.type];
  const safeSource = safeSourceMetadata(item.source.uri);
  const locator = normalizedDisplayText(item.source.locator, '包内来源定位不可用', 500);
  const lines = locatorLines(locator);
  const title = normalizedDisplayText(item.title, `导入条目 ${digest(item.id).slice(0, 8)}`, 240);
  const tokenCount = countEntryTokens(title, item.content);
  const logicalSeed = [packageValue.producer.name, packageValue.kind, item.id].join('\u0000');
  const namespacedId = digest(`${packageValue.packageId}\u0000${item.id}`);
  const importedTags = [
    ...item.tags.map((tag) => normalizedDisplayText(tag, '', 120)).filter(Boolean),
    'imported',
    'context-package',
    `producer:${safeTag(packageValue.producer.name, 'unknown')}`,
    `kind:${packageValue.kind}`,
  ];
  return {
    id: `imported-${namespacedId.slice(0, 24)}`,
    logicalKey: `context-package:${digest(logicalSeed).slice(0, 32)}`,
    title,
    category,
    packageType: item.type,
    scope: item.scope,
    content: item.content,
    summary: summaryFor(item.content),
    source: {
      relativePath: safeSource.relativePath,
      uri: safeSource.uri,
      locator,
      startLine: lines.startLine,
      endLine: lines.endLine,
      revision: normalizedRevision(item.source.revision),
      modifiedAt: item.validity.observedAt,
    },
    sensitivity: item.sensitivity,
    validity: { ...item.validity },
    tags: [...new Set(importedTags)],
    riskIds: [],
    tokenCount,
    tokenEncoding: TOKEN_ENCODING,
    tokenEstimate: tokenCount,
  };
}

function packageWarnings(value: ContextPackage): string[] {
  const warnings = value.warnings
    .filter((warning): warning is string => typeof warning === 'string')
    .slice(0, 100)
    .map((warning) => normalizedDisplayText(warning, '导入包告警', 500));
  const ignored = value.warnings.length - warnings.length;
  if (ignored > 0) warnings.push(`另有 ${ignored} 条非文本或超量包告警未展开。`);
  return warnings;
}

function signatureWarnings(verification: SignatureVerification): string[] {
  return verification.status === 'unsigned' || verification.status === 'valid-untrusted'
    ? [verification.message]
    : [];
}

/**
 * Validates and normalizes a Context Package without opening, fetching, or
 * resolving any source URI carried by the package.
 */
export async function inspectContextPackage(
  raw: string | Buffer,
  verifier: SignatureVerifier,
  now = new Date(),
): Promise<PackageImportResult> {
  const startedAt = Date.now();
  const decoded = decodeRaw(raw);
  assertSafeNestingDepth(decoded.text);
  const parsed = parseJson(decoded.text);
  validateSchema(parsed);
  // Compute before normalization: accepted unknown extensions are part of package identity,
  // even though their untrusted values are deliberately never persisted or returned.
  const identityDigest = `sha256:${digest(canonicalIdentity(parsed))}`;
  validateSignatureShape(parsed);
  const contentBytes = validateLimits(parsed);
  assertNoSecrets(decoded.text, parsed);

  const signature = await verifier.verify(parsed);
  if (signature.status === 'invalid') {
    throw new PackageImportError('INVALID_SIGNATURE', 'Context Package 签名无效，导入已阻断。');
  }

  const entries = parsed.items.map((item) => normalizeEntry(item, parsed));
  const exactTokens = entries.reduce((sum, entry) => sum + entry.tokenCount, 0);
  const warnings = [...signatureWarnings(signature), ...packageWarnings(parsed)];
  const scannedAt = now.toISOString();
  const durationMs = Math.max(0, Date.now() - startedAt);
  const safeName = normalizedDisplayText(parsed.name, `Context Package ${parsed.packageId.slice(0, 8)}`, 240);
  const safeProducer = {
    name: normalizedDisplayText(parsed.producer.name, 'unknown', 160),
    version: normalizedDisplayText(parsed.producer.version, 'unknown', 80),
  };
  const result: ScanResult = {
    rootPath: `package:${parsed.packageId}`,
    projectName: safeName,
    sourceKind: 'context-package',
    scannedAt,
    entries,
    risks: [],
    warnings,
    analyzers: [{
      id: 'context-package-import',
      version: '0.1.0',
      mode: 'local',
      privacy: '仅解析包内 JSON；来源 URI 只作脱敏显示，不访问文件或网络。',
      status: 'ok',
    }],
    stats: {
      filesScanned: 1,
      entries: entries.length,
      risks: 0,
      tokenCount: exactTokens,
      tokenEstimate: exactTokens,
      tokenEncoding: TOKEN_ENCODING,
      healthScore: 100,
      performance: {
        directoriesVisited: 0,
        fsEntriesVisited: 0,
        candidatesDiscovered: entries.length,
        filesRead: 0,
        cacheHits: 0,
        cacheMisses: 0,
        ignoredPaths: 0,
        totalBytesRead: 0,
        durationMs,
        truncated: false,
      },
    },
    rules: {
      included: ['Context Package v0.1 已声明条目'],
      excludedDirectories: [],
      excludedFiles: ['包内 source.uri 指向的所有文件与网络资源'],
      maxFileBytes: PACKAGE_IMPORT_LIMITS.itemContentBytes,
      maxFiles: PACKAGE_IMPORT_LIMITS.items,
      maxDirectories: 0,
      maxFsEntries: 0,
      maxEntriesPerFile: PACKAGE_IMPORT_LIMITS.items,
      maxEntries: PACKAGE_IMPORT_LIMITS.items,
      maxRisks: PACKAGE_IMPORT_LIMITS.items,
      maxClaims: PACKAGE_IMPORT_LIMITS.items,
      maxTotalBytes: PACKAGE_IMPORT_LIMITS.totalContentBytes,
      concurrency: 1,
    },
  };

  return {
    identityDigest,
    inspection: {
      accepted: true,
      schemaVersion: '0.1',
      packageId: parsed.packageId,
      name: safeName,
      kind: parsed.kind,
      producer: safeProducer,
      rawBytes: decoded.bytes,
      itemCount: entries.length,
      sensitiveItemCount: parsed.items.filter((item) => item.sensitivity === 'sensitive' || item.sensitivity === 'secret').length,
      secretWarningCount: parsed.items.filter((item) => item.type === 'secret-warning').length,
      contentBytes,
      exactTokens,
      tokenEncoding: TOKEN_ENCODING,
      sourceAccess: 'metadata-only',
      signatureVerification: signature,
      signature,
      warnings,
      limits: PACKAGE_IMPORT_LIMITS,
    },
    result,
  };
}

export const importContextPackage = inspectContextPackage;
