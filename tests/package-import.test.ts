import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  inspectContextPackage,
  PACKAGE_IMPORT_LIMITS,
} from '../server/package-import.js';
import { SigningService } from '../server/signing.js';
import { countEntryTokens } from '../server/tokenizer.js';
import type { ContextPackage } from '../server/types.js';

const temporaryDirectories: string[] = [];

async function signer(label: string): Promise<SigningService> {
  const directory = await mkdtemp(path.join(os.tmpdir(), `context-hub-${label}-`));
  temporaryDirectories.push(directory);
  return new SigningService(directory);
}

afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

function packageFixture(overrides: Partial<ContextPackage> = {}): ContextPackage {
  return {
    schemaVersion: '0.1',
    packageId: '11111111-1111-4111-8111-111111111111',
    name: 'foreign-context',
    kind: 'repository',
    createdAt: '2026-08-12T00:00:00.000Z',
    producer: { name: 'repo2skill', version: '0.2.0' },
    items: [{
      id: 'stable-rule-id',
      type: 'instruction',
      title: '测试约定',
      content: '提交前运行 npm test。',
      scope: 'project',
      source: {
        uri: 'https://example.test/docs/AGENTS.md?private=discard-me#section',
        revision: 'abc123',
        locator: '第 4-5 行',
      },
      validity: { observedAt: '2026-08-11T00:00:00.000Z', expiresAt: null, confidence: 0.9 },
      sensitivity: 'internal',
      tags: ['quality'],
    }],
    warnings: [],
    ...overrides,
  };
}

describe('Context Package 导入', () => {
  it('接受 Buffer 与未知字段，忽略未知值并生成稳定映射和精确 token', async () => {
    const verifier = await signer('unknown-fields');
    const fixture = packageFixture() as ContextPackage & Record<string, unknown>;
    fixture.futureTopLevel = { mustNotAppear: 'unknown-field-marker' };
    (fixture.producer as Record<string, unknown>).futureProducerField = true;
    (fixture.items[0] as unknown as Record<string, unknown>).futureItemField = 'future-item-marker';

    const first = await inspectContextPackage(Buffer.from(JSON.stringify(fixture)), verifier, new Date('2026-08-12T01:00:00.000Z'));
    const second = await inspectContextPackage(JSON.stringify(fixture), verifier, new Date('2026-08-12T02:00:00.000Z'));
    const entry = first.result.entries[0];

    expect(first.inspection.signature.status).toBe('unsigned');
    expect(first.inspection.warnings).toContain(first.inspection.signature.message);
    expect(first.inspection.sourceAccess).toBe('metadata-only');
    expect(first.identityDigest).toBe(second.identityDigest);
    expect(first.result.sourceKind).toBe('context-package');
    expect(entry.category).toBe('rule');
    expect(entry.logicalKey).toBe(second.result.entries[0].logicalKey);
    expect(entry.id).toBe(second.result.entries[0].id);
    expect(entry.tokenCount).toBe(countEntryTokens(entry.title, entry.content));
    expect(entry.tokenEstimate).toBe(entry.tokenCount);
    expect(entry.tags).toEqual(expect.arrayContaining(['imported', 'context-package', 'producer:repo2skill', 'kind:repository']));
    expect(JSON.stringify(first)).not.toContain('unknown-field-marker');
    expect(JSON.stringify(first)).not.toContain('future-item-marker');

    const changedUnknown = structuredClone(fixture);
    changedUnknown.futureTopLevel = { mustNotAppear: 'different-unknown-value' };
    const third = await inspectContextPackage(JSON.stringify(changedUnknown), verifier);
    expect(third.identityDigest).not.toBe(first.identityDigest);
  });

  it('拒绝错误 schemaVersion 和缺少必填字段的包', async () => {
    const verifier = await signer('schema');
    const wrongVersion = { ...packageFixture(), schemaVersion: '0.2' };
    await expect(inspectContextPackage(JSON.stringify(wrongVersion), verifier))
      .rejects.toMatchObject({ code: 'UNSUPPORTED_SCHEMA_VERSION' });

    const missingSource = packageFixture();
    delete (missingSource.items[0] as unknown as Record<string, unknown>).source;
    await expect(inspectContextPackage(JSON.stringify(missingSource), verifier))
      .rejects.toMatchObject({ code: 'SCHEMA_INVALID' });
  });

  it('在 schema 忽略未知字段时仍限制恶意未知字段的嵌套深度', async () => {
    const verifier = await signer('depth');
    const fixture = packageFixture() as ContextPackage & Record<string, unknown>;
    let nested: unknown = 'leaf';
    for (let depth = 0; depth < PACKAGE_IMPORT_LIMITS.maxNestingDepth; depth += 1) nested = [nested];
    fixture.futureDeepValue = nested;
    await expect(inspectContextPackage(JSON.stringify(fixture), verifier))
      .rejects.toMatchObject({ code: 'NESTING_TOO_DEEP' });
  });

  it('对所有包条目类型采用固定 category 映射，并统计敏感条目', async () => {
    const verifier = await signer('mapping');
    const fixture = packageFixture();
    const types = ['fact', 'instruction', 'preference', 'workflow', 'reference', 'secret-warning'] as const;
    fixture.items = types.map((type, index) => ({
      ...fixture.items[0],
      id: `mapped-${type}`,
      type,
      sensitivity: index >= 4 ? 'sensitive' : 'internal',
      content: type === 'secret-warning' ? '来源产品已移除秘密原值。' : `${type} 的安全示例正文。`,
    }));

    const imported = await inspectContextPackage(JSON.stringify(fixture), verifier);
    expect(imported.result.entries.map((entry) => entry.category)).toEqual([
      'knowledge', 'rule', 'rule', 'skill', 'knowledge', 'knowledge',
    ]);
    expect(imported.inspection.sensitiveItemCount).toBe(2);
    expect(imported.inspection.secretWarningCount).toBe(1);
  });

  it('拒绝重复 item id', async () => {
    const verifier = await signer('duplicate');
    const fixture = packageFixture();
    fixture.items.push({ ...fixture.items[0], title: '另一条规则' });
    await expect(inspectContextPackage(JSON.stringify(fixture), verifier))
      .rejects.toMatchObject({ code: 'DUPLICATE_ITEM_ID' });
  });

  it('检测明文秘密并阻断，错误对象也不回显秘密', async () => {
    const verifier = await signer('secret');
    const fixture = packageFixture();
    const providerShapedSecret = ['sk', 'this-is-a-fake-secret-value-123456789'].join('-');
    fixture.items[0].content = `api_key = "${providerShapedSecret}"`;
    let caught: unknown;
    try {
      await inspectContextPackage(JSON.stringify(fixture), verifier);
    } catch (error) {
      caught = error;
    }
    expect(caught).toMatchObject({ code: 'PLAINTEXT_SECRET' });
    expect(JSON.stringify(caught)).not.toContain(providerShapedSecret);

    const genericJsonSecret = packageFixture() as ContextPackage & Record<string, unknown>;
    genericJsonSecret.futureCredentials = { api_key: 'generic-fake-credential-1234567890' };
    await expect(inspectContextPackage(JSON.stringify(genericJsonSecret), verifier))
      .rejects.toMatchObject({ code: 'PLAINTEXT_SECRET' });

    const credentialUri = packageFixture();
    credentialUri.items[0].source.uri = 'https://alice:fake-password@example.test/rules';
    await expect(inspectContextPackage(JSON.stringify(credentialUri), verifier))
      .rejects.toMatchObject({ code: 'PLAINTEXT_SECRET' });
  });

  it('拒绝单条正文、原始 JSON 和条目数量超限', async () => {
    const verifier = await signer('limits');
    const oversizedItem = packageFixture();
    oversizedItem.items[0].content = 'x'.repeat(PACKAGE_IMPORT_LIMITS.itemContentBytes + 1);
    await expect(inspectContextPackage(JSON.stringify(oversizedItem), verifier))
      .rejects.toMatchObject({ code: 'ITEM_CONTENT_TOO_LARGE' });

    const oversizedRaw = `${JSON.stringify(packageFixture()).slice(0, -1)},"padding":"${'x'.repeat(PACKAGE_IMPORT_LIMITS.rawBytes)}"}`;
    await expect(inspectContextPackage(oversizedRaw, verifier))
      .rejects.toMatchObject({ code: 'RAW_TOO_LARGE' });

    const tooMany = packageFixture();
    tooMany.items = Array.from({ length: PACKAGE_IMPORT_LIMITS.items + 1 }, (_, index) => ({
      ...tooMany.items[0],
      id: `item-${index}`,
      content: '',
    }));
    await expect(inspectContextPackage(JSON.stringify(tooMany), verifier))
      .rejects.toMatchObject({ code: 'TOO_MANY_ITEMS' });
  });

  it('允许有效签名；可信签名无警告，有效但未受信签名带警告', async () => {
    const local = await signer('local');
    const foreign = await signer('foreign');
    const trustedPackage = await local.sign(packageFixture(), new Date('2026-08-12T00:10:00.000Z'));
    const trusted = await inspectContextPackage(JSON.stringify(trustedPackage), local);
    expect(trusted.inspection.signature.status).toBe('valid-trusted');
    expect(trusted.inspection.warnings).not.toContain(trusted.inspection.signature.message);

    const foreignPackage = await foreign.sign(packageFixture(), new Date('2026-08-12T00:20:00.000Z'));
    const untrusted = await inspectContextPackage(JSON.stringify(foreignPackage), local);
    expect(untrusted.inspection.signature.status).toBe('valid-untrusted');
    expect(untrusted.inspection.warnings).toContain(untrusted.inspection.signature.message);
  });

  it('阻断签名后被篡改的包', async () => {
    const signerService = await signer('tamper');
    const signed = await signerService.sign(packageFixture());
    signed.items[0].content = '篡改后的规则内容。';
    await expect(inspectContextPackage(JSON.stringify(signed), signerService))
      .rejects.toMatchObject({ code: 'INVALID_SIGNATURE' });
  });

  it('file/https 来源仅作安全显示，不访问 URI 且不泄漏绝对路径', async () => {
    const verifier = await signer('uri');
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    const fixture = packageFixture();
    fixture.items = [
      {
        ...fixture.items[0],
        id: 'file-source',
        source: { ...fixture.items[0].source, uri: 'file:///Users/alice/private-project/AGENTS.md' },
      },
      {
        ...fixture.items[0],
        id: 'https-source',
        source: { ...fixture.items[0].source, uri: 'https://127.0.0.1:9/would-contact?private=discard-me#fragment' },
      },
    ];

    const imported = await inspectContextPackage(JSON.stringify(fixture), verifier);
    const serialized = JSON.stringify(imported);
    expect(fetchSpy).not.toHaveBeenCalled();
    expect(serialized).not.toContain('/Users/alice/private-project');
    expect(serialized).not.toContain('discard-me');
    expect(imported.result.entries[0].source.uri).toContain('[absolute-path-redacted]');
    expect(imported.result.entries[1].source.uri).toBe('https://127.0.0.1:9/would-contact');
    expect(imported.result.stats.performance.filesRead).toBe(0);
  });
});
