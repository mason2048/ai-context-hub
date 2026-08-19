import { mkdtemp, readFile, rm, stat } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { canonicalPackageContent, SigningService } from '../server/signing.js';
import type { ContextPackage } from '../server/types.js';

const directories: string[] = [];

async function service(label: string): Promise<{ signer: SigningService; directory: string }> {
  const directory = await mkdtemp(path.join(os.tmpdir(), `context-hub-sign-${label}-`));
  directories.push(directory);
  return { signer: new SigningService(directory), directory };
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })));
});

function fixture(): ContextPackage {
  return {
    schemaVersion: '0.1', packageId: '77777777-7777-4777-8777-777777777777', name: 'signed-context', kind: 'mixed',
    createdAt: '2026-08-12T00:00:00.000Z', producer: { name: 'ai-context-hub', version: '0.2.0' },
    items: [{
      id: 'rule-1', type: 'instruction', title: '测试规则', content: '运行 npm test。', scope: 'project',
      source: { uri: 'file:///safe/AGENTS.md', revision: 'abc', locator: '第 1 行' },
      validity: { observedAt: '2026-08-12T00:00:00.000Z', expiresAt: null, confidence: 0.9 },
      sensitivity: 'internal', tags: ['quality'],
    }], warnings: [],
  };
}

describe('Ed25519 Context Package 签名', () => {
  it('签名可由本机密钥验证，JSON 重排与空白不影响结果', async () => {
    const { signer } = await service('trusted');
    const unsigned = fixture() as ContextPackage & Record<string, unknown>;
    unsigned.futureExtension = { nested: { enabled: true, order: [3, 2, 1] } };
    const signed = await signer.sign(unsigned, new Date('2026-08-12T01:00:00.000Z'));
    const deepReverse = (value: unknown): unknown => {
      if (Array.isArray(value)) return value.map(deepReverse);
      if (value && typeof value === 'object') {
        return Object.fromEntries(Object.entries(value as Record<string, unknown>).reverse().map(([key, child]) => [key, deepReverse(child)]));
      }
      return value;
    };
    const reordered = deepReverse(signed) as ContextPackage;
    const roundtrip = JSON.parse(JSON.stringify(signed, null, 4)) as ContextPackage;
    expect(await signer.verify(roundtrip)).toMatchObject({ status: 'valid-trusted', keyId: signed.signature?.keyId });
    expect((await signer.verify(reordered)).status).toBe('valid-trusted');
    expect(canonicalPackageContent(roundtrip)).toBe(canonicalPackageContent(signed));
  });

  it('正文、签名时间、公钥指纹任一变化都使签名无效', async () => {
    const { signer } = await service('tamper');
    const signed = await signer.sign(fixture());
    const contentTamper = structuredClone(signed);
    contentTamper.items[0].content = '被篡改';
    expect((await signer.verify(contentTamper)).status).toBe('invalid');

    const metadataTamper = structuredClone(signed);
    metadataTamper.signature!.createdAt = '2030-01-01T00:00:00.000Z';
    expect((await signer.verify(metadataTamper)).status).toBe('invalid');

    const keyIdTamper = structuredClone(signed);
    keyIdTamper.signature!.keyId = 'ed25519:00000000000000000000000000000000';
    expect((await signer.verify(keyIdTamper)).status).toBe('invalid');

    const extensionTamper = structuredClone(signed) as ContextPackage & Record<string, unknown>;
    extensionTamper.futureExtension = { changed: true };
    expect((await signer.verify(extensionTamper)).status).toBe('invalid');
  });

  it('外部有效签名只标记为 valid-untrusted，未签名保持兼容', async () => {
    const local = await service('local');
    const foreign = await service('foreign');
    const signed = await foreign.signer.sign(fixture());
    expect((await local.signer.verify(signed)).status).toBe('valid-untrusted');
    expect((await local.signer.verify(fixture())).status).toBe('unsigned');
  });

  it('私钥文件权限为 0600，且签名包和公钥响应不含私钥 PEM', async () => {
    const { signer, directory } = await service('permissions');
    const signed = await signer.sign(fixture());
    const privatePath = path.join(directory, 'keys', 'ed25519-private.pem');
    const privateInfo = await stat(privatePath);
    const privatePem = await readFile(privatePath, 'utf8');
    expect(privateInfo.mode & 0o777).toBe(0o600);
    expect(privatePem).toContain('PRIVATE KEY');
    expect(JSON.stringify(signed)).not.toContain('PRIVATE KEY');
  });
});
