import {
  createHash,
  generateKeyPairSync,
  randomUUID,
  sign as cryptoSign,
  verify as cryptoVerify,
} from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import { chmod, mkdir, open, readFile, rename, unlink } from 'node:fs/promises';
import path from 'node:path';
import type { ContextPackage, PackageSignature, SignatureVerification } from './types.js';

function canonicalizeValue(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('签名内容包含非有限数字。');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalizeValue).join(',')}]`;
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().filter((key) => record[key] !== undefined).map((key) => `${JSON.stringify(key)}:${canonicalizeValue(record[key])}`).join(',')}}`;
  }
  throw new Error('签名内容包含无法规范化的值。');
}

export function canonicalPackageContent(value: ContextPackage): string {
  if (!value.signature) return canonicalizeValue(value);
  const { value: _value, ...signedMetadata } = value.signature;
  return canonicalizeValue({ ...value, signature: signedMetadata });
}

export function publicKeyId(publicKeyDer: Buffer): string {
  return `ed25519:${createHash('sha256').update(publicKeyDer).digest('hex').slice(0, 32)}`;
}

async function atomicWrite(filePath: string, content: string, mode: number): Promise<void> {
  const directory = path.dirname(filePath);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  await chmod(directory, 0o700);
  const temporary = path.join(directory, `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, mode);
    await handle.writeFile(content, 'utf8');
    await handle.sync();
    await handle.close();
    handle = undefined;
    await rename(temporary, filePath);
    await chmod(filePath, mode);
    try {
      const directoryHandle = await open(directory, fsConstants.O_RDONLY);
      try { await directoryHandle.sync(); } finally { await directoryHandle.close(); }
    } catch (error) {
      if (!['EINVAL', 'ENOTSUP', 'EBADF', 'EISDIR'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
    }
  } catch (error) {
    await handle?.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export class SigningService {
  private readonly privatePath: string;
  private readonly publicPath: string;
  private keyPairPromise?: Promise<{ privateKey: string; publicKey: string }>;

  constructor(private readonly dataDirectory: string) {
    this.privatePath = path.join(dataDirectory, 'keys', 'ed25519-private.pem');
    this.publicPath = path.join(dataDirectory, 'keys', 'ed25519-public.pem');
  }

  private async ensureKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
    this.keyPairPromise ??= this.loadOrCreateKeyPair().catch((error) => {
      this.keyPairPromise = undefined;
      throw error;
    });
    return this.keyPairPromise;
  }

  private async loadOrCreateKeyPair(): Promise<{ privateKey: string; publicKey: string }> {
    try {
      const [privateKey, publicKey] = await Promise.all([
        readFile(this.privatePath, 'utf8'),
        readFile(this.publicPath, 'utf8'),
      ]);
      return { privateKey, publicKey };
    } catch {
      const generated = generateKeyPairSync('ed25519', {
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        publicKeyEncoding: { type: 'spki', format: 'pem' },
      });
      await atomicWrite(this.privatePath, generated.privateKey, 0o600);
      await atomicWrite(this.publicPath, generated.publicKey, 0o600);
      return generated;
    }
  }

  async localKeyId(): Promise<string> {
    const { publicKey } = await this.ensureKeyPair();
    const der = Buffer.from(publicKey.replace(/-----[^-]+-----|\s/g, ''), 'base64');
    return publicKeyId(der);
  }

  async sign(packageValue: ContextPackage, now = new Date()): Promise<ContextPackage> {
    const { privateKey, publicKey } = await this.ensureKeyPair();
    const publicDer = Buffer.from(publicKey.replace(/-----[^-]+-----|\s/g, ''), 'base64');
    const metadata: Omit<PackageSignature, 'value'> = {
      algorithm: 'Ed25519',
      canonicalization: 'context-hub-jcs-v1',
      keyId: publicKeyId(publicDer),
      createdAt: now.toISOString(),
      publicKey: publicDer.toString('base64'),
    };
    const canonical = canonicalPackageContent({ ...packageValue, signature: { ...metadata, value: '' } });
    const signature: PackageSignature = { ...metadata, value: cryptoSign(null, Buffer.from(canonical), privateKey).toString('base64') };
    return { ...packageValue, signature };
  }

  async verify(packageValue: ContextPackage): Promise<SignatureVerification> {
    if (!packageValue.signature) {
      return { status: 'unsigned', keyId: null, message: '该包未签名；可导入，但无法验证生成后是否被修改。' };
    }
    const signature = packageValue.signature;
    if (signature.algorithm !== 'Ed25519' || signature.canonicalization !== 'context-hub-jcs-v1') {
      return { status: 'invalid', keyId: signature.keyId ?? null, message: '不支持的签名算法或规范化方式。' };
    }
    try {
      const publicDer = Buffer.from(signature.publicKey, 'base64');
      const expectedKeyId = publicKeyId(publicDer);
      if (expectedKeyId !== signature.keyId) {
        return { status: 'invalid', keyId: signature.keyId, message: '公钥指纹与 keyId 不一致。' };
      }
      const valid = cryptoVerify(
        null,
        Buffer.from(canonicalPackageContent(packageValue)),
        { key: publicDer, format: 'der', type: 'spki' },
        Buffer.from(signature.value, 'base64'),
      );
      if (!valid) return { status: 'invalid', keyId: signature.keyId, message: '签名校验失败，包内容可能已被修改。' };
      const localKeyId = await this.localKeyId();
      return {
        status: signature.keyId === localKeyId ? 'valid-trusted' : 'valid-untrusted',
        keyId: signature.keyId,
        message: signature.keyId === localKeyId
          ? '签名有效，且来自本机 Context Hub 密钥。'
          : '签名有效，但签名者不在本机信任范围；嵌入公钥只证明完整性，不证明身份。',
      };
    } catch {
      return { status: 'invalid', keyId: signature.keyId ?? null, message: '签名字段格式无效。' };
    }
  }
}
