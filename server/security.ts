export interface SecretFinding {
  label: string;
  line: number;
}

const secretPatterns: Array<{ label: string; pattern: RegExp }> = [
  { label: 'OpenAI 风格密钥', pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g },
  { label: 'GitHub 风格令牌', pattern: /\b(?:ghp|github_pat)_[A-Za-z0-9_]{20,}\b/g },
  { label: 'AWS 访问密钥', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: '私钥', pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { label: '通用密钥赋值', pattern: /\b(?:api[_-]?key|access[_-]?token|secret)\s*[:=]\s*["']?[A-Za-z0-9_./+-]{20,}/gi },
];

export const secretFilePatterns = [
  /^\.env(?:\..+)?$/i,
  /\.(?:pem|key|p12|pfx)$/i,
  /^id_(?:rsa|dsa|ecdsa|ed25519)(?:\.pub)?$/i,
];

export function isSecretFile(name: string): boolean {
  return secretFilePatterns.some((pattern) => pattern.test(name));
}

export function findSecrets(content: string, maxFindings = 5_000): SecretFinding[] {
  const found: SecretFinding[] = [];
  const matchedLines = new Set<number>();
  const newlineOffsets: number[] = [];
  for (let index = content.indexOf('\n'); index >= 0; index = content.indexOf('\n', index + 1)) {
    newlineOffsets.push(index);
  }
  const lineAt = (offset: number): number => {
    let low = 0;
    let high = newlineOffsets.length;
    while (low < high) {
      const middle = Math.floor((low + high) / 2);
      if (newlineOffsets[middle] < offset) low = middle + 1;
      else high = middle;
    }
    return low + 1;
  };
  for (const { label, pattern } of secretPatterns) {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const line = lineAt(match.index);
      if (!matchedLines.has(line)) {
        found.push({ label, line });
        matchedLines.add(line);
        if (found.length >= maxFindings) return found;
      }
      if (match.index === pattern.lastIndex) pattern.lastIndex += 1;
    }
  }
  return found;
}

export function containsSecret(content: string): boolean {
  return findSecrets(content).length > 0;
}
