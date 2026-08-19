import { Tiktoken } from 'js-tiktoken/lite';
import o200kBase from 'js-tiktoken/ranks/o200k_base';

export const TOKEN_ENCODING = 'o200k_base' as const;

let tokenizer: Tiktoken | undefined;

function getTokenizer(): Tiktoken {
  tokenizer ??= new Tiktoken(o200kBase);
  return tokenizer;
}

/** Exact BPE count for o200k_base. No network or model call is performed. */
export function countTokens(content: string): number {
  return getTokenizer().encode(content).length;
}

export function countEntryTokens(title: string, content: string): number {
  return countTokens(`${title}\n${content}`);
}
