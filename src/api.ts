export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly code: string,
    readonly payload: unknown,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

let mutationToken = '';

export function setMutationToken(token: string): void {
  mutationToken = token;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function errorMessage(payload: unknown, fallback: string): string {
  if (!isRecord(payload)) return fallback;
  if (typeof payload.message === 'string') return payload.message;
  if (typeof payload.error === 'string') return payload.error;
  if (isRecord(payload.error) && typeof payload.error.message === 'string') return payload.error.message;
  return fallback;
}

function errorCode(payload: unknown): string {
  if (!isRecord(payload)) return 'REQUEST_FAILED';
  if (typeof payload.code === 'string') return payload.code;
  if (isRecord(payload.error) && typeof payload.error.code === 'string') return payload.error.code;
  return 'REQUEST_FAILED';
}

export async function requestJson<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const method = (init.method ?? 'GET').toUpperCase();
  if (!['GET', 'HEAD'].includes(method) && mutationToken) headers.set('X-Context-Hub-Token', mutationToken);
  const response = await fetch(path, { ...init, headers, cache: 'no-store' });
  const contentType = response.headers.get('content-type') ?? '';
  let payload: unknown = null;
  if (contentType.includes('application/json')) {
    payload = await response.json().catch(() => null);
  } else {
    const text = await response.text();
    payload = text ? { message: text } : null;
  }
  if (!response.ok) {
    throw new ApiError(errorMessage(payload, `请求失败（${response.status}）`), response.status, errorCode(payload), payload);
  }
  return payload as T;
}

export function postJson<T>(path: string, body: unknown): Promise<T> {
  return requestJson<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}
