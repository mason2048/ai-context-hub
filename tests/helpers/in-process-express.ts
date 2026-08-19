import { IncomingMessage, ServerResponse } from 'node:http';
import { Socket } from 'node:net';
import type { Express } from 'express';

function requestBody(body: RequestInit['body']): Buffer {
  if (body === undefined || body === null) return Buffer.alloc(0);
  if (typeof body === 'string') return Buffer.from(body);
  if (body instanceof ArrayBuffer) return Buffer.from(body);
  if (ArrayBuffer.isView(body)) return Buffer.from(body.buffer, body.byteOffset, body.byteLength);
  if (body instanceof URLSearchParams) return Buffer.from(body.toString());
  throw new TypeError('进程内 Express 测试只接受可确定长度的请求正文。');
}

function responseHeaders(response: ServerResponse): Headers {
  const headers = new Headers();
  for (const [name, value] of Object.entries(response.getHeaders())) {
    if (Array.isArray(value)) {
      for (const item of value) headers.append(name, String(item));
    } else if (value !== undefined) {
      headers.set(name, String(value));
    }
  }
  return headers;
}

/**
 * Exercises Express through real Node IncomingMessage/ServerResponse objects
 * without opening a TCP listener. Body parsers, middleware ordering, headers,
 * status codes and asynchronous route handlers therefore use their production
 * code paths even inside a network-denied sandbox.
 */
export async function requestExpress(
  app: Express,
  route: string,
  init: RequestInit = {},
): Promise<Response> {
  const body = requestBody(init.body);
  const headers = new Headers(init.headers);
  if (!headers.has('host')) headers.set('host', '127.0.0.1');
  if (body.length > 0 && !headers.has('content-length')) headers.set('content-length', String(body.length));

  const socket = new Socket();
  const request = new IncomingMessage(socket);
  request.method = (init.method ?? 'GET').toUpperCase();
  request.url = route;
  request.headers = {};
  request.rawHeaders = [];
  headers.forEach((value, name) => {
    request.headers[name] = value;
    request.rawHeaders.push(name, value);
  });

  return new Promise<Response>((resolve, reject) => {
    const response = new ServerResponse(request);
    const chunks: Buffer[] = [];
    let settled = false;

    const finish = (chunk?: unknown, encoding?: BufferEncoding | (() => void), callback?: () => void): ServerResponse => {
      if (chunk !== undefined && chunk !== null) {
        const selectedEncoding = typeof encoding === 'string' ? encoding : undefined;
        chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), selectedEncoding));
      }
      const done = typeof encoding === 'function' ? encoding : callback;
      done?.();
      if (!settled) {
        settled = true;
        const payload = Buffer.concat(chunks);
        resolve(new Response(payload.length > 0 ? payload : null, {
          status: response.statusCode,
          headers: responseHeaders(response),
        }));
      }
      return response;
    };

    response.write = ((chunk: unknown, encoding?: BufferEncoding | (() => void), callback?: () => void) => {
      const selectedEncoding = typeof encoding === 'string' ? encoding : undefined;
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk), selectedEncoding));
      const done = typeof encoding === 'function' ? encoding : callback;
      done?.();
      return true;
    }) as typeof response.write;
    response.end = finish as typeof response.end;

    try {
      const dispatch = app as unknown as (
        incoming: IncomingMessage,
        outgoing: ServerResponse,
        next: (error?: unknown) => void,
      ) => void;
      dispatch(request, response, (error?: unknown) => {
        if (settled) return;
        settled = true;
        reject(error ?? new Error(`Express 未处理测试请求：${request.method} ${route}`));
      });
      request.push(body.length > 0 ? body : null);
      if (body.length > 0) request.push(null);
    } catch (error) {
      settled = true;
      reject(error);
    }
  }).finally(() => socket.destroy());
}
