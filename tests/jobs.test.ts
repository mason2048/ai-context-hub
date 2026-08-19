import { describe, expect, it } from 'vitest';
import { ScanJobManager } from '../server/jobs.js';

async function waitForTerminal(manager: ScanJobManager, id: string) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    const job = manager.get(id)!;
    if (['completed', 'partial', 'cancelled', 'failed'].includes(job.status)) return job;
    await new Promise((resolve) => setTimeout(resolve, 2));
  }
  throw new Error('job timeout');
}

describe('扫描任务管理器', () => {
  it('报告单调进度并完成任务', async () => {
    const manager = new ScanJobManager();
    const created = manager.create('a', async ({ report }) => {
      report({ phase: 'read', processed: 1, total: 2, percent: 40, message: '读取中' });
      return {};
    });
    const completed = await waitForTerminal(manager, created.id);
    expect(completed.status).toBe('completed');
    expect(completed.progress.percent).toBe(100);
  });

  it('同一项目 single-flight，不同项目可并行', async () => {
    const manager = new ScanJobManager();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => { release = resolve; });
    const first = manager.create('same', async () => { await gate; return {}; });
    expect(() => manager.create('same', async () => ({}))).toThrowError(/已有扫描任务/);
    const other = manager.create('other', async () => ({}));
    release();
    expect((await waitForTerminal(manager, first.id)).status).toBe('completed');
    expect((await waitForTerminal(manager, other.id)).status).toBe('completed');
  });

  it('取消传播 AbortSignal 且不产生完成结果', async () => {
    const manager = new ScanJobManager();
    const created = manager.create('cancel', ({ signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => reject(signal.reason), { once: true });
    }));
    manager.cancel(created.id);
    expect((await waitForTerminal(manager, created.id)).status).toBe('cancelled');
  });
});
