import { randomUUID } from 'node:crypto';
import type { ScanJobView, ScanProgress, SnapshotEnvelope } from './types.js';

export interface JobOutcome {
  envelope?: SnapshotEnvelope;
  partialResult?: ScanJobView['partialResult'];
}

export type ScanJobRunner = (context: {
  signal: AbortSignal;
  report: (progress: ScanProgress) => void;
}) => Promise<JobOutcome>;

interface InternalJob {
  view: ScanJobView;
  controller: AbortController;
}

function cloneView(view: ScanJobView): ScanJobView {
  return structuredClone(view);
}

export class ScanJobManager {
  private readonly jobs = new Map<string, InternalJob>();
  private readonly runningKeys = new Set<string>();

  constructor(private readonly maxRetained = 50) {}

  create(key: string, runner: ScanJobRunner): ScanJobView {
    if (this.runningKeys.has(key)) {
      const error = new Error('该项目已有扫描任务正在运行。');
      error.name = 'SCAN_ALREADY_RUNNING';
      throw error;
    }
    const now = new Date().toISOString();
    const id = randomUUID();
    const job: InternalJob = {
      controller: new AbortController(),
      view: {
        id,
        status: 'queued',
        createdAt: now,
        updatedAt: now,
        progress: { phase: 'discover', processed: 0, total: null, percent: 0, message: '扫描任务已排队。' },
      },
    };
    this.jobs.set(id, job);
    this.runningKeys.add(key);
    this.prune();
    queueMicrotask(async () => {
      if (job.controller.signal.aborted) {
        job.view.status = 'cancelled';
        job.view.error = { code: 'SCAN_CANCELLED', message: '扫描已取消，旧快照保持不变。' };
        job.view.updatedAt = new Date().toISOString();
        this.runningKeys.delete(key);
        return;
      }
      job.view.status = 'running';
      job.view.updatedAt = new Date().toISOString();
      try {
        const outcome = await runner({
          signal: job.controller.signal,
          report: (progress) => {
            if (job.view.status !== 'running') return;
            job.view.progress = { ...progress };
            job.view.updatedAt = new Date().toISOString();
          },
        });
        // A returned envelope means the atomic manifest commit won the race. It must be
        // reported as completed even if a late cancellation arrived after that commit.
        if (outcome.envelope) {
          job.view.status = 'completed';
          job.view.envelope = outcome.envelope;
          job.view.progress = { phase: 'done', processed: outcome.envelope.result.entries.length, total: outcome.envelope.result.entries.length, percent: 100, message: '扫描与快照保存完成。' };
        } else if (job.controller.signal.aborted) {
          job.view.status = 'cancelled';
          job.view.error = { code: 'SCAN_CANCELLED', message: '扫描已取消，旧快照保持不变。' };
        } else if (outcome.partialResult) {
          job.view.status = 'partial';
          job.view.partialResult = outcome.partialResult;
          job.view.progress = { phase: 'done', processed: outcome.partialResult.entries.length, total: outcome.partialResult.entries.length, percent: 100, message: '扫描达到安全上限；部分结果未覆盖旧快照。' };
        } else {
          job.view.status = 'completed';
          job.view.progress = { phase: 'done', processed: 0, total: 0, percent: 100, message: '扫描完成。' };
        }
      } catch (error) {
        if (job.controller.signal.aborted || (error instanceof Error && error.name === 'AbortError')) {
          job.view.status = 'cancelled';
          job.view.error = { code: 'SCAN_CANCELLED', message: '扫描已取消，旧快照保持不变。' };
        } else {
          job.view.status = 'failed';
          job.view.error = { code: 'SCAN_FAILED', message: '扫描失败，旧快照保持不变。请检查目录访问权限与扫描规则。' };
        }
      } finally {
        job.view.updatedAt = new Date().toISOString();
        this.runningKeys.delete(key);
      }
    });
    return cloneView(job.view);
  }

  get(id: string): ScanJobView | undefined {
    const job = this.jobs.get(id);
    return job ? cloneView(job.view) : undefined;
  }

  cancel(id: string): ScanJobView | undefined {
    const job = this.jobs.get(id);
    if (!job) return undefined;
    if (job.view.status === 'queued' || job.view.status === 'running') {
      job.controller.abort(new Error('用户取消'));
      if (job.view.status === 'queued') {
        job.view.status = 'cancelled';
        job.view.error = { code: 'SCAN_CANCELLED', message: '扫描已取消，旧快照保持不变。' };
      }
      job.view.progress = { ...job.view.progress, message: job.view.status === 'cancelled' ? '扫描已取消。' : '正在取消扫描…' };
      job.view.updatedAt = new Date().toISOString();
    }
    return cloneView(job.view);
  }

  private prune(): void {
    if (this.jobs.size <= this.maxRetained) return;
    for (const [id, job] of this.jobs) {
      if (['completed', 'partial', 'cancelled', 'failed'].includes(job.view.status)) this.jobs.delete(id);
      if (this.jobs.size <= this.maxRetained) break;
    }
  }
}
