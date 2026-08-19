import {
  useDeferredValue,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ChangeEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
} from 'react';
import {
  AlertTriangle,
  Archive,
  BookOpen,
  Box,
  Check,
  ChevronDown,
  Code2,
  Download,
  Eye,
  FileCode2,
  FileText,
  FolderOpen,
  Gauge,
  History,
  Import,
  ListFilter,
  LockKeyhole,
  Menu,
  PackageCheck,
  RefreshCw,
  Search,
  Settings2,
  ShieldAlert,
  SlidersHorizontal,
  Square,
  Wrench,
  X,
} from 'lucide-react';
import { ApiError, postJson, requestJson, setMutationToken } from './api';
import type {
  BudgetPolicy,
  Category,
  CompletionEnvelope,
  ConfigResponse,
  Entry,
  ExportFormat,
  ExportPreviewResult,
  PackageInspectionResponse,
  PublicProject,
  Risk,
  RiskKind,
  Rules,
  ScanJob,
  ScanResult,
  Scope,
  SnapshotDiff,
  SnapshotMetadata,
  SnapshotView,
  WorkspaceData,
} from './types';

const DEFAULT_RULES: Rules = {
  included: ['AGENTS.md / CLAUDE.md', '.github/copilot-instructions.md', 'rules/** / SKILL.md', 'Markdown 知识文件 / MCP 配置元数据'],
  excludedDirectories: ['.git', 'node_modules', 'dist', 'build', 'vendor'],
  excludedFiles: ['常见密钥与凭据文件', '二进制文件', '.gitignore 命中的路径'],
  maxFileBytes: 1_000_000,
  maxFiles: 5_000,
  maxDirectories: 20_000,
  maxFsEntries: 100_000,
  maxEntriesPerFile: 1_000,
  maxEntries: 5_000,
  maxRisks: 5_000,
  maxClaims: 20_000,
  maxTotalBytes: 32 * 1024 * 1024,
  concurrency: 8,
};

const categoryLabels: Record<Category, string> = {
  rule: '规则', skill: 'Skill', knowledge: '知识', tool: '工具配置',
};
const scopeLabels: Record<Scope, string> = { global: '全局', project: '项目', task: '任务' };
const riskLabels: Record<RiskKind, string> = {
  conflict: '冲突', duplicate: '重复', 'broken-reference': '失效引用', secret: '秘密', 'semantic-conflict': '语义冲突',
};
const policyLabels: Record<BudgetPolicy, string> = {
  warn: '超限提示', block: '超限阻止', 'auto-trim': '自动精简',
};
const phaseLabels = { discover: '发现文件', read: '读取内容', analyze: '分析风险', persist: '保存快照', done: '完成' } as const;

function formatDate(value: string, withTime = false): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '未知时间';
  return withTime
    ? date.toLocaleString('zh-CN', { hour12: false })
    : date.toLocaleDateString('zh-CN');
}

function normalizeSnapshot(value: CompletionEnvelope['snapshot'], fallbackDiff?: SnapshotDiff, fallbackResult?: ScanResult): SnapshotView {
  if ('metadata' in value && 'result' in value && 'diff' in value) return value as SnapshotView;
  return {
    metadata: value as SnapshotMetadata,
    diff: fallbackDiff ?? {
      fromSnapshotId: null,
      toSnapshotId: (value as SnapshotMetadata).id,
      added: [], removed: [], changed: [], unchanged: 0,
      files: { added: [], removed: [], changed: [], unchanged: 0 },
      risks: { added: 0, removed: 0 },
    },
    result: fallbackResult ?? (() => { throw new Error('快照正文缺失。'); })(),
  };
}

function normalizeWorkspace(envelope: CompletionEnvelope): WorkspaceData {
  return {
    project: envelope.project,
    snapshot: normalizeSnapshot(envelope.snapshot, envelope.diff, envelope.result),
  };
}

function EntryIcon({ category }: { category: Category }) {
  const props = { size: 18, strokeWidth: 1.8, 'aria-hidden': true } as const;
  if (category === 'skill') return <Wrench {...props} />;
  if (category === 'knowledge') return <BookOpen {...props} />;
  if (category === 'tool') return <Settings2 {...props} />;
  return <FileText {...props} />;
}

function Checkbox({ checked, mixed = false, onChange, label }: {
  checked: boolean; mixed?: boolean; onChange: () => void; label: string;
}) {
  return (
    <button
      className={`checkbox ${checked || mixed ? 'checked' : ''}`}
      onClick={(event) => { event.stopPropagation(); onChange(); }}
      aria-label={label}
      aria-checked={mixed ? 'mixed' : checked}
      role="checkbox"
      type="button"
    >
      {mixed ? <span className="minus" /> : checked ? <Check size={13} strokeWidth={2.4} /> : null}
    </button>
  );
}

function SelectControl<T extends string>({ value, onChange, label, options }: {
  value: T; onChange: (value: T) => void; label: string; options: Array<{ value: T; label: string }>;
}) {
  return (
    <label className="select-control">
      <span>{label}</span>
      <span className="select-wrap">
        <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value as T)}>
          {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
        <ChevronDown size={14} aria-hidden="true" />
      </span>
    </label>
  );
}

function Modal({ open, titleId, className, onClose, children }: {
  open: boolean; titleId: string; className: string; onClose: () => void; children: ReactNode;
}) {
  const dialogRef = useRef<HTMLElement>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;
  useEffect(() => {
    if (!open) return undefined;
    const previous = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const dialog = dialogRef.current;
    const backdrop = dialog?.parentElement;
    const modalRoot = backdrop?.parentElement;
    const background = modalRoot
      ? [...modalRoot.children].filter((element): element is HTMLElement => element instanceof HTMLElement && element !== backdrop)
      : [];
    const nestedBackground = modalRoot
      ? [...modalRoot.querySelectorAll<HTMLElement>('.workspace, .setup-view, .workspace-shell, .topbar')]
      : [];
    const isolatedBackground = [...new Set([...background, ...nestedBackground])];
    const backgroundState = isolatedBackground.map((element) => ({
      element,
      inert: element.inert,
      ariaHidden: element.getAttribute('aria-hidden'),
    }));
    isolatedBackground.forEach((element) => {
      element.inert = true;
      element.setAttribute('aria-hidden', 'true');
    });
    dialog?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onCloseRef.current();
      if (event.key !== 'Tab' || !dialog) return;
      const focusable = [...dialog.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), [href], [tabindex]:not([tabindex="-1"])')];
      if (focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      backgroundState.forEach(({ element, inert, ariaHidden }) => {
        element.inert = inert;
        if (ariaHidden === null) element.removeAttribute('aria-hidden');
        else element.setAttribute('aria-hidden', ariaHidden);
      });
      previous?.focus();
    };
  }, [open]);
  if (!open) return null;
  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={(event) => event.target === event.currentTarget && onClose()}>
      <section ref={dialogRef} className={className} role="dialog" aria-modal="true" aria-labelledby={titleId} tabIndex={-1}>
        {children}
      </section>
    </div>
  );
}

function RulesPanel({ rules, compact = false }: { rules: Rules; compact?: boolean }) {
  const [expanded, setExpanded] = useState(!compact);
  return (
    <section className={`rules-panel ${compact ? 'compact' : ''}`} aria-labelledby="rules-title">
      <button className="rules-heading" type="button" aria-expanded={expanded} onClick={() => setExpanded((value) => !value)}>
        <span><SlidersHorizontal size={18} /> <strong id="rules-title">扫描规则</strong> <small>只读 · 扫描前确认</small></span>
        <ChevronDown className={expanded ? 'rotated' : ''} size={18} />
      </button>
      {expanded ? (
        <div className="rules-grid">
          <div><h3><span className="status-dot green" />包含文件</h3><ul>{rules.included.map((item) => <li key={item}>{item}</li>)}</ul></div>
          <div><h3><span className="status-dot red" />排除目录 / 文件</h3><p className="mono-list">{rules.excludedDirectories.join(' · ')}</p><p className="mono-list">{rules.excludedFiles.join(' · ')}</p></div>
          <div><h3>安全与性能上限</h3><p>单文件 ≤ {Math.max(1, Math.round(rules.maxFileBytes / 1_000_000))} MB</p><p>最多 {rules.maxFiles.toLocaleString()} 个候选文件 / {rules.maxDirectories.toLocaleString()} 个目录</p><p>目录发现最多读取 {rules.maxFsEntries.toLocaleString()} 个文件系统条目</p><p>结构化条目最多 {rules.maxEntries.toLocaleString()} 个（单文件 {rules.maxEntriesPerFile.toLocaleString()} 个）</p><p>语义声明最多 {rules.maxClaims.toLocaleString()} 条；风险与引用最多 {rules.maxRisks.toLocaleString()} 个</p><p>最终正文合计 ≤ {Math.round(rules.maxTotalBytes / 1024 / 1024)} MiB</p><p>{rules.concurrency} 路受限并发，不跟随符号链接</p></div>
        </div>
      ) : null}
    </section>
  );
}

function ProjectCards({ projects, loading, onOpen }: {
  projects: PublicProject[]; loading: boolean; onOpen: (id: string) => void;
}) {
  if (loading) return <div className="recent-empty"><RefreshCw className="spin" size={18} />正在读取本地项目…</div>;
  if (projects.length === 0) return <div className="recent-empty"><History size={20} />尚无快照。第一次扫描或导入后会显示在这里。</div>;
  return (
    <div className="project-card-grid">
      {projects.map((project) => (
        <button type="button" className="project-card" key={project.id} onClick={() => onOpen(project.id)}>
          <span className={`project-kind ${project.sourceKind}`}><span className="status-dot green" />{project.sourceKind === 'local-project' ? '本地项目' : '导入包'}</span>
          <strong>{project.name}</strong>
          <small>{project.snapshots.length} 个快照 · {formatDate(project.updatedAt, true)}</small>
        </button>
      ))}
    </div>
  );
}

function SetupView({ initialPath, rules, projects, projectsLoading, busy, job, error, onScan, onCancel, onImport, onOpenProject }: {
  initialPath: string; rules: Rules; projects: PublicProject[]; projectsLoading: boolean; busy: boolean; job: ScanJob | null; error: string;
  onScan: (path: string) => void; onCancel: () => void; onImport: () => void; onOpenProject: (id: string) => void;
}) {
  const [pathValue, setPathValue] = useState(initialPath);
  useEffect(() => setPathValue(initialPath), [initialPath]);
  return (
    <main className="setup-view">
      <div className="setup-copy"><div className="setup-symbol"><Archive size={29} strokeWidth={1.7} /></div><h1>先看清，再交给 AI</h1><p>只读整理多个项目的规则、Skill、知识和工具配置；每次刷新都保存为可追溯快照。</p></div>
      <section className="path-section" aria-labelledby="project-path-label">
        <div className="path-title-row"><label id="project-path-label" htmlFor="project-path">本地项目绝对路径</label><button className="text-button" type="button" onClick={onImport}><Import size={15} />导入 Context Package</button></div>
        <div className="path-input-wrap"><FolderOpen size={19} /><input id="project-path" value={pathValue} onChange={(event) => setPathValue(event.target.value)} placeholder="/Users/you/project" spellCheck={false} /><button className="primary-button" type="button" disabled={busy || !pathValue.trim()} onClick={() => onScan(pathValue.trim())}>{busy ? <RefreshCw className="spin" size={17} /> : <Search size={17} />}{busy ? '扫描任务进行中' : '开始只读扫描'}</button></div>
        <p className="field-help">目录只在本机服务中读取；扫描不会修改项目文件。也可导入其他产品生成的 v0.1 JSON 包。</p>
        {error ? <p className="error-message" role="alert"><AlertTriangle size={16} />{error}</p> : null}
        {job ? <ScanStatus job={job} onCancel={onCancel} /> : null}
      </section>
      <RulesPanel rules={rules} />
      <section className="recent-projects" aria-labelledby="recent-title"><div className="section-heading"><div><h2 id="recent-title">最近项目</h2><p>切换项目会直接打开最近快照，不会重新读取源目录。</p></div><History size={19} /></div><ProjectCards projects={projects} loading={projectsLoading} onOpen={onOpenProject} /></section>
      <div className="boundary-row"><span><LockKeyhole size={16} /> 文件默认不上传</span><span><Eye size={16} /> 导出前显示完整内容</span><span><PackageCheck size={16} /> 不修改被扫描项目</span></div>
    </main>
  );
}

function Sidebar({ workspace, projects, active, onActive, onOpenProject, onReset }: {
  workspace: WorkspaceData; projects: PublicProject[]; active: string; onActive: (value: string) => void;
  onOpenProject: (id: string) => void; onReset: () => void;
}) {
  const { project, snapshot } = workspace;
  const nav = [
    { id: 'rules', label: '扫描规则', icon: SlidersHorizontal },
    { id: 'entries', label: '上下文清单', icon: ListFilter },
    { id: 'risks', label: '风险报告', icon: ShieldAlert },
    { id: 'export', label: '导出预览', icon: Download },
  ];
  return (
    <aside className="sidebar">
      <div className="project-block"><span className="sidebar-label">当前项目</span><strong>{project.name}</strong><code title={snapshot.metadata.id}>{snapshot.metadata.id}</code><small>{project.sourceKind === 'local-project' ? '本地项目快照' : 'Context Package 快照'} · {formatDate(snapshot.metadata.capturedAt, true)}</small><button type="button" className="secondary-button full" onClick={onReset}><FolderOpen size={16} />打开项目库</button></div>
      {projects.length > 1 ? <label className="project-switch"><span>快速切换</span><span className="select-wrap"><select aria-label="切换最近项目" value={project.id} onChange={(event) => onOpenProject(event.target.value)}>{projects.map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select><ChevronDown size={14} /></span></label> : null}
      <nav aria-label="工作台区域">{nav.map(({ id, label, icon: Icon }) => <button key={id} type="button" className={active === id ? 'active' : ''} onClick={() => onActive(id)}><Icon size={18} strokeWidth={1.8} />{label}{id === 'risks' && snapshot.result.risks.length > 0 ? <span className="nav-count">{snapshot.result.risks.length}</span> : null}</button>)}</nav>
      <div className="privacy-note"><LockKeyhole size={15} /><span>仅监听本机<br />快照不可变、源项目不回写</span></div>
    </aside>
  );
}

function HealthStrip({ result, selectedEntries, budget }: { result: ScanResult; selectedEntries: Entry[]; budget: number }) {
  const selectedTokens = selectedEntries.reduce((sum, item) => sum + item.tokenCount, 0);
  const values = [
    { icon: Gauge, text: `健康分 ${result.stats.healthScore}` },
    { icon: FileText, text: `${result.stats.entries} 个条目` },
    { icon: ShieldAlert, text: `${result.stats.risks} 个风险` },
    { icon: Code2, text: `${selectedTokens.toLocaleString()} / ${budget.toLocaleString()} tokens` },
  ];
  return <div className="health-strip">{values.map(({ icon: Icon, text }) => <span key={text}><Icon size={17} />{text}</span>)}</div>;
}

function RiskBadge({ risk }: { risk: Risk }) {
  return <span className={`risk-badge ${risk.severity}`}><AlertTriangle size={13} />{riskLabels[risk.kind]}</span>;
}

function DiffBanner({ diff, onDismiss }: { diff: SnapshotDiff; onDismiss: () => void }) {
  const changed = diff.added.length + diff.removed.length + diff.changed.length;
  return (
    <section className={`diff-banner ${changed === 0 ? 'quiet' : ''}`} aria-label="本次快照变化">
      <History size={18} />
      <div><strong>{diff.fromSnapshotId ? (changed === 0 ? '刷新完成，没有上下文变化' : '刷新完成，已保存新快照') : '首个快照已保存'}</strong><span>新增 {diff.added.length} · 修改 {diff.changed.length} · 移除 {diff.removed.length} · 风险 +{diff.risks.added}/-{diff.risks.removed}</span></div>
      <button className="icon-button" type="button" aria-label="关闭变化摘要" onClick={onDismiss}><X size={18} /></button>
    </section>
  );
}

function Inspector({ entry, risks, onSelectEntry }: { entry?: Entry; risks: Risk[]; onSelectEntry: (id: string) => void }) {
  if (!entry) return <aside className="inspector empty"><FileText size={32} /><p>选择一个条目查看来源和内容。</p></aside>;
  return (
    <aside className="inspector">
      <div className="inspector-heading"><span className={`entry-icon ${entry.category}`}><EntryIcon category={entry.category} /></span><div><h2>{entry.title}</h2><span className="type-label">{categoryLabels[entry.category]} · {entry.tokenCount.toLocaleString()} tokens</span></div></div>
      <section><h3>来源信息</h3><dl className="source-list"><div><dt>文件路径</dt><dd><code>{entry.source.relativePath}</code></dd></div><div><dt>位置</dt><dd>{entry.source.locator}</dd></div><div><dt>SHA-256</dt><dd><code title={entry.source.revision}>{entry.source.revision.slice(0, 16)}…</code></dd></div><div><dt>修改时间</dt><dd>{formatDate(entry.source.modifiedAt, true)}</dd></div></dl></section>
      <section><h3>内容预览</h3><pre className={entry.packageType === 'secret-warning' ? 'secret-content' : ''}>{entry.content}</pre></section>
      {risks.map((risk) => <section className={`risk-box ${risk.severity}`} key={risk.id}><h3><AlertTriangle size={16} />{risk.title}</h3><p>{risk.description}</p><div className="risk-sides">{risk.sides.map((side, index) => <button type="button" key={`${side.itemId}-${index}`} onClick={() => onSelectEntry(side.itemId)}><span>{side.source} · {side.locator}</span><code>{side.excerpt}</code></button>)}</div>{risk.sides.length > 1 ? <small>点击任一方可查看完整来源</small> : null}</section>)}
    </aside>
  );
}

function EntryTable({ entries, risksById, selectedIds, activeId, allSelected, someSelected, onToggleVisible, onToggle, onInspect }: {
  entries: Entry[]; risksById: Map<string, Risk>; selectedIds: Set<string>; activeId: string; allSelected: boolean; someSelected: boolean;
  onToggleVisible: () => void; onToggle: (id: string) => void; onInspect: (id: string) => void;
}) {
  const pageSize = 200;
  const [page, setPage] = useState(0);
  const pageCount = Math.max(1, Math.ceil(entries.length / pageSize));
  const safePage = Math.min(page, pageCount - 1);
  const pageEntries = useMemo(() => entries.slice(safePage * pageSize, (safePage + 1) * pageSize), [entries, safePage]);
  useEffect(() => setPage(0), [entries]);
  const inspectOnKey = (event: ReactKeyboardEvent<HTMLTableRowElement>, id: string) => {
    if (event.target !== event.currentTarget || !['Enter', ' '].includes(event.key)) return;
    event.preventDefault(); onInspect(id);
  };
  return (
    <>
      <div className="table-scroll desktop-entries"><table><thead><tr><th className="check-col"><Checkbox checked={allSelected} mixed={!allSelected && someSelected} onChange={onToggleVisible} label="选择或取消当前筛选的全部条目" /></th><th>条目</th><th>类型</th><th>作用域</th><th>来源</th><th>修改时间</th><th>风险</th></tr></thead><tbody>{pageEntries.map((entry) => { const entryRisks = entry.riskIds.map((id) => risksById.get(id)).filter((item): item is Risk => Boolean(item)); return <tr key={entry.id} tabIndex={0} aria-label={`查看 ${entry.title}`} className={entry.id === activeId ? 'selected' : ''} onClick={() => onInspect(entry.id)} onKeyDown={(event) => inspectOnKey(event, entry.id)}><td><Checkbox checked={selectedIds.has(entry.id)} onChange={() => onToggle(entry.id)} label={`${selectedIds.has(entry.id) ? '取消' : '选择'} ${entry.title}`} /></td><td><div className="entry-name"><span className={`entry-icon ${entry.category}`}><EntryIcon category={entry.category} /></span><span><strong>{entry.title}</strong><small>{entry.summary}</small></span></div></td><td><span className={`category-label ${entry.category}`}>{categoryLabels[entry.category]}</span></td><td>{scopeLabels[entry.scope]}</td><td><code className="source-code">{entry.source.relativePath}<small>{entry.source.locator}</small></code></td><td>{formatDate(entry.source.modifiedAt)}</td><td>{entryRisks.length > 0 ? <RiskBadge risk={entryRisks[0]} /> : <span className="no-risk">—</span>}</td></tr>; })}</tbody></table></div>
      <div className="mobile-entry-list">{pageEntries.map((entry) => { const entryRisk = entry.riskIds.map((id) => risksById.get(id)).find(Boolean); return <article key={entry.id} className={`mobile-entry-card ${entry.id === activeId ? 'selected' : ''}`}><div className="mobile-card-head"><Checkbox checked={selectedIds.has(entry.id)} onChange={() => onToggle(entry.id)} label={`${selectedIds.has(entry.id) ? '取消' : '选择'} ${entry.title}`} /><button type="button" onClick={() => onInspect(entry.id)}><span className={`entry-icon ${entry.category}`}><EntryIcon category={entry.category} /></span><span><strong>{entry.title}</strong><small>{entry.summary}</small></span></button></div><dl><div><dt>类型</dt><dd>{categoryLabels[entry.category]} · {scopeLabels[entry.scope]}</dd></div><div><dt>来源</dt><dd><code>{entry.source.relativePath}</code></dd></div><div><dt>Token</dt><dd>{entry.tokenCount.toLocaleString()}</dd></div></dl>{entryRisk ? <RiskBadge risk={entryRisk} /> : <span className="no-risk">无风险</span>}</article>; })}</div>
      {entries.length > pageSize ? <nav className="entry-pagination" aria-label="上下文清单分页"><span>第 {safePage + 1} / {pageCount} 页 · 共 {entries.length.toLocaleString()} 条</span><div><button type="button" disabled={safePage === 0} onClick={() => setPage((value) => Math.max(0, value - 1))}>上一页</button><button type="button" disabled={safePage >= pageCount - 1} onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}>下一页</button></div></nav> : null}
    </>
  );
}

function ScanStatus({ job, onCancel }: { job: ScanJob; onCancel: () => void }) {
  const cancellable = job.status === 'queued' || job.status === 'running';
  return (
    <section className="scan-status" aria-live="polite"><div className="scan-progress-copy"><RefreshCw className={cancellable ? 'spin' : ''} size={18} /><div><strong>{phaseLabels[job.progress.phase]} · {Math.round(job.progress.percent)}%</strong><span>{job.progress.message}</span></div>{cancellable ? <button className="secondary-button" type="button" onClick={onCancel}><Square size={14} />取消</button> : null}</div><div className="progress-track" role="progressbar" aria-label="扫描进度" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(job.progress.percent)} aria-valuetext={`${phaseLabels[job.progress.phase]} ${Math.round(job.progress.percent)}%`}><span style={{ width: `${Math.min(100, Math.max(0, job.progress.percent))}%` }} /></div></section>
  );
}

function ImportDialog({ inspection, busy, error, onClose, onConfirm }: {
  inspection: PackageInspectionResponse | null; busy: boolean; error: string; onClose: () => void; onConfirm: () => void;
}) {
  const info = inspection?.inspection;
  return (
    <Modal open={Boolean(inspection)} titleId="import-title" className="import-modal" onClose={onClose}>
      <header><div><h2 id="import-title">确认导入 Context Package</h2><p>这里只检查包内 JSON 与元数据，不访问包中声明的来源。</p></div><button className="icon-button" type="button" onClick={onClose} aria-label="关闭导入预览"><X size={20} /></button></header>
      {info ? <div className="import-body"><div className="package-hero"><span className="entry-icon knowledge"><PackageCheck size={20} /></span><div><strong>{info.name}</strong><small>schema {info.schemaVersion} · {info.kind} · {info.producer.name} {info.producer.version}</small><code className="package-id">{info.packageId}</code></div></div><dl className="package-stats"><div><dt>条目</dt><dd>{info.itemCount}</dd></div><div><dt>精确 Token</dt><dd>{info.exactTokens.toLocaleString()}</dd></div><div><dt>敏感条目</dt><dd>{info.sensitiveItemCount}</dd></div><div><dt>秘密警告</dt><dd>{info.secretWarningCount}</dd></div></dl><section className={`signature-card ${info.signatureVerification.status}`}><strong>{info.signatureVerification.status === 'valid-trusted' ? '签名可信' : info.signatureVerification.status === 'valid-untrusted' ? '签名有效，密钥未信任' : info.signatureVerification.status === 'unsigned' ? '未签名包' : '签名无效'}</strong><p>{info.signatureVerification.message}</p></section>{info.warnings.length > 0 ? <section className="import-warnings"><strong>导入提示</strong><ul>{info.warnings.map((warning) => <li key={warning}>{warning}</li>)}</ul></section> : null}{error ? <p className="error-message" role="alert"><AlertTriangle size={16} />{error}</p> : null}</div> : null}
      <footer><span><LockKeyhole size={16} />原始 JSON 不会作为文件写入项目</span><button className="primary-button" type="button" disabled={busy || info?.signatureVerification.status === 'invalid'} onClick={onConfirm}>{busy ? <RefreshCw className="spin" size={16} /> : <Import size={16} />}{busy ? '正在导入' : '确认创建本地快照'}</button></footer>
    </Modal>
  );
}

function ExportDialog({ open, format, preview, loading, error, entries, excluded, budgetMax, budgetPolicy, sign, signingAvailable, onClose, onFormat, onBudgetMax, onBudgetPolicy, onSign, onGenerate, onDownload }: {
  open: boolean; format: ExportFormat; preview: ExportPreviewResult | null; loading: boolean; error: string; entries: Entry[]; excluded: Entry[];
  budgetMax: number; budgetPolicy: BudgetPolicy; sign: boolean; signingAvailable: boolean;
  onClose: () => void; onFormat: (format: ExportFormat) => void; onBudgetMax: (value: number) => void; onBudgetPolicy: (value: BudgetPolicy) => void; onSign: (value: boolean) => void; onGenerate: () => void; onDownload: () => void;
}) {
  const budget = preview?.budget;
  const signature = preview?.signatureVerification ?? preview?.signature;
  const entriesById = useMemo(() => new Map(entries.map((entry) => [entry.id, entry])), [entries]);
  return (
    <Modal open={open} titleId="export-title" className="export-modal" onClose={onClose}>
      <header><div><h2 id="export-title">导出前完整预览</h2><p>导出固定到当前不可变快照；调整选项后请重新生成预览。</p></div><button className="icon-button" type="button" onClick={onClose} aria-label="关闭预览"><X size={20} /></button></header>
      <div className="export-scroll">
        <div className="format-tabs" role="group" aria-label="导出格式"><button type="button" aria-pressed={format === 'json'} className={format === 'json' ? 'active' : ''} onClick={() => onFormat('json')}><Box size={16} />Context Package JSON</button><button type="button" aria-pressed={format === 'agents'} className={format === 'agents' ? 'active' : ''} onClick={() => onFormat('agents')}><FileCode2 size={16} />AGENTS.md 草案</button></div>
        <div className="export-options"><label><span>Token 预算</span><input aria-label="最大 Token 预算" type="number" min="0" step="100" value={budgetMax} onChange={(event) => onBudgetMax(Math.max(0, Number(event.target.value) || 0))} /></label><SelectControl value={budgetPolicy} onChange={onBudgetPolicy} label="超限策略" options={Object.entries(policyLabels).map(([value, label]) => ({ value: value as BudgetPolicy, label }))} /><label className={`sign-toggle ${format !== 'json' || !signingAvailable ? 'disabled' : ''}`}><input type="checkbox" checked={sign && format === 'json'} disabled={format !== 'json' || !signingAvailable} onChange={(event) => onSign(event.target.checked)} /><span>Ed25519 签名</span></label><button className="secondary-button" type="button" disabled={loading} onClick={onGenerate}>{loading ? <RefreshCw className="spin" size={16} /> : <Eye size={16} />}生成精确预览</button></div>
        <div className="change-preview"><strong>本次变更预览</strong><span className="include-mark">请求包含 {preview?.budget.selectedIds.length ?? '所选'} 个条目</span><span className="exclude-mark">手动排除 {excluded.length} 个</span><span>原项目写入 0 个文件</span></div>
        {budget ? <section className={`budget-meter ${budget.exceeded ? 'over' : ''}`} role="meter" aria-label="完整导出 Token 预算" aria-valuemin={0} aria-valuemax={Math.max(1, budget.maxTokens, budget.exactTokens)} aria-valuenow={budget.exactTokens} aria-valuetext={`${budget.exactTokens} / ${budget.maxTokens} tokens，${budget.exceeded ? '已超限' : '预算内'}`}><div><strong>完整文件 {budget.exactTokens.toLocaleString()} / {budget.maxTokens.toLocaleString()} tokens</strong><span>{budget.autoTrimmed ? `已自动精简，另排除 ${budget.omittedIds.length} 个条目` : budget.exceeded ? '超出预算，请按当前策略确认' : '精确 o200k_base 计数在预算内'}</span></div><div className="progress-track"><span style={{ width: `${Math.min(100, budget.maxTokens === 0 ? 100 : (budget.exactTokens / budget.maxTokens) * 100)}%` }} /></div></section> : null}
        {budget?.autoTrimmed && budget.omittedIds.length > 0 ? (
          <section className="omitted-preview" aria-labelledby="omitted-preview-title">
            <div>
              <strong id="omitted-preview-title">自动精简排除清单（{budget.omittedIds.length}）</strong>
              <span>以下条目不会写入本次下载文件，请确认后再下载。</span>
            </div>
            <ol>
              {budget.omittedIds.map((id) => {
                const entry = entriesById.get(id);
                return (
                  <li key={id}>
                    <strong>{entry?.title ?? id}</strong>
                    <span>{entry ? <><code>{entry.source.relativePath}</code><small>{entry.source.locator}</small></> : <code>{id}</code>}</span>
                  </li>
                );
              })}
            </ol>
          </section>
        ) : null}
        {signature && signature.status !== 'unsigned' ? <p className={`signature-inline ${signature.status}`}><PackageCheck size={15} />{signature.message}</p> : null}
        {error ? <p className="error-message modal-error" role="alert"><AlertTriangle size={16} />{error}</p> : null}
        <pre className="full-preview">{loading ? '正在从当前快照生成完整预览…' : preview?.content ?? '选择预算与格式，然后生成完整预览。'}</pre>
      </div>
      <footer><span><Eye size={16} />下载内容与上方完整正文一致</span><button className="primary-button" type="button" disabled={loading || !preview || preview.budget.blocked} onClick={onDownload}><Download size={17} />确认并下载</button></footer>
    </Modal>
  );
}

export function App() {
  const [config, setConfig] = useState<ConfigResponse | null>(null);
  const [projects, setProjects] = useState<PublicProject[]>([]);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [workspace, setWorkspace] = useState<WorkspaceData | null>(null);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(() => new Set());
  const [selectedEntryId, setSelectedEntryId] = useState('');
  const [category, setCategory] = useState<'all' | Category>('all');
  const [scope, setScope] = useState<'all' | Scope>('all');
  const [risk, setRisk] = useState<'all' | 'any' | 'none' | RiskKind>('all');
  const [query, setQuery] = useState('');
  const deferredQuery = useDeferredValue(query);
  const [activeSection, setActiveSection] = useState('entries');
  const [mobileNav, setMobileNav] = useState(false);
  const [isMobileViewport, setIsMobileViewport] = useState(() => window.matchMedia('(max-width: 1120px)').matches);
  const [job, setJob] = useState<ScanJob | null>(null);
  const [error, setError] = useState('');
  const [showDiff, setShowDiff] = useState(false);
  const [inspection, setInspection] = useState<PackageInspectionResponse | null>(null);
  const [importBusy, setImportBusy] = useState(false);
  const [importError, setImportError] = useState('');
  const [exportOpen, setExportOpen] = useState(false);
  const [exportFormat, setExportFormat] = useState<ExportFormat>('json');
  const [exportPreview, setExportPreview] = useState<ExportPreviewResult | null>(null);
  const [selectionRevision, setSelectionRevision] = useState<string | null>(null);
  const [exportLoading, setExportLoading] = useState(false);
  const [exportError, setExportError] = useState('');
  const [budgetMax, setBudgetMax] = useState(16_000);
  const [budgetPolicy, setBudgetPolicy] = useState<BudgetPolicy>('warn');
  const [signExport, setSignExport] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const mobileMenuButtonRef = useRef<HTMLButtonElement>(null);
  const mobileSidebarRef = useRef<HTMLDivElement>(null);
  const pollGeneration = useRef(0);
  const exportPreviewGeneration = useRef(0);

  useEffect(() => {
    const media = window.matchMedia('(max-width: 1120px)');
    const update = () => {
      setIsMobileViewport(media.matches);
      if (!media.matches) setMobileNav(false);
    };
    update();
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);

  useEffect(() => {
    if (!isMobileViewport || !mobileNav) return undefined;
    const drawer = mobileSidebarRef.current;
    const restoreTarget = mobileMenuButtonRef.current;
    const previousBodyOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    drawer?.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.preventDefault();
        setMobileNav(false);
        return;
      }
      if (event.key !== 'Tab' || !drawer) return;
      const focusable = [...drawer.querySelectorAll<HTMLElement>(
        'a[href], button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), [tabindex]:not([tabindex="-1"])',
      )].filter((element) => !element.hidden && element.getAttribute('aria-hidden') !== 'true');
      if (focusable.length === 0) {
        event.preventDefault();
        drawer.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const activeElement = document.activeElement;
      if (activeElement === drawer || !drawer.contains(activeElement)) {
        event.preventDefault();
        (event.shiftKey ? last : first).focus();
      } else if (event.shiftKey && activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener('keydown', onKeyDown, true);
    return () => {
      document.removeEventListener('keydown', onKeyDown, true);
      document.body.style.overflow = previousBodyOverflow;
      if (window.matchMedia('(max-width: 1120px)').matches && restoreTarget?.isConnected) restoreTarget.focus();
    };
  }, [isMobileViewport, mobileNav]);

  async function refreshProjects(): Promise<void> {
    const next = await requestJson<PublicProject[]>('/api/projects');
    setProjects(next);
    setProjectsLoading(false);
  }

  useEffect(() => {
    let disposed = false;
    Promise.all([requestJson<ConfigResponse>('/api/config'), requestJson<PublicProject[]>('/api/projects')])
      .then(([nextConfig, nextProjects]) => {
        if (disposed) return;
        setMutationToken(nextConfig.csrfToken);
        setConfig(nextConfig);
        setBudgetMax(nextConfig.defaultBudget.maxTokens);
        setBudgetPolicy(nextConfig.defaultBudget.policy);
        setProjects(nextProjects);
        setProjectsLoading(false);
      })
      .catch((reason) => {
        if (disposed) return;
        setError(reason instanceof Error ? reason.message : '本地服务不可用。');
        setProjectsLoading(false);
      });
    return () => {
      disposed = true;
      pollGeneration.current += 1;
      exportPreviewGeneration.current += 1;
    };
  }, []);

  function invalidateExportPreview(resetSelectionRevision = false): void {
    exportPreviewGeneration.current += 1;
    setExportLoading(false);
    setExportPreview(null);
    setExportError('');
    if (resetSelectionRevision) setSelectionRevision(null);
  }

  function installWorkspace(next: WorkspaceData, revealDiff = false, migration?: {
    workspace: WorkspaceData;
    selectedIds: Set<string>;
  } | null): void {
    let nextSelection = new Set(next.snapshot.result.entries.map((entry) => entry.id));
    if (migration && migration.workspace.project.id === next.project.id) {
      const previouslySelectedKeys = new Set(
        migration.workspace.snapshot.result.entries
          .filter((entry) => migration.selectedIds.has(entry.id))
          .map((entry) => entry.logicalKey),
      );
      const changedKeys = new Set(next.snapshot.diff.changed.map((entry) => entry.logicalKey));
      nextSelection = new Set(
        next.snapshot.result.entries
          .filter((entry) => previouslySelectedKeys.has(entry.logicalKey) && !changedKeys.has(entry.logicalKey))
          .map((entry) => entry.id),
      );
    }
    invalidateExportPreview(true);
    setWorkspace(next);
    setSelectedIds(nextSelection);
    setSelectedEntryId(next.snapshot.result.entries[0]?.id ?? '');
    setActiveSection('entries');
    setShowDiff(revealDiff);
    setError('');
  }

  async function openProject(projectId: string): Promise<void> {
    setError('');
    try {
      const next = await requestJson<WorkspaceData>(`/api/projects/${encodeURIComponent(projectId)}`);
      installWorkspace(next);
      setMobileNav(false);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '无法打开项目快照。');
    }
  }

  async function pollJob(jobId: string, generation: number, migration?: {
    workspace: WorkspaceData;
    selectedIds: Set<string>;
  } | null): Promise<void> {
    while (pollGeneration.current === generation) {
      const next = await requestJson<ScanJob>(`/api/scans/${encodeURIComponent(jobId)}`);
      if (pollGeneration.current !== generation) return;
      setJob(next);
      if (next.status === 'completed') {
        const envelope = next.result ?? next.envelope;
        if (!envelope) throw new Error('扫描完成但缺少快照结果。');
        installWorkspace(normalizeWorkspace(envelope), true, migration);
        setJob(null);
        await refreshProjects();
        return;
      }
      if (next.status === 'partial') {
        setError('扫描达到安全上限，部分结果未覆盖已有快照。请缩小目录或调整排除规则。');
        setJob(null);
        return;
      }
      if (next.status === 'cancelled' || next.status === 'failed') {
        setError(next.error?.message ?? (next.status === 'cancelled' ? '扫描已取消，旧快照保持不变。' : '扫描失败，旧快照保持不变。'));
        setJob(null);
        return;
      }
      await new Promise((resolve) => window.setTimeout(resolve, 300));
    }
  }

  async function startScan(input: { path?: string; projectId?: string; baseSnapshotId?: string }): Promise<void> {
    setError('');
    const generation = pollGeneration.current + 1;
    pollGeneration.current = generation;
    const migration = input.projectId && workspace?.project.id === input.projectId
      ? { workspace, selectedIds: new Set(selectedIds) }
      : null;
    try {
      const created = await postJson<{ jobId: string }>('/api/scans', input);
      const initial: ScanJob = {
        id: created.jobId,
        status: 'queued',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        progress: { phase: 'discover', processed: 0, total: null, percent: 0, message: '扫描任务已排队。' },
      };
      setJob(initial);
      await pollJob(created.jobId, generation, migration);
    } catch (reason) {
      if (pollGeneration.current === generation) {
        setJob(null);
        setError(reason instanceof Error ? reason.message : '扫描失败。');
      }
    }
  }

  async function cancelScan(): Promise<void> {
    if (!job) return;
    const jobId = job.id;
    const generation = pollGeneration.current + 1;
    pollGeneration.current = generation;
    const migration = workspace
      ? { workspace, selectedIds: new Set(selectedIds) }
      : null;
    try {
      const cancelling = await requestJson<ScanJob>(`/api/scans/${encodeURIComponent(jobId)}`, { method: 'DELETE' });
      if (pollGeneration.current !== generation) return;
      setJob(cancelling);
      if (cancelling.status === 'queued' || cancelling.status === 'running') {
        setError('取消请求已发送；若任务已进入原子保存，将继续等待真实完成状态。');
      }
      await pollJob(jobId, generation, migration);
    } catch (reason) {
      if (pollGeneration.current === generation) setError(reason instanceof Error ? reason.message : '无法取消扫描。');
    }
  }

  async function inspectPackage(event: ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    setError(''); setImportError('');
    try {
      if (file.size > 5 * 1024 * 1024) throw new Error('Context Package 超过 5 MB 客户端上限。');
      const raw = await file.text();
      const next = await requestJson<PackageInspectionResponse>('/api/packages/inspect', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: raw,
      });
      setInspection(next);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '无法检查 Context Package。');
    }
  }

  async function confirmImport(): Promise<void> {
    if (!inspection) return;
    setImportBusy(true); setImportError('');
    try {
      const envelope = await postJson<CompletionEnvelope>('/api/packages/import', { inspectionId: inspection.inspectionId });
      setInspection(null);
      installWorkspace(normalizeWorkspace(envelope), true);
      await refreshProjects();
    } catch (reason) {
      setImportError(reason instanceof Error ? reason.message : '导入失败。');
    } finally { setImportBusy(false); }
  }

  const result = workspace?.snapshot.result ?? null;
  const risksById = useMemo(() => new Map(result?.risks.map((item) => [item.id, item]) ?? []), [result]);
  const filteredEntries = useMemo(() => {
    if (!result) return [];
    const normalizedQuery = deferredQuery.trim().toLowerCase();
    return result.entries.filter((entry) => {
      const entryRisks = entry.riskIds.map((id) => risksById.get(id)).filter((item): item is Risk => Boolean(item));
      return (category === 'all' || entry.category === category)
        && (scope === 'all' || entry.scope === scope)
        && (risk === 'all' || (risk === 'any' ? entryRisks.length > 0 : risk === 'none' ? entryRisks.length === 0 : entryRisks.some((item) => item.kind === risk)))
        && (!normalizedQuery || `${entry.title} ${entry.summary} ${entry.content} ${entry.source.relativePath}`.toLowerCase().includes(normalizedQuery));
    });
  }, [result, deferredQuery, category, scope, risk, risksById]);
  const selectedEntries = useMemo(() => result?.entries.filter((entry) => selectedIds.has(entry.id)) ?? [], [result, selectedIds]);
  const selectedEntry = result?.entries.find((entry) => entry.id === selectedEntryId);
  const selectedRisks = selectedEntry?.riskIds.map((id) => risksById.get(id)).filter((item): item is Risk => Boolean(item)) ?? [];
  const allVisibleSelected = filteredEntries.length > 0 && filteredEntries.every((entry) => selectedIds.has(entry.id));
  const someVisibleSelected = filteredEntries.some((entry) => selectedIds.has(entry.id));
  const signingAvailable = config?.signing.available
    ?? config?.signing.enabled
    ?? Boolean(config?.signing.keyId || config?.signing.algorithm);

  function toggleVisible(): void {
    invalidateExportPreview(true);
    setSelectedIds((previous) => {
      const next = new Set(previous);
      if (allVisibleSelected) filteredEntries.forEach((entry) => next.delete(entry.id));
      else filteredEntries.forEach((entry) => next.add(entry.id));
      return next;
    });
  }

  function toggleEntry(id: string): void {
    invalidateExportPreview(true);
    setSelectedIds((previous) => { const next = new Set(previous); if (next.has(id)) next.delete(id); else next.add(id); return next; });
  }

  function navigate(section: string): void {
    setActiveSection(section); setMobileNav(false);
    if (section === 'rules') document.getElementById('scan-rules')?.scrollIntoView({ behavior: 'smooth' });
    else if (section === 'risks') {
      setCategory('all'); setScope('all'); setQuery(''); setRisk('any');
      const firstRiskyEntry = result?.entries.find((entry) => entry.riskIds.length > 0);
      if (firstRiskyEntry) setSelectedEntryId(firstRiskyEntry.id);
      document.getElementById('context-list')?.scrollIntoView({ behavior: 'smooth' });
    }
    else if (section === 'export') openExport('json');
    else document.getElementById('context-list')?.scrollIntoView({ behavior: 'smooth' });
  }

  function openExport(format: ExportFormat): void {
    invalidateExportPreview();
    setExportFormat(format);
    setSignExport(format === 'json' && signExport);
    setExportOpen(true);
  }

  async function generatePreview(): Promise<void> {
    if (!workspace) return;
    const generation = exportPreviewGeneration.current + 1;
    exportPreviewGeneration.current = generation;
    setExportLoading(true); setExportError(''); setExportPreview(null);
    try {
      const preview = await postJson<ExportPreviewResult>('/api/export', {
        projectId: workspace.project.id,
        snapshotId: workspace.snapshot.metadata.id,
        selectedIds: [...selectedIds],
        format: exportFormat,
        budget: { maxTokens: budgetMax, policy: budgetPolicy },
        selectionRevision,
        sign: exportFormat === 'json' && signExport,
      });
      if (exportPreviewGeneration.current !== generation) return;
      setExportPreview(preview);
      setSelectionRevision(preview.selectionRevision ?? preview.budget.selectionRevision);
    } catch (reason) {
      if (exportPreviewGeneration.current !== generation) return;
      if (reason instanceof ApiError && reason.code === 'TOKEN_BUDGET_EXCEEDED') setExportError(`完整导出已被预算策略阻止：${reason.message}`);
      else if (reason instanceof ApiError && reason.code === 'STALE_SELECTION') setExportError(`当前选择已变化：${reason.message} 请重新生成预览。`);
      else setExportError(reason instanceof Error ? reason.message : '无法生成导出预览。');
    } finally {
      if (exportPreviewGeneration.current === generation) setExportLoading(false);
    }
  }

  function downloadPreview(): void {
    if (!exportPreview) return;
    const blob = new Blob([exportPreview.content], { type: exportPreview.mediaType });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url; anchor.download = exportPreview.filename; anchor.click();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
  }

  if (!config) return <div className="loading-screen"><RefreshCw className="spin" /><p>{error || '正在连接本地服务…'}</p></div>;
  const busy = Boolean(job && (job.status === 'queued' || job.status === 'running'));

  return (
    <div className="app-shell">
      <header className="topbar"><div className="brand"><span><Archive size={20} /></span><strong>Context Hub</strong></div><div className="local-status"><span className="status-dot green" />本地运行 · 不上传文件</div>{workspace ? <button ref={mobileMenuButtonRef} className="mobile-menu" type="button" onClick={() => setMobileNav((value) => !value)} aria-label={mobileNav ? '关闭工作台导航' : '打开工作台导航'} aria-expanded={mobileNav} aria-controls="workspace-sidebar">{mobileNav ? <X /> : <Menu />}</button> : null}</header>
      <input ref={fileInputRef} hidden aria-hidden="true" tabIndex={-1} type="file" accept="application/json,.json" onChange={inspectPackage} />
      {!workspace ? <SetupView initialPath={config.samplePath} rules={config.rules ?? DEFAULT_RULES} projects={projects} projectsLoading={projectsLoading} busy={busy} job={job} error={error} onScan={(path) => void startScan({ path })} onCancel={() => void cancelScan()} onImport={() => fileInputRef.current?.click()} onOpenProject={(id) => void openProject(id)} /> : (
        <div className="workspace-shell">
          <div className={mobileNav ? 'mobile-sidebar open' : 'mobile-sidebar'} aria-hidden="true" onClick={() => setMobileNav(false)} />
          <div
            ref={mobileSidebarRef}
            id="workspace-sidebar"
            className={mobileNav ? 'sidebar-wrap open' : 'sidebar-wrap'}
            role={isMobileViewport ? 'dialog' : undefined}
            aria-modal={isMobileViewport && mobileNav ? true : undefined}
            aria-label={isMobileViewport ? '工作台导航抽屉' : undefined}
            aria-hidden={isMobileViewport ? !mobileNav : undefined}
            inert={isMobileViewport && !mobileNav ? true : undefined}
            tabIndex={isMobileViewport ? -1 : undefined}
          >
            <Sidebar workspace={workspace} projects={projects} active={activeSection} onActive={navigate} onOpenProject={(id) => void openProject(id)} onReset={() => { invalidateExportPreview(true); setExportOpen(false); setWorkspace(null); setError(''); setMobileNav(false); }} />
          </div>
          <main className="workspace" aria-hidden={isMobileViewport && mobileNav ? true : undefined} inert={isMobileViewport && mobileNav ? true : undefined}>
            <header className="workspace-header"><div><h1>项目上下文清单</h1><p>快照 {workspace.snapshot.metadata.id.slice(-12)} · {formatDate(workspace.snapshot.metadata.capturedAt, true)}</p></div><div className="header-actions"><button className="secondary-button import-button" type="button" onClick={() => fileInputRef.current?.click()}><Import size={17} />导入</button><button className="secondary-button" type="button" disabled={busy || workspace.project.sourceKind !== 'local-project'} title={workspace.project.sourceKind !== 'local-project' ? '导入包是不可变来源，请重新导入新包' : undefined} onClick={() => void startScan({ projectId: workspace.project.id, baseSnapshotId: workspace.snapshot.metadata.id })}><RefreshCw className={busy ? 'spin' : ''} size={17} />刷新快照</button><button className="primary-button" type="button" onClick={() => openExport('json')}><Eye size={17} />预览导出</button></div></header>
            {job ? <ScanStatus job={job} onCancel={() => void cancelScan()} /> : null}
            {showDiff ? <DiffBanner diff={workspace.snapshot.diff} onDismiss={() => setShowDiff(false)} /> : null}
            <HealthStrip result={workspace.snapshot.result} selectedEntries={selectedEntries} budget={budgetMax} />
            {error ? <p className="error-message workspace-error" role="alert"><AlertTriangle size={16} />{error}</p> : null}
            <div className="content-columns" id="context-list">
              <section className="manifest">
                <div className="filters"><SelectControl value={category} onChange={setCategory} label="类型" options={[{ value: 'all', label: '全部' }, ...Object.entries(categoryLabels).map(([value, label]) => ({ value: value as Category, label }))]} /><SelectControl value={scope} onChange={setScope} label="作用域" options={[{ value: 'all', label: '全部' }, ...Object.entries(scopeLabels).map(([value, label]) => ({ value: value as Scope, label }))]} /><SelectControl value={risk} onChange={setRisk} label="风险" options={[{ value: 'all', label: '全部' }, { value: 'any', label: '有风险' }, { value: 'none', label: '无风险' }, ...Object.entries(riskLabels).map(([value, label]) => ({ value: value as RiskKind, label }))]} /><label className="search-box"><Search size={16} /><span className="visually-hidden">搜索条目或来源</span><input aria-label="搜索条目或来源" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="搜索条目或来源" /></label></div>
                <EntryTable entries={filteredEntries} risksById={risksById} selectedIds={selectedIds} activeId={selectedEntryId} allSelected={allVisibleSelected} someSelected={someVisibleSelected} onToggleVisible={toggleVisible} onToggle={toggleEntry} onInspect={setSelectedEntryId} />
                {filteredEntries.length === 0 ? <div className="empty-filter"><Search size={25} /><p>当前筛选没有匹配条目。</p></div> : null}
                <div className="selection-bar"><div><strong>已选择 {selectedIds.size}/{workspace.snapshot.result.entries.length} 个条目</strong><small>条目正文精确计数 {selectedEntries.reduce((sum, entry) => sum + entry.tokenCount, 0).toLocaleString()} tokens；完整导出以预览计数为准。</small></div><button className="secondary-button" type="button" onClick={() => openExport('json')}><Box size={16} />Context Package JSON</button><button className="primary-button" type="button" onClick={() => openExport('agents')}><FileCode2 size={16} />AGENTS.md 草案</button></div>
              </section>
              <Inspector entry={selectedEntry} risks={selectedRisks} onSelectEntry={setSelectedEntryId} />
            </div>
            <div id="scan-rules"><RulesPanel rules={workspace.snapshot.result.rules} compact /></div>
          </main>
        </div>
      )}
      <ImportDialog inspection={inspection} busy={importBusy} error={importError} onClose={() => { if (!importBusy) { setInspection(null); setImportError(''); } }} onConfirm={() => void confirmImport()} />
      {workspace ? <ExportDialog open={exportOpen} format={exportFormat} preview={exportPreview} loading={exportLoading} error={exportError} entries={workspace.snapshot.result.entries} excluded={workspace.snapshot.result.entries.filter((entry) => !selectedIds.has(entry.id))} budgetMax={budgetMax} budgetPolicy={budgetPolicy} sign={signExport} signingAvailable={signingAvailable} onClose={() => { invalidateExportPreview(); setExportOpen(false); }} onFormat={(format) => { invalidateExportPreview(); setExportFormat(format); if (format !== 'json') setSignExport(false); }} onBudgetMax={(value) => { invalidateExportPreview(); setBudgetMax(value); }} onBudgetPolicy={(value) => { invalidateExportPreview(); setBudgetPolicy(value); }} onSign={(value) => { invalidateExportPreview(); setSignExport(value); }} onGenerate={() => void generatePreview()} onDownload={downloadPreview} /> : null}
    </div>
  );
}
