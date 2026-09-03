import { useMemo, useState } from 'react'
import {
  BookOpen, Check, ChevronRight, CircleAlert, Database, ExternalLink, Eye,
  FileKey, FlaskConical, GitBranch, KeyRound, LockKeyhole, RotateCcw,
  Settings2, ShieldCheck, Users, X,
} from 'lucide-react'
import './index.css'
import { defaultConfig, type PermissionConfig, type RequestedAction, type WorkspaceRole } from './domain'
import { evaluateAccess } from './evaluator'
import { citations, ruleCards, SNAPSHOT_DATE } from './rules'
import { scenarios } from './scenarios'

type Page = 'overview' | 'simulator' | 'scenarios' | 'rules' | 'references'
type TestTarget = 'onelake' | 'sql' | 'shortcut'

const pages: { id: Page; label: string; icon: typeof ShieldCheck }[] = [
  { id: 'overview', label: 'Overview', icon: ShieldCheck },
  { id: 'simulator', label: 'Simulator', icon: Settings2 },
  { id: 'scenarios', label: 'Scenario Lab', icon: FlaskConical },
  { id: 'rules', label: 'Rules & caveats', icon: FileKey },
  { id: 'references', label: 'References', icon: BookOpen },
]

const actions: { value: RequestedAction; label: string }[] = [
  { value: 'open-lakehouse', label: 'Open the Lakehouse' },
  { value: 'read-onelake', label: 'Read through OneLake' },
  { value: 'query-sql', label: 'Query the SQL endpoint' },
  { value: 'write-spark', label: 'Write through Spark/OneLake' },
  { value: 'write-sql', label: 'Write through SQL endpoint' },
  { value: 'reshare-manage', label: 'Reshare or manage permissions' },
]

const targetActions: Record<TestTarget, RequestedAction[]> = {
  onelake: ['open-lakehouse', 'read-onelake', 'write-spark', 'reshare-manage'],
  sql: ['query-sql', 'write-sql'],
  shortcut: ['read-onelake', 'query-sql'],
}

const roleLabels: Record<WorkspaceRole, string> = {
  none: 'No workspace role',
  viewer: 'Viewer',
  contributor: 'Contributor',
  member: 'Member',
  admin: 'Admin',
}

function Toggle({ checked, onChange, label, description }: {
  checked: boolean
  onChange: (checked: boolean) => void
  label: string
  description?: string
}) {
  return (
    <label className="toggle-row">
      <span>
        <strong>{label}</strong>
        {description && <small>{description}</small>}
      </span>
      <input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} />
      <span className="switch" aria-hidden="true"><span /></span>
    </label>
  )
}

function App() {
  const [page, setPage] = useState<Page>('overview')
  const [config, setConfig] = useState<PermissionConfig>(defaultConfig)
  const evaluation = useMemo(() => evaluateAccess(config), [config])
  const set = <K extends keyof PermissionConfig>(key: K, value: PermissionConfig[K]) =>
    setConfig((current) => ({ ...current, [key]: value }))
  const loadScenario = (scenarioConfig: PermissionConfig) => {
    setConfig(scenarioConfig)
    setPage('simulator')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><LockKeyhole size={22} /></div>
          <div><strong>OneLake Security</strong><span>Effective access explorer</span></div>
        </div>
        <nav aria-label="Primary navigation">
          {pages.map((item) => {
            const Icon = item.icon
            return (
              <button key={item.id} className={page === item.id ? 'nav-item active' : 'nav-item'} onClick={() => setPage(item.id)}>
                <Icon size={18} /><span>{item.label}</span>
              </button>
            )
          })}
        </nav>
        <div className="snapshot-card">
          <span className="eyebrow">Rules snapshot</span>
          <strong>{SNAPSHOT_DATE}</strong>
          <small>Educational model based on linked Microsoft Learn documentation.</small>
        </div>
      </aside>

      <main>
        <header className="topbar">
          <div>
            <span className="eyebrow">Microsoft Fabric</span>
            <h1>{pages.find((item) => item.id === page)?.label}</h1>
          </div>
          <button className="primary-button" onClick={() => setPage('simulator')}>
            Test permissions <ChevronRight size={17} />
          </button>
        </header>
        {page === 'overview' && <Overview onSimulate={() => setPage('simulator')} />}
        {page === 'simulator' && <Simulator config={config} set={set} reset={() => setConfig(defaultConfig)} evaluation={evaluation} />}
        {page === 'scenarios' && <ScenarioLab loadScenario={loadScenario} />}
        {page === 'rules' && <RulesPage />}
        {page === 'references' && <ReferencesPage />}
      </main>
    </div>
  )
}

function Overview({ onSimulate }: { onSimulate: () => void }) {
  const layers = [
    { icon: Users, title: '1. Entra identity', text: 'Authentication and direct or group-derived assignments.' },
    { icon: KeyRound, title: '2. Fabric reachability', text: 'Workspace role or item Read makes the Lakehouse reachable.' },
    { icon: Database, title: '3. Data authorization', text: 'OneLake roles or SQL permissions authorize the selected path.' },
    { icon: Eye, title: '4. Effective scope', text: 'Table, folder, row, column, shortcut, and action constraints.' },
  ]
  return (
    <section className="page-content">
      <div className="hero-card">
        <div>
          <span className="eyebrow">Permission dependencies, made visible</span>
          <h2>Access is a chain, not a single checkbox.</h2>
          <p>See how identity, workspace roles, sharing, OneLake roles, SQL permissions, and shortcuts combine into an effective decision.</p>
          <button className="primary-button" onClick={onSimulate}>Open the simulator <ChevronRight size={17} /></button>
        </div>
        <div className="mini-result">
          <div className="mini-result-icon"><ShieldCheck size={28} /></div>
          <span>Example result</span><strong>Filtered access</strong>
          <p>Can query Sales through SQL, limited to EMEA rows and approved columns.</p>
        </div>
      </div>
      <div className="section-heading">
        <span className="eyebrow">Authorization flow</span>
        <h2>Every request passes through ordered gates</h2>
      </div>
      <div className="flow-grid">
        {layers.map((layer, index) => {
          const Icon = layer.icon
          return (
            <div className="flow-card" key={layer.title}>
              <div className="flow-number"><Icon size={20} /></div>
              <h3>{layer.title}</h3><p>{layer.text}</p>
              {index < layers.length - 1 && <ChevronRight className="flow-arrow" size={20} aria-hidden="true" />}
            </div>
          )
        })}
      </div>
      <div className="two-column">
        <article className="content-card">
          <div className="card-icon"><GitBranch size={20} /></div>
          <div><h3>Grants are often additive</h3><p>A direct assignment, workspace role, sharing grant, or nested group can broaden access. Removing only one path may not remove effective access.</p></div>
        </article>
        <article className="content-card">
          <div className="card-icon"><CircleAlert size={20} /></div>
          <div><h3>Controls are path-specific</h3><p>A SQL DENY can block SQL while a OneLake role still permits Spark or API access. Always evaluate the engine used for the request.</p></div>
        </article>
      </div>
    </section>
  )
}

function Simulator({ config, set, reset, evaluation }: {
  config: PermissionConfig
  set: <K extends keyof PermissionConfig>(key: K, value: PermissionConfig[K]) => void
  reset: () => void
  evaluation: ReturnType<typeof evaluateAccess>
}) {
  const activeTarget: TestTarget = config.shortcut !== 'none'
    ? 'shortcut'
    : config.action === 'query-sql' || config.action === 'write-sql'
      ? 'sql'
      : 'onelake'
  const availableActions = actions.filter((action) => targetActions[activeTarget].includes(action.value))
  const switchTarget = (target: TestTarget) => {
    if (target === 'onelake') {
      set('shortcut', 'none')
      if (!targetActions.onelake.includes(config.action)) set('action', 'read-onelake')
    } else if (target === 'sql') {
      set('shortcut', 'none')
      if (!targetActions.sql.includes(config.action)) set('action', 'query-sql')
    } else {
      if (config.shortcut === 'none') set('shortcut', 'passthrough')
      if (!targetActions.shortcut.includes(config.action)) set('action', 'read-onelake')
    }
  }

  return (
    <section className="page-content simulator-layout">
      <div className="config-panel">
        <div className="panel-heading">
          <div><span className="eyebrow">Principal configuration</span><h2>Set the effective grants</h2></div>
          <button className="icon-button" onClick={reset} title="Reset simulator"><RotateCcw size={17} /></button>
        </div>
        <div className="field-group">
          <h3>What are you testing?</h3>
          <div className="target-switcher" role="group" aria-label="Access path to test">
            <button type="button" className={activeTarget === 'onelake' ? 'target-button active' : 'target-button'} onClick={() => switchTarget('onelake')} aria-pressed={activeTarget === 'onelake'}>
              <Database size={18} />
              <span><strong>OneLake</strong><small>Files, tables, Spark</small></span>
            </button>
            <button type="button" className={activeTarget === 'sql' ? 'target-button active' : 'target-button'} onClick={() => switchTarget('sql')} aria-pressed={activeTarget === 'sql'}>
              <FileKey size={18} />
              <span><strong>SQL endpoint</strong><small>T-SQL permissions</small></span>
            </button>
            <button type="button" className={activeTarget === 'shortcut' ? 'target-button active' : 'target-button'} onClick={() => switchTarget('shortcut')} aria-pressed={activeTarget === 'shortcut'}>
              <GitBranch size={18} />
              <span><strong>Shortcut</strong><small>Source and target</small></span>
            </button>
          </div>
          <label className="select-label">Action to evaluate
            <select value={config.action} onChange={(event) => set('action', event.target.value as RequestedAction)}>
              {availableActions.map((action) => <option key={action.value} value={action.value}>{action.label}</option>)}
            </select>
          </label>
        </div>
        <div className="field-group">
          <h3>Identity and workspace</h3>
          <Toggle checked={config.authenticated} onChange={(value) => set('authenticated', value)} label="Entra authentication succeeds" />
          <Toggle checked={config.fabricEnabled} onChange={(value) => set('fabricEnabled', value)} label="Fabric access enabled" />
          <Toggle checked={config.viaGroup} onChange={(value) => set('viaGroup', value)} label="Permissions include group-derived grants" description="Includes nested group membership." />
          <label className="select-label">Workspace role
            <select value={config.workspaceRole} onChange={(event) => set('workspaceRole', event.target.value as WorkspaceRole)}>
              {Object.entries(roleLabels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </label>
        </div>
        <div className="field-group">
          <h3>Item and sharing</h3>
          <Toggle checked={config.itemRead} onChange={(value) => set('itemRead', value)} label="Item Read" description="Makes the Lakehouse or SQL endpoint reachable." />
          <Toggle checked={config.readData} onChange={(value) => set('readData', value)} label="ReadData" description="Read through SQL/TDS." />
          <Toggle checked={config.readAll} onChange={(value) => set('readAll', value)} label="ReadAll" description="Read through OneLake APIs and Spark." />
          <Toggle checked={config.itemWrite} onChange={(value) => set('itemWrite', value)} label="Item Write" />
          <Toggle checked={config.reshare} onChange={(value) => set('reshare', value)} label="Explicit Reshare" />
        </div>
        <div className={activeTarget === 'onelake' || activeTarget === 'shortcut' ? 'field-group relevant-group' : 'field-group muted-group'}>
          <h3>OneLake security</h3>
          <Toggle checked={config.defaultReader} onChange={(value) => set('defaultReader', value)} label="DefaultReader role exists" />
          <Toggle checked={config.oneLakeRead} onChange={(value) => set('oneLakeRead', value)} label="Scoped OneLake Read role" />
          <Toggle checked={config.oneLakeReadWrite} onChange={(value) => set('oneLakeReadWrite', value)} label="Scoped OneLake ReadWrite role" />
          <Toggle checked={config.rowFilter} onChange={(value) => set('rowFilter', value)} label="Row filter applies" />
          <Toggle checked={config.hiddenColumns} onChange={(value) => set('hiddenColumns', value)} label="Columns are hidden" />
        </div>
        <div className={activeTarget === 'sql' || (activeTarget === 'shortcut' && config.action === 'query-sql') ? 'field-group relevant-group' : 'field-group muted-group'}>
          <h3>SQL authorization</h3>
          <Toggle checked={config.sqlSelect} onChange={(value) => set('sqlSelect', value)} label="SQL GRANT SELECT" />
          <Toggle checked={config.sqlWrite} onChange={(value) => set('sqlWrite', value)} label="SQL write grant" description="Shown for comparison; Lakehouse SQL endpoint writes remain unavailable." />
          <Toggle checked={config.sqlDenySelect} onChange={(value) => set('sqlDenySelect', value)} label="SQL DENY SELECT" />
        </div>
        <div className={activeTarget === 'shortcut' ? 'field-group relevant-group' : 'field-group muted-group'}>
          <h3>Shortcut</h3>
          <label className="select-label">Shortcut mode
            <select value={config.shortcut} onChange={(event) => set('shortcut', event.target.value as PermissionConfig['shortcut'])}>
              <option value="none">No shortcut</option>
              <option value="passthrough">Passthrough identity</option>
              <option value="delegated">Delegated identity</option>
            </select>
          </label>
          {config.shortcut !== 'none' && <Toggle checked={config.shortcutTargetAccess} onChange={(value) => set('shortcutTargetAccess', value)} label="Target identity has access" />}
        </div>
      </div>

      <div className="result-column">
        <div className={`result-card verdict-${evaluation.verdict}`}>
          <div className="result-topline"><span className="verdict-pill">{evaluation.verdict}</span><span>Live effective-access result</span></div>
          <div className="result-title-row">
            <div className="result-icon">{evaluation.verdict === 'allowed' || evaluation.verdict === 'filtered' ? <Check size={25} /> : <X size={25} />}</div>
            <div><h2>{evaluation.title}</h2><p>{evaluation.summary}</p></div>
          </div>
          {evaluation.effectiveScope && <div className="scope-box"><strong>Effective scope</strong><span>{evaluation.effectiveScope}</span></div>}
        </div>
        <div className="trace-card">
          <div className="panel-heading"><div><span className="eyebrow">Decision trace</span><h2>Why this result?</h2></div></div>
          <div className="trace-list">
            {evaluation.steps.map((step, index) => {
              const source = Object.values(citations).find((citation) => citation.id === step.citation)
              return (
                <div className={`trace-step trace-${step.status}`} key={`${step.layer}-${index}`}>
                  <div className="trace-marker">{step.status === 'pass' ? <Check size={15} /> : step.status === 'fail' ? <X size={15} /> : <CircleAlert size={15} />}</div>
                  <div>
                    <span>{step.layer}</span><strong>{step.title}</strong><p>{step.detail}</p>
                    {source && <a href={source.url} target="_blank" rel="noreferrer">View source <ExternalLink size={13} /></a>}
                  </div>
                </div>
              )
            })}
          </div>
        </div>
        {(evaluation.warnings.length > 0 || evaluation.remediation) && (
          <div className="advice-card">
            {evaluation.warnings.map((warning) => <div className="advice-row" key={warning}><CircleAlert size={17} /><span>{warning}</span></div>)}
            {evaluation.remediation && <div className="advice-row remediation"><ShieldCheck size={17} /><span><strong>Least-privilege next step:</strong> {evaluation.remediation}</span></div>}
          </div>
        )}
      </div>
    </section>
  )
}

function ScenarioLab({ loadScenario }: { loadScenario: (config: PermissionConfig) => void }) {
  return (
    <section className="page-content">
      <div className="intro-copy"><span className="eyebrow">Preset configurations</span><h2>Learn from common permission patterns</h2><p>Each scenario opens in the simulator so you can change one grant at a time and watch the decision trace update.</p></div>
      <div className="scenario-grid">
        {scenarios.map((scenario) => {
          const preview = evaluateAccess(scenario.config)
          return (
            <article className="scenario-card" key={scenario.id}>
              <div className="scenario-topline"><span className={`status-dot dot-${preview.verdict}`} /><span>{preview.verdict}</span></div>
              <h3>{scenario.name}</h3><p>{scenario.description}</p>
              <div className="scenario-action"><strong>{actions.find((action) => action.value === scenario.config.action)?.label}</strong></div>
              <button className="secondary-button" onClick={() => loadScenario(scenario.config)}>Explore scenario <ChevronRight size={16} /></button>
            </article>
          )
        })}
      </div>
    </section>
  )
}

function RulesPage() {
  return (
    <section className="page-content">
      <div className="intro-copy"><span className="eyebrow">Rules snapshot</span><h2>Six ideas prevent most access surprises</h2><p>These rules describe effective authorization for the modeled Lakehouse paths. Follow each source before using the model for a production decision.</p></div>
      <div className="rules-grid">
        {ruleCards.map((rule, index) => (
          <article className="rule-card" key={rule.title}>
            <span className="rule-index">0{index + 1}</span><h3>{rule.title}</h3><p>{rule.text}</p>
            <a href={rule.citation.url} target="_blank" rel="noreferrer">{rule.citation.title} <ExternalLink size={13} /></a>
          </article>
        ))}
      </div>
      <div className="caveat-card"><CircleAlert size={22} /><div><h3>Boundary of this simulator</h3><p>It does not connect to a tenant, resolve live Entra memberships, inspect sensitivity policies, or reproduce every engine limitation. Unsupported combinations are surfaced as blocked rather than guessed.</p></div></div>
    </section>
  )
}

function ReferencesPage() {
  return (
    <section className="page-content">
      <div className="intro-copy"><span className="eyebrow">Reviewed {SNAPSHOT_DATE}</span><h2>Authoritative source map</h2><p>The evaluator is an educational interpretation of these Microsoft Learn pages. Product behavior and documentation can change after the review date.</p></div>
      <div className="reference-list">
        {Object.values(citations).map((citation) => (
          <a className="reference-card" href={citation.url} target="_blank" rel="noreferrer" key={citation.id}>
            <div className="reference-icon"><BookOpen size={20} /></div>
            <div><h3>{citation.title}</h3><p>{citation.note}</p><span>learn.microsoft.com <ExternalLink size={13} /></span></div>
          </a>
        ))}
      </div>
      <div className="glossary-card">
        <h2>Glossary</h2>
        <dl>
          <div><dt>Read</dt><dd>See an item and its metadata. It is also the minimum prerequisite for connecting to a SQL endpoint when no workspace role applies.</dd></div>
          <div><dt>ReadData</dt><dd>Read Lakehouse or Warehouse data through the SQL/TDS endpoint.</dd></div>
          <div><dt>ReadAll</dt><dd>Read Lakehouse data through OneLake APIs and Spark; can feed DefaultReader virtual membership.</dd></div>
          <div><dt>OneLake ReadWrite</dt><dd>Scoped OneLake read and write capability for an item reader; it cannot contain OneLake RLS or CLS.</dd></div>
          <div><dt>Reshare</dt><dd>Permission to share an item onward without granting full workspace administration.</dd></div>
        </dl>
      </div>
    </section>
  )
}

export default App
