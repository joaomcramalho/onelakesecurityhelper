export type WorkspaceRole = 'none' | 'viewer' | 'contributor' | 'member' | 'admin'

export type RequestedAction =
  | 'open-lakehouse'
  | 'read-onelake'
  | 'query-sql'
  | 'write-spark'
  | 'write-sql'
  | 'reshare-manage'

export type Verdict = 'allowed' | 'denied' | 'filtered' | 'blocked'

export interface PermissionConfig {
  authenticated: boolean
  fabricEnabled: boolean
  workspaceRole: WorkspaceRole
  viaGroup: boolean
  itemRead: boolean
  readData: boolean
  readAll: boolean
  itemWrite: boolean
  reshare: boolean
  oneLakeRead: boolean
  oneLakeReadWrite: boolean
  defaultReader: boolean
  rowFilter: boolean
  hiddenColumns: boolean
  sqlAccessMode: 'user' | 'delegated'
  delegatedOwnerAccess: boolean
  sqlSelect: boolean
  sqlWrite: boolean
  sqlDenySelect: boolean
  sqlRowFilter: boolean
  sqlHiddenColumns: boolean
  sqlMasking: boolean
  shortcut: 'none' | 'passthrough' | 'delegated'
  shortcutTargetAccess: boolean
  action: RequestedAction
}

export interface DecisionStep {
  layer: string
  status: 'pass' | 'fail' | 'info' | 'warning'
  title: string
  detail: string
  citation?: string
}

export interface EvaluationResult {
  verdict: Verdict
  title: string
  summary: string
  steps: DecisionStep[]
  warnings: string[]
  effectiveScope?: string
  remediation?: string
}

export interface Scenario {
  id: string
  name: string
  description: string
  config: PermissionConfig
}

export const defaultConfig: PermissionConfig = {
  authenticated: true,
  fabricEnabled: true,
  workspaceRole: 'viewer',
  viaGroup: false,
  itemRead: false,
  readData: true,
  readAll: false,
  itemWrite: false,
  reshare: false,
  oneLakeRead: false,
  oneLakeReadWrite: false,
  defaultReader: true,
  rowFilter: false,
  hiddenColumns: false,
  sqlAccessMode: 'delegated',
  delegatedOwnerAccess: true,
  sqlSelect: true,
  sqlWrite: false,
  sqlDenySelect: false,
  sqlRowFilter: false,
  sqlHiddenColumns: false,
  sqlMasking: false,
  shortcut: 'none',
  shortcutTargetAccess: true,
  action: 'query-sql',
}
