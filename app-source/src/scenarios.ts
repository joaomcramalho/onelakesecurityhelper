import type { Scenario } from './domain'
import { defaultConfig } from './domain'

export const scenarios: Scenario[] = [
  {
    id: 'viewer-sql',
    name: 'Viewer querying SQL',
    description: 'Workspace Viewer reaches the SQL endpoint with ReadData but has no direct OneLake/Spark read.',
    config: { ...defaultConfig, action: 'query-sql' },
  },
  {
    id: 'shared-restricted',
    name: 'Sharing-only restricted reader',
    description: 'A nonmember has item Read and a scoped OneLake role with row and column restrictions.',
    config: { ...defaultConfig, workspaceRole: 'none', itemRead: true, readData: false, defaultReader: false, oneLakeRead: true, rowFilter: true, hiddenColumns: true, action: 'read-onelake' },
  },
  {
    id: 'sql-deny',
    name: 'SQL DENY, OneLake allowed',
    description: 'SQL SELECT is denied even though a OneLake role still authorizes direct data access.',
    config: { ...defaultConfig, workspaceRole: 'none', itemRead: true, readData: false, defaultReader: false, oneLakeRead: true, sqlSelect: true, sqlDenySelect: true, action: 'query-sql' },
  },
  {
    id: 'sql-user-identity',
    name: 'SQL with user identity',
    description: 'The SQL endpoint passes the signed-in user to OneLake, so a OneLake role—not SQL SELECT—controls table access.',
    config: { ...defaultConfig, workspaceRole: 'viewer', sqlAccessMode: 'user', readData: true, sqlSelect: false, oneLakeRead: true, rowFilter: true, action: 'query-sql' },
  },
  {
    id: 'group-broadening',
    name: 'Nested group broadens access',
    description: 'A group-derived Contributor role makes a custom restricted-reader role ineffective as a boundary.',
    config: { ...defaultConfig, workspaceRole: 'contributor', viaGroup: true, oneLakeRead: true, rowFilter: true, action: 'read-onelake' },
  },
  {
    id: 'scoped-write',
    name: 'Scoped OneLake write',
    description: 'A sharing-only user combines item Read with OneLake ReadWrite for Spark/OneLake writes.',
    config: { ...defaultConfig, workspaceRole: 'none', itemRead: true, readData: false, defaultReader: false, oneLakeReadWrite: true, action: 'write-spark' },
  },
  {
    id: 'shortcut-target',
    name: 'Shortcut target missing',
    description: 'The user can reach the Lakehouse but passthrough access fails at the shortcut target.',
    config: { ...defaultConfig, workspaceRole: 'viewer', shortcut: 'passthrough', shortcutTargetAccess: false, action: 'read-onelake' },
  },
  {
    id: 'reshare',
    name: 'Explicit Reshare',
    description: 'A Viewer can share an item only because an explicit Reshare permission was granted.',
    config: { ...defaultConfig, workspaceRole: 'viewer', reshare: true, action: 'reshare-manage' },
  },
]
