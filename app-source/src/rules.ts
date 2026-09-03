export const SNAPSHOT_DATE = '1 September 2026'

export const citations = {
  permissionModel: {
    id: 'permission-model',
    title: 'Permission model - Microsoft Fabric',
    url: 'https://learn.microsoft.com/en-us/fabric/security/permission-model',
    note: 'Sequential identity, Fabric access, and data-security layers; item Read does not automatically grant underlying data access.',
  },
  workspaceRoles: {
    id: 'workspace-roles',
    title: 'Roles in workspaces in Microsoft Fabric',
    url: 'https://learn.microsoft.com/en-us/fabric/fundamentals/roles-workspaces',
    note: 'Workspace capabilities, group inheritance, ReadData, ReadAll, write, sharing, and management behavior.',
  },
  lakehouseRoles: {
    id: 'lakehouse-roles',
    title: 'Workspace roles and permissions in lakehouse',
    url: 'https://learn.microsoft.com/en-us/fabric/data-engineering/workspace-roles-lakehouse',
    note: 'Admin, Member, and Contributor can perform Lakehouse CRUD; Viewer access is read-oriented.',
  },
  oneLakeModel: {
    id: 'onelake-model',
    title: 'OneLake security roles, permissions, and scopes',
    url: 'https://learn.microsoft.com/en-us/fabric/onelake/security/data-access-control-model',
    note: 'Grant-only, deny-by-default roles; Read/ReadWrite behavior; default roles; scope inheritance; shortcuts.',
  },
  oneLakeRoles: {
    id: 'onelake-roles',
    title: 'OneLake security roles: create and manage',
    url: 'https://learn.microsoft.com/en-us/fabric/onelake/security/create-manage-roles',
    note: 'Role prerequisites, DefaultReader warning, RLS/CLS, and ReadWrite limitations.',
  },
  sqlPermissions: {
    id: 'sql-permissions',
    title: 'SQL granular permissions in Fabric Data Warehouse',
    url: 'https://learn.microsoft.com/en-us/fabric/data-warehouse/sql-granular-permissions',
    note: 'Item Read or a workspace role is required to connect; SQL GRANT, REVOKE, DENY, and database roles refine SQL access.',
  },
} as const

export const ruleCards = [
  {
    title: 'Reachability comes first',
    text: 'A SQL grant cannot make an unreachable item reachable. The user first needs a workspace role or item Read permission.',
    citation: citations.sqlPermissions,
  },
  {
    title: 'Workspace access is broad',
    text: 'Admin, Member, and Contributor have broad Lakehouse CRUD capabilities. Viewer is read-oriented and does not receive OneLake/Spark ReadAll by default.',
    citation: citations.workspaceRoles,
  },
  {
    title: 'OneLake is grant-only',
    text: 'OneLake security starts with no data access and supports Grant roles, not explicit Deny roles. Multiple memberships can broaden effective access.',
    citation: citations.oneLakeModel,
  },
  {
    title: 'SQL DENY stays in SQL',
    text: 'T-SQL DENY can override SQL grants for SQL queries, but it is not a universal deny for Spark or direct OneLake access.',
    citation: citations.sqlPermissions,
  },
  {
    title: 'ReadWrite has limits',
    text: 'OneLake ReadWrite applies to users who have item Read and cannot be combined with OneLake row- or column-level restrictions.',
    citation: citations.oneLakeModel,
  },
  {
    title: 'Shortcuts have two sides',
    text: 'Passthrough access is constrained by permissions at the shortcut and target. Delegated shortcuts use a configured target identity.',
    citation: citations.oneLakeModel,
  },
] as const
