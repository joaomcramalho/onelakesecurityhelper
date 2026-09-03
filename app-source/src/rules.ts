export const SNAPSHOT_DATE = '3 September 2026'

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
  sqlAccessModes: {
    id: 'sql-access-modes',
    title: 'OneLake Security for SQL analytics endpoints',
    url: 'https://learn.microsoft.com/en-us/fabric/onelake/security/sql-analytics-endpoint-onelake-security',
    note: 'User identity mode enforces OneLake roles for tables; delegated identity mode uses SQL security and the item owner identity for OneLake access.',
  },
  directLakeSecurity: {
    id: 'direct-lake-security',
    title: 'Integrate Direct Lake Security',
    url: 'https://learn.microsoft.com/en-us/fabric/fundamentals/direct-lake-security-integration',
    note: 'Direct Lake on OneLake permission requirements, SSO and fixed identities, owner framing access, shortcuts, and layered OLS/RLS.',
  },
  semanticModelPermissions: {
    id: 'semantic-model-permissions',
    title: 'Semantic model permissions',
    url: 'https://learn.microsoft.com/en-us/power-bi/connect-data/service-datasets-permissions',
    note: 'Read, Build, Reshare, Write, and Owner capabilities; workspace inheritance; metadata access; and interaction with semantic-model RLS.',
  },
  readSecuredData: {
    id: 'read-secured-data',
    title: 'Read data secured with OneLake security',
    url: 'https://learn.microsoft.com/en-us/fabric/onelake/security/read-secured-data',
    note: 'Direct Lake on OneLake is an authorized engine that enforces OneLake row-level and column-level security.',
  },
  semanticModelRls: {
    id: 'semantic-model-rls',
    title: 'Row-level security with Power BI',
    url: 'https://learn.microsoft.com/en-us/fabric/security/service-admin-row-level-security',
    note: 'Semantic-model RLS role behavior and the elevated workspace roles for which model RLS is not enforced.',
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
    text: 'T-SQL DENY applies to table access in delegated identity mode. User identity mode instead uses OneLake roles for table authorization.',
    citation: citations.sqlAccessModes,
  },
  {
    title: 'SQL endpoints have two identities',
    text: 'User identity mode passes the signed-in user to OneLake. Delegated mode authorizes the user in SQL, then reads OneLake using the endpoint owner identity.',
    citation: citations.sqlAccessModes,
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
  {
    title: 'Model and source access are separate',
    text: 'Report or semantic-model Read makes the model reachable, but Direct Lake SSO also requires the current user to reach and read the source data.',
    citation: citations.directLakeSecurity,
  },
  {
    title: 'The connection chooses the source identity',
    text: 'SSO checks the current user at OneLake. A fixed cloud-connection identity lets consumers query the model without direct source access.',
    citation: citations.directLakeSecurity,
  },
  {
    title: 'OneLake and model rules intersect',
    text: 'OneLake roles are unioned first, then Direct Lake intersects that result with semantic-model RLS and OLS.',
    citation: citations.directLakeSecurity,
  },
  {
    title: 'Model rules are path-specific',
    text: 'Semantic-model RLS and OLS restrict model queries only. Use OneLake security when the restriction must apply across Spark, SQL, and other engines.',
    citation: citations.directLakeSecurity,
  },
  {
    title: 'Write bypasses model security',
    text: 'Model Write, ownership, and Contributor-or-higher roles in the model workspace bypass semantic-model RLS and OLS.',
    citation: citations.semanticModelPermissions,
  },
  {
    title: 'The model owner must reach the source',
    text: 'Direct Lake checks the semantic-model owner’s source access during framing, regardless of who triggers the refresh.',
    citation: citations.directLakeSecurity,
  },
] as const
