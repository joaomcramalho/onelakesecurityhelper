import type {
  DecisionStep,
  EvaluationResult,
  PermissionConfig,
  WorkspaceRole,
} from './domain'

const elevatedRoles: WorkspaceRole[] = ['admin', 'member', 'contributor']

const result = (
  verdict: EvaluationResult['verdict'],
  title: string,
  summary: string,
  steps: DecisionStep[],
  warnings: string[] = [],
  remediation?: string,
  effectiveScope?: string,
): EvaluationResult => ({ verdict, title, summary, steps, warnings, remediation, effectiveScope })

export function evaluateAccess(config: PermissionConfig): EvaluationResult {
  const steps: DecisionStep[] = []
  const warnings: string[] = []

  if (!config.authenticated) {
    steps.push({
      layer: 'Identity',
      status: 'fail',
      title: 'Microsoft Entra authentication failed',
      detail: 'No downstream Fabric permission is evaluated until the principal can authenticate.',
      citation: 'permission-model',
    })
    return result('blocked', 'Blocked at identity', 'The principal cannot enter the Fabric authorization chain.', steps, warnings, 'Authenticate the principal in the applicable tenant.')
  }

  steps.push({
    layer: 'Identity',
    status: 'pass',
    title: config.viaGroup ? 'Authenticated with group-derived grants' : 'Authenticated principal',
    detail: config.viaGroup
      ? 'Direct and nested group assignments can add permissions; the highest applicable workspace capability wins.'
      : 'The principal is eligible for Fabric permission evaluation.',
    citation: 'workspace-roles',
  })

  if (!config.fabricEnabled) {
    steps.push({
      layer: 'Fabric',
      status: 'fail',
      title: 'Fabric access unavailable',
      detail: 'The principal is authenticated but cannot access Microsoft Fabric.',
      citation: 'permission-model',
    })
    return result('blocked', 'Blocked at Fabric access', 'Data permissions cannot be used until Fabric access is available.', steps, warnings)
  }

  const elevated = elevatedRoles.includes(config.workspaceRole)
  const workspaceMember = config.workspaceRole !== 'none'
  const reachable = workspaceMember || config.itemRead

  steps.push({
    layer: 'Fabric',
    status: reachable ? 'pass' : 'fail',
    title: reachable ? 'Lakehouse is reachable' : 'Lakehouse is not reachable',
    detail: workspaceMember
      ? `The ${config.workspaceRole} workspace role applies to every item in the workspace.`
      : config.itemRead
        ? 'Direct item Read makes this Lakehouse reachable without workspace membership.'
        : 'No workspace role or item Read grant applies.',
    citation: 'permission-model',
  })

  if (config.action === 'open-lakehouse') {
    return reachable
      ? result('allowed', 'Lakehouse can be opened', 'The item is visible through workspace membership or direct item sharing.', steps, warnings)
      : result('denied', 'Lakehouse cannot be opened', 'The principal has no control-plane path to the item.', steps, warnings, 'Grant item Read or an appropriate workspace role.')
  }

  if (!reachable) {
    return result(
      'blocked',
      'Blocked by item prerequisite',
      'Data-plane permissions do not replace the workspace role or item Read needed to reach the item.',
      steps,
      warnings,
      'Grant item Read or an appropriate workspace role before adding data permissions.',
    )
  }

  if (elevated) {
    warnings.push(`The ${config.workspaceRole} workspace role is broad and can override the intent of a restricted-reader design.`)
  }
  if (config.defaultReader && config.readAll) {
    warnings.push('DefaultReader plus ReadAll grants broad read access; remove or narrow DefaultReader before relying on a restricted role.')
  }
  if (config.viaGroup) {
    warnings.push('Review every direct and nested group assignment because grants are additive.')
  }

  if (config.shortcut !== 'none') {
    steps.push({
      layer: 'Shortcut',
      status: config.shortcutTargetAccess ? 'pass' : 'fail',
      title: config.shortcutTargetAccess ? `${config.shortcut} target access satisfied` : 'Shortcut target access missing',
      detail:
        config.shortcut === 'passthrough'
          ? 'Passthrough uses the caller identity, so access is constrained by both the shortcut path and target path.'
          : 'Delegated access uses a configured target identity; the caller still sees only what the shortcut path exposes.',
      citation: 'onelake-model',
    })
    if (!config.shortcutTargetAccess) {
      return result('denied', 'Shortcut target denied access', 'Permission on the containing Lakehouse is not enough to open the target.', steps, warnings, 'Grant the caller or delegated connection identity access to the shortcut target.')
    }
  }

  if (config.action === 'read-onelake') {
    const defaultRead = config.defaultReader && config.readAll
    const canRead = elevated || config.oneLakeRead || config.oneLakeReadWrite || defaultRead
    const restrictedReadOnly = config.oneLakeRead && !elevated && !config.oneLakeReadWrite && !defaultRead
    steps.push({
      layer: 'OneLake',
      status: canRead ? 'pass' : 'fail',
      title: canRead ? 'OneLake Read applies' : 'No OneLake data grant applies',
      detail: elevated
        ? 'The elevated workspace role carries broad data access.'
        : config.oneLakeReadWrite
          ? 'A OneLake ReadWrite role includes Read.'
          : config.oneLakeRead
            ? 'A custom OneLake Read role includes the requested resource.'
            : defaultRead
              ? 'DefaultReader virtual membership applies because the principal has ReadAll.'
              : 'Item visibility alone does not grant underlying OneLake data access.',
      citation: 'onelake-model',
    })
    if (!canRead) {
      return result('denied', 'OneLake read denied', 'The item is reachable, but no applicable OneLake data role grants the requested resource.', steps, warnings, 'Grant a scoped OneLake Read role or the intended ReadAll-based default access.')
    }
    if ((config.rowFilter || config.hiddenColumns) && restrictedReadOnly) {
      const scope = [
        config.rowFilter ? 'rows restricted by the role predicate' : '',
        config.hiddenColumns ? 'sensitive columns hidden' : '',
      ].filter(Boolean).join('; ')
      return result('filtered', 'OneLake read is filtered', 'The user can read the resource within the role-defined data boundary.', steps, warnings, undefined, scope)
    }
    if ((config.rowFilter || config.hiddenColumns) && !restrictedReadOnly) {
      warnings.push('A broader effective grant means the restricted role is not the user’s access boundary for this request.')
    }
    return result('allowed', 'OneLake read allowed', 'An applicable workspace or OneLake role grants the requested data.', steps, warnings)
  }

  if (config.action === 'query-sql') {
    steps.push({
      layer: 'SQL endpoint',
      status: 'pass',
      title: 'SQL connection prerequisite satisfied',
      detail: 'A workspace role or item Read is required before SQL permissions can be used.',
      citation: 'sql-permissions',
    })
    if (config.sqlDenySelect) {
      steps.push({
        layer: 'SQL authorization',
        status: 'fail',
        title: 'SQL DENY SELECT applies',
        detail: 'The SQL deny prevents this query through the SQL analytics endpoint, even when another SQL grant exists.',
        citation: 'sql-permissions',
      })
      warnings.push('This SQL DENY does not remove access through Spark or direct OneLake paths.')
      return result('denied', 'SQL query denied', 'An explicit SQL DENY blocks SELECT on this SQL path.', steps, warnings, 'Remove the SQL DENY or query through an intentionally authorized access path.')
    }
    const canSelect = elevated || config.readData || config.sqlSelect
    steps.push({
      layer: 'SQL authorization',
      status: canSelect ? 'pass' : 'fail',
      title: canSelect ? 'SQL SELECT is effective' : 'No SQL SELECT permission',
      detail: elevated
        ? 'The elevated workspace role supplies broad access.'
        : config.readData
          ? 'ReadData grants SQL/TDS read access.'
          : config.sqlSelect
            ? 'A granular SQL grant supplies SELECT.'
            : 'Item Read allows connection but does not itself grant table data.',
      citation: 'sql-permissions',
    })
    if (!canSelect) {
      return result('denied', 'SQL query denied', 'The endpoint is reachable, but SELECT is not granted.', steps, warnings, 'Grant ReadData or a scoped SQL SELECT permission.')
    }
    if ((config.rowFilter || config.hiddenColumns) && !elevated) {
      return result('filtered', 'SQL query is filtered', 'SQL or OneLake security limits the rows or columns returned by this access path.', steps, warnings, undefined, 'The result set is restricted by configured row and column controls.')
    }
    return result('allowed', 'SQL query allowed', 'The connection prerequisite and effective SELECT permission are both satisfied.', steps, warnings)
  }

  if (config.action === 'write-spark') {
    const scopedWrite = config.itemRead && config.oneLakeReadWrite
    const canWrite = elevated || scopedWrite || config.itemWrite
    steps.push({
      layer: 'OneLake write',
      status: canWrite ? 'pass' : 'fail',
      title: canWrite ? 'Spark/OneLake write is effective' : 'No write permission applies',
      detail: elevated
        ? 'Admin, Member, and Contributor have broad Lakehouse write capability.'
        : scopedWrite
          ? 'Item Read plus a scoped OneLake ReadWrite role enables OneLake-engine writes.'
          : config.itemWrite
            ? 'An explicit item Write grant applies.'
            : 'The principal has read access only.',
      citation: 'onelake-model',
    })
    if (config.oneLakeReadWrite && (config.rowFilter || config.hiddenColumns)) {
      warnings.push('OneLake ReadWrite roles cannot contain row-level or column-level restrictions; this configuration is invalid in Fabric.')
      return result('blocked', 'Unsupported role combination', 'ReadWrite cannot be combined with OneLake RLS or CLS.', steps, warnings, 'Remove RLS/CLS from the ReadWrite role or split read and write responsibilities.')
    }
    return canWrite
      ? result('allowed', 'Spark write allowed', 'The effective role permits writes through OneLake-compatible write paths.', steps, warnings)
      : result('denied', 'Spark write denied', 'No workspace, item, or OneLake ReadWrite permission grants this operation.', steps, warnings, 'Grant the narrowest appropriate write permission.')
  }

  if (config.action === 'write-sql') {
    steps.push({
      layer: 'SQL analytics endpoint',
      status: 'fail',
      title: 'Lakehouse SQL analytics endpoint is not a write path',
      detail: 'Lakehouse data writes use OneLake-compatible engines such as Spark or OneLake APIs; SQL analytics endpoint access is modeled as read/query access.',
      citation: 'onelake-model',
    })
    return result('blocked', 'SQL write is unavailable', 'This simulator targets a Lakehouse SQL analytics endpoint, not a writable Fabric Warehouse.', steps, warnings, 'Use Spark/OneLake for Lakehouse writes, or evaluate a Fabric Warehouse as a separate resource type.')
  }

  const canManage = config.workspaceRole === 'admin'
  const canReshare = canManage || config.workspaceRole === 'member' || config.reshare
  steps.push({
    layer: 'Sharing and management',
    status: canReshare ? 'pass' : 'fail',
    title: canManage ? 'Manage permissions allowed' : canReshare ? 'Reshare allowed' : 'No Reshare or manage capability',
    detail: canManage
      ? 'Workspace Admin can manage access and permissions.'
      : config.workspaceRole === 'member'
        ? 'Workspace Member can share content and allow lower permissions.'
        : config.reshare
          ? 'An explicit Reshare permission allows sharing this item.'
          : 'Viewer and Contributor require an explicit Reshare permission to share.',
    citation: 'workspace-roles',
  })
  return canReshare
    ? result('allowed', canManage ? 'Permission management allowed' : 'Resharing allowed', canManage ? 'The principal can manage workspace and item access.' : 'The principal can reshare the item but does not gain full workspace administration.', steps, warnings)
    : result('denied', 'Resharing denied', 'No workspace role or explicit Reshare grant permits this action.', steps, warnings, 'Grant Reshare, Member, or Admin only if the principal should delegate access.')
}
