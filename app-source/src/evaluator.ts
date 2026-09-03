import type {
  DecisionStep,
  EvaluationResult,
  PermissionConfig,
  SemanticModelPermission,
  WorkspaceRole,
} from './domain'

const elevatedRoles: WorkspaceRole[] = ['admin', 'member', 'contributor']
const semanticActions = new Set([
  'view-report',
  'query-semantic-model',
  'build-report',
  'refresh-semantic-model',
])
const semanticPermissionRank: Record<SemanticModelPermission, number> = {
  none: 0,
  read: 1,
  build: 2,
  write: 3,
  owner: 4,
}

const result = (
  verdict: EvaluationResult['verdict'],
  title: string,
  summary: string,
  steps: DecisionStep[],
  warnings: string[] = [],
  remediation?: string,
  effectiveScope?: string,
): EvaluationResult => ({ verdict, title, summary, steps, warnings, remediation, effectiveScope })

const effectiveSemanticPermission = (config: PermissionConfig): SemanticModelPermission => {
  const inherited = elevatedRoles.includes(config.semanticWorkspaceRole)
    ? 'write'
    : config.semanticWorkspaceRole === 'viewer'
      ? 'read'
      : 'none'
  return semanticPermissionRank[inherited] > semanticPermissionRank[config.semanticModelPermission]
    ? inherited
    : config.semanticModelPermission
}

const hasOneLakeRead = (config: PermissionConfig) => {
  const elevated = elevatedRoles.includes(config.workspaceRole)
  const defaultRead = config.defaultReader && config.readAll
  return {
    canRead: elevated || config.oneLakeRead || config.oneLakeReadWrite || defaultRead,
    elevated,
    defaultRead,
    restrictedReadOnly: config.oneLakeRead && !elevated && !config.oneLakeReadWrite && !defaultRead,
  }
}

const evaluateSemanticModelAccess = (
  config: PermissionConfig,
  steps: DecisionStep[],
  warnings: string[],
): EvaluationResult => {
  const permission = effectiveSemanticPermission(config)
  const modelElevated = elevatedRoles.includes(config.semanticWorkspaceRole)
  const requiredPermission: SemanticModelPermission =
    config.action === 'build-report' ? 'build' : config.action === 'refresh-semantic-model' ? 'write' : 'read'

  if (config.action === 'view-report') {
    steps.push({
      layer: 'Report',
      status: config.reportRead ? 'pass' : 'fail',
      title: config.reportRead ? 'Report is reachable' : 'Report Read is missing',
      detail: config.reportRead
        ? 'The consumer can open the report that uses the semantic model.'
        : 'Semantic-model permissions do not make an unshared report reachable.',
      citation: 'semantic-model-permissions',
    })
    if (!config.reportRead) {
      return result('denied', 'Report cannot be opened', 'The consumer has no Read path to the report.', steps, warnings, 'Share the report with Read permission or distribute it through an appropriate app audience.')
    }
  }

  const modelAllowed = semanticPermissionRank[permission] >= semanticPermissionRank[requiredPermission]
  steps.push({
    layer: 'Semantic model',
    status: modelAllowed ? 'pass' : 'fail',
    title: modelAllowed ? `${permission} permission satisfies the request` : `${requiredPermission} permission is required`,
    detail: modelElevated
      ? `The ${config.semanticWorkspaceRole} role in the semantic-model workspace implicitly grants Read, Build, and Write.`
      : permission === 'owner'
        ? 'Semantic-model ownership includes Read, Build, Write, and owner-only configuration capabilities.'
        : `The effective explicit or Viewer-derived semantic-model permission is ${permission}.`,
    citation: 'semantic-model-permissions',
  })
  if (!modelAllowed) {
    const remediation = requiredPermission === 'build'
      ? 'Grant Build only when the principal should author reports, use Analyze in Excel, or query through XMLA.'
      : requiredPermission === 'write'
        ? 'Grant Write to trigger refreshes; keep ownership limited to principals that must manage credentials and refresh settings.'
        : 'Grant semantic-model Read or an appropriate model-workspace role.'
    return result('denied', 'Semantic-model permission denied', `The requested action requires ${requiredPermission} permission on the semantic model.`, steps, warnings, remediation)
  }

  if (requiredPermission === 'build') {
    warnings.push('Build permission exposes semantic-model metadata and hidden fields. OneLake OLS can still leave secured table or column names discoverable through model metadata.')
  }

  if (config.action === 'refresh-semantic-model') {
    steps.push({
      layer: 'Direct Lake framing',
      status: config.semanticModelOwnerSourceAccess ? 'pass' : 'fail',
      title: config.semanticModelOwnerSourceAccess ? 'Semantic-model owner can read the source' : 'Semantic-model owner cannot read the source',
      detail: 'Direct Lake checks the model owner’s source permissions when it frames the model, regardless of who triggers the refresh.',
      citation: 'direct-lake-security',
    })
    if (!config.semanticModelOwnerSourceAccess) {
      return result('blocked', 'Refresh and framing blocked', 'The refresh initiator is authorized, but Direct Lake cannot frame source tables without owner access.', steps, warnings, 'Restore the semantic-model owner’s least-privilege read access to every required source table.')
    }
    if (config.semanticModelIdentity === 'fixed') {
      steps.push({
        layer: 'Fixed connection identity',
        status: config.fixedIdentitySourceAccess ? 'pass' : 'fail',
        title: config.fixedIdentitySourceAccess ? 'Fixed identity can access the source' : 'Fixed identity cannot access the source',
        detail: 'When SSO is disabled, the cloud-connection identity is used for Direct Lake source operations.',
        citation: 'direct-lake-security',
      })
      if (!config.fixedIdentitySourceAccess) {
        return result('blocked', 'Fixed identity cannot frame the model', 'The semantic-model owner is authorized, but the configured connection identity cannot access the Direct Lake source.', steps, warnings, 'Grant the fixed identity least-privilege source item and OneLake access.')
      }
    }
    if (config.shortcut !== 'none') {
      steps.push({
        layer: 'Shortcut target',
        status: config.shortcutTargetAccess ? 'pass' : 'fail',
        title: config.shortcutTargetAccess ? 'Framing identity can reach the shortcut target' : 'Framing identity cannot reach the shortcut target',
        detail: 'Direct Lake framing requires access to the target behind every source shortcut.',
        citation: 'direct-lake-security',
      })
      if (!config.shortcutTargetAccess) {
        return result('blocked', 'Shortcut target blocks model framing', 'The source item is reachable, but Direct Lake cannot frame a table whose shortcut target denies the required identity.', steps, warnings, 'Grant the framing identity least-privilege access to the shortcut target.')
      }
    }
    return result('allowed', 'Semantic-model refresh allowed', 'The initiator can trigger refresh and the required Direct Lake identities can frame the source.', steps, warnings)
  }

  steps.push({
    layer: 'Direct Lake identity',
    status: 'info',
    title: config.semanticModelIdentity === 'sso' ? 'Current user through SSO' : 'Fixed connection identity',
    detail: config.semanticModelIdentity === 'sso'
      ? 'Direct Lake evaluates the current report or model user against the source item and OneLake security.'
      : 'Direct Lake evaluates the configured cloud-connection identity; the consumer does not need direct source permission.',
    citation: 'direct-lake-security',
  })

  const oneLake = hasOneLakeRead(config)
  let sourceCanRead = false
  let restrictedByOneLake = false

  if (config.semanticModelIdentity === 'sso') {
    const sourceReachable = config.workspaceRole !== 'none' || config.itemRead
    steps.push({
      layer: 'Source Lakehouse',
      status: sourceReachable ? 'pass' : 'fail',
      title: sourceReachable ? 'Source item Read is satisfied' : 'Source item Read is missing',
      detail: config.workspaceRole !== 'none'
        ? `The current user has the ${config.workspaceRole} role in the source workspace.`
        : config.itemRead
          ? 'The current user has explicit Read on the source Fabric item.'
          : 'SSO requires the current user to reach the source item before OneLake data roles are evaluated.',
      citation: 'direct-lake-security',
    })
    if (!sourceReachable) {
      return result('denied', 'Direct Lake source denied', 'The semantic model is reachable, but the SSO user cannot reach its source item.', steps, warnings, 'Grant source item Read without granting broader workspace access.')
    }
    sourceCanRead = oneLake.canRead
    restrictedByOneLake = oneLake.restrictedReadOnly && (config.rowFilter || config.hiddenColumns)
    steps.push({
      layer: 'OneLake security',
      status: sourceCanRead ? (restrictedByOneLake ? 'warning' : 'pass') : 'fail',
      title: sourceCanRead ? (restrictedByOneLake ? 'OneLake grants filtered access' : 'OneLake Read applies') : 'No OneLake data grant applies',
      detail: oneLake.elevated
        ? 'The elevated source workspace role grants broad OneLake data access.'
        : config.oneLakeReadWrite
          ? 'The current user has a OneLake ReadWrite role that includes Read.'
          : config.oneLakeRead
            ? 'The current user has a scoped OneLake Read role.'
            : oneLake.defaultRead
              ? 'DefaultReader applies because the current user has ReadAll.'
              : 'Source item Read alone does not grant access to the underlying Delta tables.',
      citation: 'read-secured-data',
    })
  } else {
    sourceCanRead = config.fixedIdentitySourceAccess
    restrictedByOneLake = sourceCanRead && (config.rowFilter || config.hiddenColumns)
    steps.push({
      layer: 'Source Lakehouse and OneLake',
      status: sourceCanRead ? (restrictedByOneLake ? 'warning' : 'pass') : 'fail',
      title: sourceCanRead ? 'Fixed identity can read the source' : 'Fixed identity lacks source access',
      detail: sourceCanRead
        ? 'The configured connection identity satisfies source item and OneLake data permissions.'
        : 'Consumer permissions cannot compensate for a fixed identity that cannot read the source.',
      citation: 'direct-lake-security',
    })
    warnings.push('Every consumer shares the fixed identity’s source authorization boundary; use semantic-model security for per-consumer restrictions.')
  }

  if (!sourceCanRead) {
    return result('denied', 'OneLake denied the Direct Lake query', 'The effective Direct Lake identity cannot read the required source data.', steps, warnings, config.semanticModelIdentity === 'sso' ? 'Add the user to a scoped OneLake Read role or grant the intended ReadAll access.' : 'Grant the fixed identity least-privilege access to the source item and required OneLake tables.')
  }

  if (config.shortcut !== 'none') {
    steps.push({
      layer: 'Shortcut target',
      status: config.shortcutTargetAccess ? 'pass' : 'fail',
      title: config.shortcutTargetAccess ? 'Effective identity can reach the shortcut target' : 'Shortcut target access is missing',
      detail: 'Direct Lake on OneLake requires the effective SSO or fixed identity to have access at the shortcut target.',
      citation: 'direct-lake-security',
    })
    if (!config.shortcutTargetAccess) {
      return result('denied', 'Shortcut target denied Direct Lake', 'The source table is visible through the semantic model, but its shortcut target rejects the effective identity.', steps, warnings, 'Grant the effective Direct Lake identity access to the shortcut target.')
    }
  }

  const modelSecurityDefined = config.semanticModelRls || config.semanticModelOls
  const modelSecurityBypassed = modelSecurityDefined && semanticPermissionRank[permission] >= semanticPermissionRank.write
  let restrictedByModel = false

  if (modelSecurityDefined) {
    if (modelSecurityBypassed) {
      steps.push({
        layer: 'Semantic-model security',
        status: 'warning',
        title: 'Model RLS/OLS is bypassed',
        detail: 'Semantic-model Write, ownership, or an elevated model-workspace role bypasses model-level data-access rules.',
        citation: 'semantic-model-rls',
      })
      warnings.push('The effective Write-level semantic-model permission bypasses model RLS and OLS.')
      warnings.push('Use Viewer or explicit Read/Build access when semantic-model RLS or OLS must constrain the principal.')
    } else if (config.semanticModelRls && !config.semanticModelRoleAssigned) {
      steps.push({
        layer: 'Semantic-model security',
        status: 'fail',
        title: 'No applicable semantic-model role',
        detail: 'Read and Build users cannot query a model with RLS unless they belong to an applicable model role.',
        citation: 'semantic-model-permissions',
      })
      return result('denied', 'Semantic-model security denied access', 'The source query is authorized, but no semantic-model role permits this Read/Build user to consume the model.', steps, warnings, 'Assign the principal to the narrowest applicable semantic-model role.')
    } else if (!config.semanticModelRoleAssigned) {
      steps.push({
        layer: 'Semantic-model security',
        status: 'warning',
        title: 'Semantic-model OLS role does not apply',
        detail: 'OLS is defined in a model role, but this principal is not assigned to that role, so it does not restrict the query.',
        citation: 'semantic-model-rls',
      })
      warnings.push('Semantic-model OLS does not restrict a principal that is not assigned to the secured model role.')
    } else {
      restrictedByModel = true
      steps.push({
        layer: 'Semantic-model security',
        status: 'warning',
        title: 'Semantic-model RLS/OLS applies',
        detail: 'Direct Lake intersects the effective OneLake result with the applicable semantic-model roles.',
        citation: 'direct-lake-security',
      })
      warnings.push('Semantic-model RLS/OLS protects only this model path; it does not restrict direct OneLake or Spark access.')
    }
  } else {
    steps.push({
      layer: 'Semantic-model security',
      status: 'info',
      title: 'No model-level RLS or OLS',
      detail: 'The semantic model adds no data restriction beyond the effective OneLake access.',
      citation: 'semantic-model-rls',
    })
  }

  if ((config.rowFilter || config.hiddenColumns) && !restrictedByOneLake && config.semanticModelIdentity === 'sso') {
    warnings.push('A broader source workspace or OneLake grant means the configured restricted OneLake role is not the effective boundary.')
  }

  if (restrictedByOneLake || restrictedByModel) {
    const scope = [
      restrictedByOneLake && config.rowFilter ? 'rows restricted by OneLake security' : '',
      restrictedByOneLake && config.hiddenColumns ? 'columns hidden by OneLake security' : '',
      restrictedByModel && config.semanticModelRls ? 'rows further restricted by semantic-model RLS' : '',
      restrictedByModel && config.semanticModelOls ? 'objects further restricted by semantic-model OLS' : '',
    ].filter(Boolean).join('; ')
    return result('filtered', 'Semantic-model access is filtered', 'The request is authorized within the intersection of OneLake and semantic-model security.', steps, warnings, undefined, scope)
  }

  return result('allowed', 'Semantic-model access allowed', 'The principal satisfies the semantic-model and Direct Lake on OneLake authorization chain.', steps, warnings)
}

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

  if (semanticActions.has(config.action)) {
    return evaluateSemanticModelAccess(config, steps, warnings)
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
    const { canRead, defaultRead, restrictedReadOnly } = hasOneLakeRead(config)
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
      citation: 'sql-access-modes',
    })

    steps.push({
      layer: 'SQL access mode',
      status: 'info',
      title: config.sqlAccessMode === 'user' ? 'User identity mode' : 'Delegated identity mode',
      detail: config.sqlAccessMode === 'user'
        ? 'The signed-in user identity is passed to OneLake, and OneLake security governs table access.'
        : 'SQL authorizes the signed-in user, then the endpoint owner identity reads the underlying OneLake data.',
      citation: 'sql-access-modes',
    })

    if (config.sqlAccessMode === 'user') {
      const { canRead, defaultRead, restrictedReadOnly } = hasOneLakeRead(config)
      if (config.readData || config.sqlSelect || config.sqlDenySelect || config.sqlRowFilter || config.sqlHiddenColumns || config.sqlMasking) {
        warnings.push('ReadData and SQL table grants, denies, RLS, CLS, and masking do not govern table access in user identity mode; OneLake security is authoritative.')
      }
      steps.push({
        layer: 'OneLake table authorization',
        status: canRead ? 'pass' : 'fail',
        title: canRead ? 'Signed-in user has OneLake table access' : 'Signed-in user lacks a OneLake data role',
        detail: elevated
          ? 'The elevated workspace role provides broad data access.'
          : config.oneLakeReadWrite
            ? 'A OneLake ReadWrite role includes table Read.'
            : config.oneLakeRead
              ? 'A scoped OneLake Read role includes the requested table.'
              : defaultRead
                ? 'DefaultReader applies because the user has ReadAll.'
                : 'ReadData or SQL SELECT does not replace a OneLake table grant in user identity mode.',
        citation: 'sql-access-modes',
      })
      if (!canRead) {
        return result('denied', 'SQL query denied by OneLake', 'User identity mode requires the signed-in user to have an applicable OneLake role.', steps, warnings, 'Grant a scoped OneLake Read role or switch deliberately to delegated identity mode with SQL security.')
      }
      if ((config.rowFilter || config.hiddenColumns) && restrictedReadOnly) {
        return result('filtered', 'SQL query is filtered by OneLake', 'The SQL endpoint passes the user identity through and enforces the OneLake role boundary.', steps, warnings, undefined, 'Rows and columns are restricted by the applicable OneLake role.')
      }
      if ((config.rowFilter || config.hiddenColumns) && !restrictedReadOnly) {
        warnings.push('A broader OneLake or workspace grant means the restricted role is not the effective SQL table boundary.')
      }
      return result('allowed', 'SQL query allowed through user identity', 'The signed-in user satisfies item reachability and OneLake table authorization.', steps, warnings)
    }

    steps.push({
      layer: 'Delegated OneLake identity',
      status: config.delegatedOwnerAccess ? 'pass' : 'fail',
      title: config.delegatedOwnerAccess ? 'Endpoint owner can read OneLake' : 'Endpoint owner lacks OneLake access',
      detail: 'Delegated mode reads the underlying files with the Lakehouse or SQL endpoint owner identity, not the querying user.',
      citation: 'sql-access-modes',
    })
    if (!config.delegatedOwnerAccess) {
      return result('blocked', 'Delegated identity cannot reach OneLake', 'The SQL user may be authorized, but the endpoint owner cannot read the underlying OneLake data.', steps, warnings, 'Restore the item owner’s OneLake access or use user identity mode.')
    }
    if (config.oneLakeRead || config.oneLakeReadWrite || config.rowFilter || config.hiddenColumns) {
      warnings.push('The querying user’s OneLake roles and policies do not govern table access through a delegated SQL endpoint.')
    }
    if (config.sqlDenySelect) {
      steps.push({
        layer: 'SQL authorization',
        status: 'fail',
        title: 'SQL DENY SELECT applies',
        detail: 'The SQL deny prevents this query through the SQL analytics endpoint, even when another SQL grant exists.',
        citation: 'sql-access-modes',
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
      citation: 'sql-access-modes',
    })
    if (!canSelect) {
      return result('denied', 'SQL query denied', 'The endpoint is reachable, but SELECT is not granted.', steps, warnings, 'Grant ReadData or a scoped SQL SELECT permission.')
    }
    if (config.sqlRowFilter || config.sqlHiddenColumns || config.sqlMasking) {
      const scope = [
        config.sqlRowFilter ? 'rows restricted by SQL security policy' : '',
        config.sqlHiddenColumns ? 'columns restricted by SQL permissions' : '',
        config.sqlMasking ? 'sensitive values dynamically masked' : '',
      ].filter(Boolean).join('; ')
      return result('filtered', 'SQL query is filtered by SQL security', 'Delegated identity mode applies SQL-native data protection after authorizing the user.', steps, warnings, undefined, scope)
    }
    return result('allowed', 'SQL query allowed through delegated identity', 'SQL authorization succeeded and the endpoint owner can read the underlying OneLake data.', steps, warnings)
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
