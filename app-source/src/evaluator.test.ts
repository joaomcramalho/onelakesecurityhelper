import { describe, expect, it } from 'vitest'
import { defaultConfig } from './domain'
import { evaluateAccess } from './evaluator'
import { scenarios } from './scenarios'

describe('evaluateAccess', () => {
  it('blocks data access before item reachability is satisfied', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: false,
      oneLakeRead: true,
      action: 'read-onelake',
    })

    expect(result.verdict).toBe('blocked')
    expect(result.title).toBe('Blocked by item prerequisite')
  })

  it('keeps SQL DENY scoped to the SQL path', () => {
    const sqlResult = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: true,
      readData: false,
      oneLakeRead: true,
      sqlSelect: true,
      sqlDenySelect: true,
      action: 'query-sql',
    })
    const oneLakeResult = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: true,
      readData: false,
      oneLakeRead: true,
      sqlDenySelect: true,
      action: 'read-onelake',
    })

    expect(sqlResult.verdict).toBe('denied')
    expect(oneLakeResult.verdict).toBe('allowed')
  })

  it('uses OneLake roles instead of SQL table permissions in user identity mode', () => {
    const denied = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'viewer',
      sqlAccessMode: 'user',
      readData: true,
      sqlSelect: true,
      oneLakeRead: false,
      action: 'query-sql',
    })
    const allowed = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'viewer',
      sqlAccessMode: 'user',
      oneLakeRead: true,
      sqlDenySelect: true,
      action: 'query-sql',
    })

    expect(denied.verdict).toBe('denied')
    expect(allowed.verdict).toBe('allowed')
    expect(allowed.warnings.some((warning) => warning.includes('do not govern table access'))).toBe(true)
  })

  it('requires the delegated endpoint owner to reach OneLake', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      sqlAccessMode: 'delegated',
      delegatedOwnerAccess: false,
      sqlSelect: true,
      action: 'query-sql',
    })

    expect(result.verdict).toBe('blocked')
    expect(result.title).toBe('Delegated identity cannot reach OneLake')
  })

  it('applies SQL-native filtering in delegated identity mode', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      sqlAccessMode: 'delegated',
      delegatedOwnerAccess: true,
      sqlSelect: true,
      sqlRowFilter: true,
      sqlMasking: true,
      action: 'query-sql',
    })

    expect(result.verdict).toBe('filtered')
    expect(result.effectiveScope).toContain('SQL security policy')
    expect(result.effectiveScope).toContain('dynamically masked')
  })

  it('returns filtered when a scoped reader has row or column controls', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: true,
      oneLakeRead: true,
      rowFilter: true,
      hiddenColumns: true,
      action: 'read-onelake',
    })

    expect(result.verdict).toBe('filtered')
    expect(result.effectiveScope).toContain('rows restricted')
    expect(result.effectiveScope).toContain('columns hidden')
  })

  it('does not treat a restricted role as a boundary when a broader workspace grant applies', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'contributor',
      oneLakeRead: true,
      rowFilter: true,
      action: 'read-onelake',
    })

    expect(result.verdict).toBe('allowed')
    expect(result.warnings.some((warning) => warning.includes('broader effective grant'))).toBe(true)
  })

  it('blocks invalid OneLake ReadWrite with RLS or CLS', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: true,
      oneLakeReadWrite: true,
      rowFilter: true,
      action: 'write-spark',
    })

    expect(result.verdict).toBe('blocked')
    expect(result.title).toBe('Unsupported role combination')
  })

  it('does not model the Lakehouse SQL endpoint as a write path', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'admin',
      sqlWrite: true,
      action: 'write-sql',
    })

    expect(result.verdict).toBe('blocked')
    expect(result.title).toBe('SQL write is unavailable')
  })

  it('requires report Read and semantic-model Read for report consumption', () => {
    const noReport = evaluateAccess({
      ...defaultConfig,
      reportRead: false,
      semanticModelPermission: 'read',
      action: 'view-report',
    })
    const noModel = evaluateAccess({
      ...defaultConfig,
      reportRead: true,
      semanticModelPermission: 'none',
      semanticWorkspaceRole: 'none',
      action: 'view-report',
    })

    expect(noReport.title).toBe('Report cannot be opened')
    expect(noModel.title).toBe('Semantic-model permission denied')
  })

  it('requires Build for report authoring and warns about metadata exposure', () => {
    const denied = evaluateAccess({
      ...defaultConfig,
      semanticModelPermission: 'read',
      action: 'build-report',
    })
    const allowed = evaluateAccess({
      ...defaultConfig,
      oneLakeRead: true,
      semanticModelPermission: 'build',
      action: 'build-report',
    })

    expect(denied.verdict).toBe('denied')
    expect(allowed.verdict).toBe('allowed')
    expect(allowed.warnings.some((warning) => warning.includes('metadata'))).toBe(true)
  })

  it('inherits semantic-model permissions from the model workspace role', () => {
    const viewer = evaluateAccess({
      ...defaultConfig,
      oneLakeRead: true,
      semanticWorkspaceRole: 'viewer',
      semanticModelPermission: 'none',
      action: 'query-semantic-model',
    })
    const contributor = evaluateAccess({
      ...defaultConfig,
      oneLakeRead: true,
      semanticWorkspaceRole: 'contributor',
      semanticModelPermission: 'none',
      action: 'build-report',
    })

    expect(viewer.verdict).toBe('allowed')
    expect(contributor.verdict).toBe('allowed')
  })

  it('uses the current user source permissions for Direct Lake SSO', () => {
    const unreachable = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: false,
      oneLakeRead: true,
      semanticModelPermission: 'read',
      semanticModelIdentity: 'sso',
      action: 'query-semantic-model',
    })
    const noDataRole = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: true,
      readAll: false,
      defaultReader: false,
      oneLakeRead: false,
      semanticModelPermission: 'read',
      semanticModelIdentity: 'sso',
      action: 'query-semantic-model',
    })

    expect(unreachable.title).toBe('Direct Lake source denied')
    expect(noDataRole.title).toBe('OneLake denied the Direct Lake query')
  })

  it('uses fixed identity access without granting the consumer source access', () => {
    const allowed = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: false,
      readAll: false,
      defaultReader: false,
      oneLakeRead: false,
      semanticModelPermission: 'read',
      semanticModelIdentity: 'fixed',
      fixedIdentitySourceAccess: true,
      action: 'query-semantic-model',
    })
    const denied = evaluateAccess({
      ...defaultConfig,
      semanticModelPermission: 'read',
      semanticModelIdentity: 'fixed',
      fixedIdentitySourceAccess: false,
      action: 'query-semantic-model',
    })

    expect(allowed.verdict).toBe('allowed')
    expect(denied.verdict).toBe('denied')
  })

  it('intersects OneLake filtering with semantic-model RLS and OLS', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      workspaceRole: 'none',
      itemRead: true,
      defaultReader: false,
      oneLakeRead: true,
      rowFilter: true,
      hiddenColumns: true,
      semanticModelPermission: 'read',
      semanticModelRls: true,
      semanticModelOls: true,
      semanticModelRoleAssigned: true,
      action: 'query-semantic-model',
    })

    expect(result.verdict).toBe('filtered')
    expect(result.effectiveScope).toContain('OneLake security')
    expect(result.effectiveScope).toContain('semantic-model RLS')
    expect(result.effectiveScope).toContain('semantic-model OLS')
  })

  it('denies Read and Build users without an applicable semantic-model role', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      oneLakeRead: true,
      semanticModelPermission: 'read',
      semanticModelRls: true,
      semanticModelRoleAssigned: false,
      action: 'query-semantic-model',
    })

    expect(result.verdict).toBe('denied')
    expect(result.title).toBe('Semantic-model security denied access')
  })

  it('does not apply an OLS-only role to an unassigned user', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      oneLakeRead: true,
      semanticModelPermission: 'read',
      semanticModelOls: true,
      semanticModelRoleAssigned: false,
      action: 'query-semantic-model',
    })

    expect(result.verdict).toBe('allowed')
    expect(result.warnings.some((warning) => warning.includes('OLS does not restrict'))).toBe(true)
  })

  it('allows Write and elevated model roles to bypass model security', () => {
    const explicitWrite = evaluateAccess({
      ...defaultConfig,
      oneLakeRead: true,
      semanticModelPermission: 'write',
      semanticModelRls: true,
      semanticModelRoleAssigned: false,
      action: 'query-semantic-model',
    })
    const contributor = evaluateAccess({
      ...defaultConfig,
      oneLakeRead: true,
      semanticWorkspaceRole: 'contributor',
      semanticModelPermission: 'none',
      semanticModelOls: true,
      semanticModelRoleAssigned: false,
      action: 'query-semantic-model',
    })

    expect(explicitWrite.verdict).toBe('allowed')
    expect(contributor.verdict).toBe('allowed')
    expect(explicitWrite.warnings.some((warning) => warning.includes('bypasses'))).toBe(true)
  })

  it('requires model owner source access for Direct Lake framing', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      semanticModelPermission: 'write',
      semanticModelOwnerSourceAccess: false,
      action: 'refresh-semantic-model',
    })

    expect(result.verdict).toBe('blocked')
    expect(result.title).toBe('Refresh and framing blocked')
  })

  it('requires shortcut target access for Direct Lake framing', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      semanticModelPermission: 'write',
      semanticModelOwnerSourceAccess: true,
      shortcut: 'passthrough',
      shortcutTargetAccess: false,
      action: 'refresh-semantic-model',
    })

    expect(result.verdict).toBe('blocked')
    expect(result.title).toBe('Shortcut target blocks model framing')
  })

  it('checks shortcut target access for Direct Lake on OneLake', () => {
    const result = evaluateAccess({
      ...defaultConfig,
      oneLakeRead: true,
      semanticModelPermission: 'read',
      shortcut: 'passthrough',
      shortcutTargetAccess: false,
      action: 'query-semantic-model',
    })

    expect(result.verdict).toBe('denied')
    expect(result.title).toBe('Shortcut target denied Direct Lake')
  })

  it('keeps every scenario deterministic and explainable', () => {
    for (const scenario of scenarios) {
      const result = evaluateAccess(scenario.config)
      expect(['allowed', 'denied', 'filtered', 'blocked']).toContain(result.verdict)
      expect(result.steps.length).toBeGreaterThan(0)
      expect(result.steps.every((step) => step.detail.length > 0)).toBe(true)
    }
  })
})
