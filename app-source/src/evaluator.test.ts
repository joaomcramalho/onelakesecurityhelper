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

  it('keeps every scenario deterministic and explainable', () => {
    for (const scenario of scenarios) {
      const result = evaluateAccess(scenario.config)
      expect(['allowed', 'denied', 'filtered', 'blocked']).toContain(result.verdict)
      expect(result.steps.length).toBeGreaterThan(0)
      expect(result.steps.every((step) => step.detail.length > 0)).toBe(true)
    }
  })
})
