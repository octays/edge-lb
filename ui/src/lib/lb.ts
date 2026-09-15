//! Native load-balancer helpers: probe types, numeric policy mappings, and UI
//! option tables.

import type { LbSelect } from '@/api/types'
import { type I18nKey } from './i18n'

export const probeTypes = ['ping', 'tcp', 'udp', 'http', 'https'] as const
export type ProbeType = (typeof probeTypes)[number] | 'none'

export function normalizeProbeType(value?: string | null): ProbeType {
  const next = value?.trim().toLowerCase()
  if (next === 'none') return 'none'
  return probeTypes.includes(next as (typeof probeTypes)[number]) ? (next as (typeof probeTypes)[number]) : 'none'
}

export function probeTypeUsesPort(value: string) {
  return ['tcp', 'udp', 'http', 'https'].includes(value)
}

export function probeTypeUsesPayload(value: string) {
  return ['tcp', 'udp', 'http', 'https'].includes(value)
}

// Dropdown options carrying a per-language description.
export const listenerSelectOptions: { value: LbSelect; descKey: I18nKey }[] = [
  { value: 'rr', descKey: 'selectRrDesc' },
  { value: 'hash', descKey: 'selectHashDesc' },
  { value: 'consistent_hash', descKey: 'selectConsistentHashDesc' },
  { value: 'priority', descKey: 'selectPriorityDesc' },
  { value: 'persist', descKey: 'selectPersistDesc' },
  { value: 'lc', descKey: 'selectLcDesc' },
]

export function healthStateLabel(state?: string) {
  if (!state) return 'unknown'
  return state
}

export function healthVariant(state?: string) {
  const normalized = (state ?? '').toLowerCase()
  if (['ok', 'active', 'up', 'alive'].includes(normalized)) return 'success'
  if (!normalized || ['unknown', 'disabled'].includes(normalized)) return 'outline'
  return 'destructive'
}
