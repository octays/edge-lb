//! Listener form model, validation, payload conversion, and module-level state.
import { computed, reactive, ref, watch } from 'vue'
import {
  api,
  type LbSelect,
  type Protocol,
  type TargetGroup,
  type ListenerConfig,
} from '@/api'
import { t } from '@/lib/i18n'
import {
  normalizeProbeType,
  probeTypeUsesPayload,
  probeTypeUsesPort,
  type ProbeType,
} from '@/lib/lb'
import {
  boundedInt,
  isBlankNumber,
  isIPv4,
  numberOrDefault,
  optionalBoundedInt,
  optionalPort,
  optionalPositiveInt,
  requiredPort,
} from '@/lib/validation'
import { error, refreshTargetGroupOptions, run, targetGroupOptionPage } from '@/composables/useNodeData'

export type ListenerForm = {
  name: string
  vip_ips: string[]
  target_group: string
  port: number | ''
  target_port: number | ''
  protocols: Protocol[]
  monitor: boolean
  probe_type: ProbeType
  probe_port: number | null
  probe_req: string
  probe_resp: string
  skip_tls_verify: boolean
  period_secs: number | null
  retries: number | null
  select: LbSelect
  inactive_timeout: number | null
}

const emptyListener: ListenerForm = {
  name: '',
  vip_ips: [],
  port: '',
  target_port: '',
  target_group: '',
  protocols: ['tcp'],
  monitor: false,
  probe_type: 'none',
  probe_port: null,
  probe_req: '',
  probe_resp: '',
  skip_tls_verify: false,
  period_secs: null,
  retries: null,
  inactive_timeout: 60,
  select: 'rr',
}

export const listenerForm = reactive<ListenerForm>({ ...emptyListener })
export const editingListener = ref<string | null>(null)
export const listenerFormOpen = ref(false)

const targetGroupOptions = computed(() => targetGroupOptionPage.items)
function targetGroupByName(name: string) {
  return targetGroupOptions.value.find((group) => group.name === name)
}


const selectedListenerProbeType = computed(() => {
  const probe = normalizeProbeType(listenerForm.probe_type)
  return listenerForm.monitor ? (probe === 'none' ? 'http' : probe) : 'none'
})
const listenerProbeEnabled = computed(() => !!listenerForm.monitor)
const listenerProbeUsesPort = computed(() => probeTypeUsesPort(selectedListenerProbeType.value))
const listenerProbeUsesPayload = computed(() => probeTypeUsesPayload(selectedListenerProbeType.value))
const listenerProbeTypeModel = computed({
  get: () => selectedListenerProbeType.value,
  set: (value: string | number | null | undefined) => {
    applyListenerProbeType(String(value ?? 'none'))
  },
})

export {
  selectedListenerProbeType,
  listenerProbeEnabled,
  listenerProbeUsesPort,
  listenerProbeUsesPayload,
  listenerProbeTypeModel,
}

export function toggleListenerProtocol(protocol: Protocol, checked: boolean | 'indeterminate') {
  const next = listenerForm.protocols.filter((item) => item !== protocol)
  if (checked === true) next.push(protocol)
  listenerForm.protocols = (['tcp', 'udp'] as Protocol[]).filter((item) => next.includes(item))
}

export const generatedListenerName = computed(() => {
  const protocols = listenerForm.protocols.length ? [...listenerForm.protocols].sort() : ['tcp']
  const port = requiredPort(listenerForm.port) ? Number(listenerForm.port) : 0
  return `${protocols.join('-')}-${port}`
})

export function applyListenerProbeType(value: string | number | null | undefined) {
  const next = normalizeProbeType(String(value ?? 'none'))
  listenerForm.probe_type = next
  if (next === 'none') {
    listenerForm.monitor = false
    listenerForm.probe_port = null
    listenerForm.probe_req = ''
    listenerForm.probe_resp = ''
    listenerForm.period_secs = null
    listenerForm.retries = null
    return
  }
  listenerForm.monitor = true
  listenerForm.period_secs = isBlankNumber(listenerForm.period_secs) ? 15 : listenerForm.period_secs
  listenerForm.retries = isBlankNumber(listenerForm.retries) ? 3 : listenerForm.retries
  if (!probeTypeUsesPort(next)) {
    listenerForm.probe_port = null
  }
  if (!probeTypeUsesPayload(next)) {
    listenerForm.probe_req = ''
    listenerForm.probe_resp = ''
  }
}

export const listenerErrors = computed(() => {
  const errors: string[] = []
  if (!requiredPort(listenerForm.port)) {
    errors.push(t('listenerPortRange'))
  }
  if (!requiredPort(listenerForm.target_port)) {
    errors.push(t('listenerTargetPortRange'))
  }
  if (!listenerForm.protocols.length) {
    errors.push(t('listenerProtocolRequired'))
  }
  if (!listenerForm.target_group.trim()) {
    errors.push(t('listenerTargetGroupRequired'))
  }
  if (listenerForm.select !== 'persist' && !optionalPositiveInt(listenerForm.inactive_timeout)) {
    errors.push(t('inactiveTimeoutRange'))
  }
  return errors
})
export const canSubmitListener = computed(() => listenerErrors.value.length === 0)

export function listenerPayload(): ListenerConfig {
  const name = generatedListenerName.value
  return {
    name,
    // VIPs are assigned by edge-lb from the local underlay and HA state.
    vip_ips: [],
    port: Number(listenerForm.port),
    target_port: Number(listenerForm.target_port),
    protocols: [...listenerForm.protocols],
    target_group: listenerForm.target_group.trim(),
    select: listenerForm.select,
    inactive_timeout: listenerForm.select === 'persist' ? null : numberOrDefault(listenerForm.inactive_timeout, 60),
  }
}

export function editListener(listener: ListenerConfig) {
  targetGroupOptionPage.page = 1
  targetGroupOptionPage.q = listener.target_group ?? ''
  void refreshTargetGroupOptions()
  const group = targetGroupByName(listener.target_group ?? '')
  const probeType = normalizeProbeType(group?.probe_type)
  Object.assign(listenerForm, {
    name: listener.name,
    port: listener.port,
    target_port: listener.target_port ?? '',
    target_group: listener.target_group ?? '',
    vip_ips: listener.vip_ips ?? [],
    monitor: probeType !== 'none' && !!group?.monitor,
    probe_type: probeType,
    probe_port: group?.probe_port ?? null,
    probe_req: group?.probe_req ?? '',
    probe_resp: group?.probe_resp ?? '',
    skip_tls_verify: !!group?.probe_skip_tls_verify,
    period_secs: probeType === 'none' ? null : group?.period_secs ?? 15,
    retries: probeType === 'none' ? null : group?.retries ?? 3,
    select: listener.select ?? 'rr',
    inactive_timeout: listener.inactive_timeout ?? null,
    protocols: listener.protocols?.length ? [...listener.protocols] : ['tcp'],
  })
  editingListener.value = listener.name
  listenerFormOpen.value = true
}

export function resetListenerForm() {
  Object.assign(listenerForm, { ...emptyListener })
  listenerForm.target_group = ''
  listenerForm.target_port = ''
  editingListener.value = null
}

export function applyListenerTargetGroup(value: string | number | null | undefined) {
  listenerForm.target_group = String(value ?? '')
  if (requiredPort(listenerForm.target_port)) return
  const group = targetGroupByName(listenerForm.target_group)
  if (group?.targets?.length && !requiredPort(listenerForm.target_port)) {
    listenerForm.target_port = ''
  }
}

export async function openNewListener() {
  resetListenerForm()
  targetGroupOptionPage.page = 1
  targetGroupOptionPage.q = ''
  void refreshTargetGroupOptions()
  listenerFormOpen.value = true
}

export async function submitListener() {
  if (listenerErrors.value.length) {
    error.value = listenerErrors.value[0]
    return
  }
  const saved = editingListener.value
    ? await run(t('save'), () => api.updateListenerConfig(editingListener.value!, listenerPayload()))
    : await run(t('create'), () => api.createListenerConfig(listenerPayload()))
  if (!saved) return
  listenerFormOpen.value = false
  resetListenerForm()
}

watch(
  () => listenerForm.monitor,
  (enabled) => {
    if (!enabled) {
      listenerForm.probe_type = 'none'
      listenerForm.probe_port = null
      listenerForm.probe_req = ''
      listenerForm.probe_resp = ''
      listenerForm.period_secs = null
      listenerForm.retries = null
      return
    }

    const current = normalizeProbeType(listenerForm.probe_type)
    if (current === 'none') {
      listenerForm.probe_type = 'http'
    }
    listenerForm.period_secs = isBlankNumber(listenerForm.period_secs) ? 15 : listenerForm.period_secs
    listenerForm.retries = isBlankNumber(listenerForm.retries) ? 3 : listenerForm.retries
  },
)
