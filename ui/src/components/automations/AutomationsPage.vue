<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { Download, FlaskConical, Loader2, Plus, Save, Trash2, Upload } from 'lucide-vue-next'
import {
  Badge,
  Button,
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  Input,
  Label,
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui'
import PaginationBar from '@/components/common/PaginationBar.vue'
import { api } from '@/api'
import type {
  AutomationFilterCondition,
  AutomationFilterField,
  AutomationFilterOp,
  AutomationImportMode,
  AutomationImportRequest,
  AutomationNodeFilter,
  AutomationNodeScope,
  AutomationTemplate,
  AutomationTargetGroupTemplate,
} from '@/api/types'
import {
  automationTemplatePage,
  automationsError,
  backendNodes,
  busy,
  refreshAutomationData,
  refreshAutomationPage,
  run,
} from '@/composables/useNodeData'
import { t as text } from '@/lib/i18n'

const filterFields: AutomationFilterField[] = [
  'name',
  'underlay_ip',
  'underlay_ip_source',
]
const filterOps: AutomationFilterOp[] = [
  'equals',
  'not_equals',
  'prefix',
  'not_prefix',
  'contains',
  'not_contains',
  'regex',
  'in_cidr',
  'not_in_cidr',
]
const probeTypes = ['ping', 'tcp', 'udp', 'http', 'https']

type AutomationTemplateForm = AutomationTemplate

const dialogOpen = ref(false)
const editingName = ref('')
const form = ref<AutomationTemplateForm>(defaultTemplate())
const formMessage = ref('')
const testOutput = ref('')
const importOpen = ref(false)
const importText = ref('')
const importMode = ref<AutomationImportMode>('merge_skip')
const importMessage = ref('')
const importResult = ref('')

const generatedTemplateName = computed(() => {
  const name = form.value.target_group.name.trim()
  return name ? `template-${name}` : 'template-'
})
const generatedTargetGroupName = computed(() => {
  return form.value.target_group.name.trim()
})

const formError = computed(() => validateTemplate(form.value))
const enabledCount = computed(() => automationTemplatePage.items.filter((item) => item.enabled).length)

watch(
  () => automationTemplatePage.page,
  () => { void refreshAutomationPage() },
)

function defaultTemplate(): AutomationTemplateForm {
  return {
    name: '',
    enabled: true,
    triggers: { on_create: true, on_node_change: true },
    node_scope: 'all',
    node_filter: defaultFilter(),
    target_group: {
      name: '',
      monitor: false,
      probe_type: 'tcp',
      probe_port: null,
      probe_req: null,
      probe_resp: null,
      probe_skip_tls_verify: false,
      period_secs: 15,
      retries: 3,
    },
    conflict_policy: 'skip',
    remove_policy: 'prune',
  }
}

function defaultFilter(): AutomationNodeFilter {
  return { match: 'all', conditions: [] }
}

function defaultCondition(): AutomationFilterCondition {
  return { field: 'name', op: 'prefix', value: '' }
}

function openNew() {
  editingName.value = ''
  form.value = defaultTemplate()
  formMessage.value = ''
  testOutput.value = ''
  dialogOpen.value = true
}

function openEdit(template: AutomationTemplate) {
  editingName.value = template.name
  form.value = clonePlain(template)
  formMessage.value = ''
  testOutput.value = ''
  dialogOpen.value = true
}

function addCondition() {
  if (!form.value.node_filter) form.value.node_filter = defaultFilter()
  form.value.node_scope = 'filtered'
  form.value.node_filter.conditions.push(defaultCondition())
}

function matchedNodeCount() {
  if (form.value.node_scope === 'all') return backendNodes.value.length
  const filter = form.value.node_filter
  if (!filter || !filter.conditions.length) return backendNodes.value.length
  return backendNodes.value.filter((node) => matchesFilter(node, filter)).length
}

function matchesFilter(node: Record<string, unknown>, filter: AutomationNodeFilter) {
  return filter.conditions.every((condition) => {
    const raw = String(node[condition.field] ?? '')
    const value = condition.value.trim()
    if (!value) return false
    try {
      switch (condition.op) {
        case 'equals':
          return raw === value
        case 'not_equals':
          return raw !== value
        case 'prefix':
          return raw.startsWith(value)
        case 'not_prefix':
          return !raw.startsWith(value)
        case 'contains':
          return raw.includes(value)
        case 'not_contains':
          return !raw.includes(value)
        case 'regex':
          return new RegExp(value).test(raw)
        case 'in_cidr':
          return ipv4InCidr(raw, value)
        case 'not_in_cidr':
          return !ipv4InCidr(raw, value)
      }
    } catch {
      return false
    }
  })
}

function ipv4InCidr(ip: string, cidr: string) {
  const [base, prefixText] = cidr.split('/')
  const prefix = Number(prefixText)
  const ipNum = ipv4ToNum(ip)
  const baseNum = ipv4ToNum(base)
  if (ipNum === null || baseNum === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    return false
  }
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0
  return (ipNum & mask) === (baseNum & mask)
}

function ipv4ToNum(value: string) {
  const parts = value.split('.').map((part) => Number(part))
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return null
  }
  return (((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3]) >>> 0
}

function validRegex(value: string) {
  try {
    new RegExp(value)
    return true
  } catch {
    return false
  }
}

function validCidr(value: string) {
  const [base, prefixText] = value.split('/')
  const prefix = Number(prefixText)
  return ipv4ToNum(base) !== null && Number.isInteger(prefix) && prefix >= 0 && prefix <= 32
}

function filterOpLabel(op: AutomationFilterOp) {
  switch (op) {
    case 'equals':
      return text('filterOp_equals')
    case 'not_equals':
      return text('filterOp_not_equals')
    case 'prefix':
      return text('filterOp_prefix')
    case 'not_prefix':
      return text('filterOp_not_prefix')
    case 'contains':
      return text('filterOp_contains')
    case 'not_contains':
      return text('filterOp_not_contains')
    case 'regex':
      return text('filterOp_regex')
    case 'in_cidr':
      return text('filterOp_in_cidr')
    case 'not_in_cidr':
      return text('filterOp_not_in_cidr')
  }
}

function validateTemplate(template: AutomationTemplateForm) {
  const targetGroup = template.target_group
  if (!targetGroup.name.trim()) return text('targetGroupNameRequired')
  if (targetGroup.monitor && ['http', 'https'].includes(targetGroup.probe_type || '')) {
    if (!targetGroup.probe_req?.trim()) return text('probeRequestRequired')
  }
  if (template.node_scope === 'filtered') {
    const filter = template.node_filter
    for (const condition of filter?.conditions ?? []) {
      const value = condition.value.trim()
      if (!value) return text('conditionValueRequired')
      if (condition.op === 'regex' && !validRegex(value)) return text('conditionRegexInvalid')
      if (['in_cidr', 'not_in_cidr'].includes(condition.op)) {
        if (condition.field !== 'underlay_ip') return text('conditionCidrFieldInvalid')
        if (!validCidr(value)) return text('conditionCidrInvalid')
      }
    }
  }
  return ''
}

function setMonitor(enabled: boolean) {
  form.value.target_group.monitor = enabled
  if (enabled && (!form.value.target_group.probe_type || form.value.target_group.probe_type === 'none')) {
    form.value.target_group.probe_type = 'tcp'
  }
}

function normalizedTemplate(): AutomationTemplate {
  const next = clonePlain(form.value)
  next.name = generatedTemplateName.value
  if (next.node_scope === 'all') {
    next.node_filter = defaultFilter()
  }
  const probeType = next.target_group.probe_type?.trim().toLowerCase()
  next.target_group.probe_type = next.target_group.monitor && probeType !== 'none' ? probeType || 'tcp' : 'none'
  if (!['tcp', 'udp', 'http', 'https'].includes(next.target_group.probe_type || '')) {
    next.target_group.probe_req = null
    next.target_group.probe_resp = null
    next.target_group.probe_skip_tls_verify = false
  } else if (!['http', 'https'].includes(next.target_group.probe_type || '')) {
    next.target_group.probe_req = next.target_group.probe_req?.trim() || null
    next.target_group.probe_resp = next.target_group.probe_resp?.trim() || null
    next.target_group.probe_skip_tls_verify = false
  } else if (next.target_group.probe_type !== 'https') {
    next.target_group.probe_skip_tls_verify = false
  }
  return next as AutomationTemplate
}

function clonePlain<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T
}

async function saveTemplate() {
  const error = formError.value
  if (error) {
    formMessage.value = error
    return
  }
  const saved = await api.saveAutomationTemplate(normalizedTemplate(), editingName.value || undefined)
  editingName.value = saved.name
  form.value = saved
  formMessage.value = text('saved')
  await refreshAutomationData()
  dialogOpen.value = false
}

async function deleteTemplate(name: string) {
  await api.deleteAutomationTemplate(name)
  if (editingName.value === name) dialogOpen.value = false
  await refreshAutomationData()
}

async function testTemplate() {
  const error = formError.value
  if (error) {
    formMessage.value = error
    return
  }
  const result = await api.testAutomationTemplate(generatedTemplateName.value, normalizedTemplate())
  testOutput.value = JSON.stringify(result, null, 2)
}

async function exportTemplates() {
  const result = await api.exportAutomationTemplates()
  importText.value = JSON.stringify(result, null, 2)
  importOpen.value = true
}

function openImport() {
  importText.value = ''
  importMode.value = 'merge_skip'
  importMessage.value = ''
  importResult.value = ''
  importOpen.value = true
}

async function importTemplates(dryRun: boolean) {
  importMessage.value = ''
  importResult.value = ''
  let payload: Record<string, unknown>
  try {
    payload = JSON.parse(importText.value)
  } catch (e) {
    importMessage.value = e instanceof Error ? e.message : String(e)
    return
  }
  const result = await api.importAutomationTemplates({
    ...(payload as AutomationImportRequest),
    dry_run: dryRun,
    mode: importMode.value,
  })
  importResult.value = JSON.stringify(result, null, 2)
  if (!dryRun) {
    importMessage.value = text('importApplied')
    await refreshAutomationData()
  }
}

function setNodeScope(value: string) {
  form.value.node_scope = value as AutomationNodeScope
  if (form.value.node_scope === 'filtered' && !form.value.node_filter) {
    form.value.node_filter = defaultFilter()
  }
}

</script>

<template>
  <div class="space-y-4">
    <div class="grid gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(360px,1fr)]">
      <Card>
        <CardHeader>
          <div class="flex items-start justify-between gap-3">
            <div>
              <CardTitle>{{ text('navAutomations') }}</CardTitle>
              <CardDescription>{{ text('automationsDesc') }}</CardDescription>
            </div>
            <div class="flex gap-2">
              <Button variant="outline" @click="openImport">
                <Upload class="size-4" />
                {{ text('import') }}
              </Button>
              <Button variant="outline" @click="run('automation-export', exportTemplates)">
                <Download class="size-4" />
                {{ text('export') }}
              </Button>
              <Button @click="openNew">
                <Plus class="size-4" />
                {{ text('newAutomation') }}
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent class="space-y-3">
          <div
            v-if="automationsError"
            class="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
          >
            {{ automationsError }}
          </div>
          <PaginationBar
            v-model:page="automationTemplatePage.page"
            v-model:q="automationTemplatePage.q"
            :total="automationTemplatePage.total"
            :per-page="automationTemplatePage.per_page"
            @refresh="refreshAutomationPage"
          />
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{{ text('name') }}</TableHead>
                <TableHead>{{ text('status') }}</TableHead>
                <TableHead>{{ text('trigger') }}</TableHead>
                <TableHead>{{ text('nodeScope') }}</TableHead>
                <TableHead>{{ text('automationTargetGroupName') }}</TableHead>
                <TableHead class="w-28"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              <TableRow v-for="template in automationTemplatePage.items" :key="template.name">
                <TableCell>
                  <button class="text-left font-medium hover:underline" @click="openEdit(template)">
                    {{ template.name }}
                  </button>
                </TableCell>
                <TableCell>
                  <Badge :variant="template.enabled ? 'success' : 'outline'">
                    {{ template.enabled ? text('enabled') : text('disabled') }}
                  </Badge>
                </TableCell>
                <TableCell class="text-sm text-muted-foreground">
                  <span v-if="template.triggers.on_create">{{ text('onCreate') }}</span>
                  <span v-if="template.triggers.on_create && template.triggers.on_node_change"> / </span>
                  <span v-if="template.triggers.on_node_change">{{ text('onNodeChange') }}</span>
                </TableCell>
                <TableCell>{{ template.node_scope === 'all' ? text('allNodes') : text('filteredNodes') }}</TableCell>
                <TableCell class="font-mono text-xs">{{ template.target_group.name || '-' }}</TableCell>
                <TableCell>
                  <div class="flex justify-end gap-1">
                    <Button variant="ghost" size="sm" @click="openEdit(template)">{{ text('edit') }}</Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      :title="text('delete')"
                      @click="run(`automation-delete-${template.name}`, () => deleteTemplate(template.name))"
                    >
                      <Trash2 class="size-4" />
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
              <TableRow v-if="!automationTemplatePage.items.length">
                <TableCell colspan="6" class="text-muted-foreground">{{ text('empty') }}</TableCell>
              </TableRow>
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>{{ text('automationSummary') }}</CardTitle>
          <CardDescription>{{ text('automationSummaryDesc') }}</CardDescription>
        </CardHeader>
        <CardContent class="space-y-4 text-sm">
          <div class="grid grid-cols-2 gap-3">
            <div class="rounded-md border p-3">
              <div class="text-muted-foreground">{{ text('enabled') }}</div>
              <div class="mt-1 text-2xl font-semibold">{{ enabledCount }}</div>
            </div>
            <div class="rounded-md border p-3">
              <div class="text-muted-foreground">{{ text('backend') }}</div>
              <div class="mt-1 text-2xl font-semibold">{{ backendNodes.length }}</div>
            </div>
          </div>
          <div class="rounded-md border p-3">
            <div class="font-medium">{{ text('automationNaming') }}</div>
            <p class="mt-1 leading-5 text-muted-foreground">{{ text('automationNamingDesc') }}</p>
          </div>
          <div class="rounded-md border p-3">
            <div class="font-medium">{{ text('automationHaModel') }}</div>
            <p class="mt-1 leading-5 text-muted-foreground">{{ text('automationHaModelDesc') }}</p>
          </div>
        </CardContent>
      </Card>
    </div>

    <Dialog v-model:open="dialogOpen">
      <DialogContent class="w-[94vw] !max-w-[94vw] xl:w-[72vw] xl:!max-w-[72vw]">
        <DialogHeader>
          <DialogTitle>{{ editingName ? text('editAutomation') : text('newAutomation') }}</DialogTitle>
          <DialogDescription>{{ text('automationFormDesc') }}</DialogDescription>
        </DialogHeader>

        <div class="max-h-[72vh] space-y-5 overflow-y-auto pr-1">
          <div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_240px]">
          <div class="grid gap-4 md:grid-cols-2">
              <div class="space-y-1.5">
                <Label>{{ text('templateName') }}</Label>
                <Input :model-value="generatedTemplateName" disabled class="font-mono text-xs" />
              </div>
              <div class="space-y-1.5">
                <Label>{{ text('automationTargetGroupName') }}</Label>
                <Input v-model="form.target_group.name" :placeholder="text('targetGroupNamePlaceholder')" class="font-mono text-xs" />
              </div>
            </div>
            <div class="flex items-center justify-between gap-3 rounded-md border p-3">
              <div>
                <Label>{{ text('enabled') }}</Label>
                <p class="text-xs text-muted-foreground">{{ text('automationEnabledDesc') }}</p>
              </div>
              <Switch v-model="form.enabled" />
            </div>
          </div>

          <div class="grid gap-4 lg:grid-cols-2">
            <div class="space-y-1.5">
              <Label>{{ text('nodeScope') }}</Label>
              <Select :model-value="form.node_scope" @update:model-value="setNodeScope">
                <SelectTrigger class="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">{{ text('allNodes') }}</SelectItem>
                  <SelectItem value="filtered">{{ text('filteredNodes') }}</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div class="grid gap-4 lg:grid-cols-[minmax(0,1fr)_220px]">
            <div class="rounded-md border p-3">
              <div class="flex items-center justify-between gap-3">
                <div>
                  <Label>{{ text('monitor') }}</Label>
                  <p class="text-xs text-muted-foreground">{{ text('automationProbeDesc') }}</p>
                </div>
                <Switch :model-value="form.target_group.monitor" @update:model-value="setMonitor" />
              </div>
              <div v-if="form.target_group.monitor" class="mt-4 grid gap-4 lg:grid-cols-3">
                <div class="space-y-1.5">
                  <Label>{{ text('probeType') }}</Label>
                  <Select v-model="form.target_group.probe_type">
                    <SelectTrigger class="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem v-for="probeType in probeTypes" :key="probeType" :value="probeType">
                        {{ probeType }}
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div class="space-y-1.5">
                  <Label>{{ text('probePort') }}</Label>
                  <Input v-model.number="form.target_group.probe_port" type="number" min="1" max="65535" />
                </div>
                <div class="grid grid-cols-2 gap-3">
                  <div class="space-y-1.5">
                    <Label>{{ text('period') }}</Label>
                    <Input v-model.number="form.target_group.period_secs" type="number" min="1" max="65535" />
                  </div>
                  <div class="space-y-1.5">
                    <Label>{{ text('retries') }}</Label>
                    <Input v-model.number="form.target_group.retries" type="number" min="0" max="65535" />
                  </div>
                </div>
                <div v-if="['tcp', 'udp', 'http', 'https'].includes(form.target_group.probe_type || '')" class="space-y-1.5">
                  <Label>{{ ['http', 'https'].includes(form.target_group.probe_type || '') ? text('probePath') : text('probeRequest') }}</Label>
                  <Input v-model="form.target_group.probe_req" :placeholder="['http', 'https'].includes(form.target_group.probe_type || '') ? '/health' : text('optional')" />
                </div>
                <div v-if="['tcp', 'udp', 'http', 'https'].includes(form.target_group.probe_type || '')" class="space-y-1.5 lg:col-span-2">
                  <Label>{{ text('probeResponse') }}</Label>
                  <Input v-model="form.target_group.probe_resp" placeholder="{&quot;status&quot;:&quot;ok&quot;}" />
                </div>
                <div v-if="form.target_group.probe_type === 'https'" class="flex items-center gap-2 pt-7">
                  <Switch v-model="form.target_group.probe_skip_tls_verify" />
                  <Label>{{ text('skipTlsVerify') }}</Label>
                </div>
              </div>
            </div>
            <div class="rounded-md border p-3 text-sm">
              <div class="text-muted-foreground">{{ text('matchedNodes') }}</div>
              <div class="mt-1 text-2xl font-semibold">{{ matchedNodeCount() }}</div>
              <p class="mt-2 leading-5 text-muted-foreground">{{ text('matchedNodesDesc') }}</p>
            </div>
          </div>

          <Card v-if="form.node_scope === 'filtered'">
            <CardHeader class="pb-3">
              <div class="flex items-center justify-between gap-3">
                <div>
                  <CardTitle class="text-base">{{ text('templateFilter') }}</CardTitle>
                  <CardDescription>{{ text('matchedNodes') }}: {{ matchedNodeCount() }}</CardDescription>
                </div>
                <Button variant="outline" size="sm" @click="addCondition">
                  <Plus class="size-4" />
                  {{ text('addCondition') }}
                </Button>
              </div>
            </CardHeader>
            <CardContent class="space-y-2">
              <div
                v-for="(condition, index) in form.node_filter?.conditions"
                :key="index"
                class="grid gap-2 md:grid-cols-[1fr_1fr_2fr_auto]"
              >
                <Select v-model="condition.field">
                  <SelectTrigger class="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="field in filterFields" :key="field" :value="field">{{ field }}</SelectItem>
                  </SelectContent>
                </Select>
                <Select v-model="condition.op">
                  <SelectTrigger class="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem v-for="op in filterOps" :key="op" :value="op">{{ filterOpLabel(op) }}</SelectItem>
                  </SelectContent>
                </Select>
                <Input v-model="condition.value" :placeholder="text('conditionValue')" />
                <Button
                  variant="ghost"
                  size="icon"
                  :title="text('delete')"
                  @click="form.node_filter?.conditions.splice(index, 1)"
                >
                  <Trash2 class="size-4" />
                </Button>
              </div>
              <p v-if="!form.node_filter?.conditions.length" class="text-sm text-muted-foreground">
                {{ text('noConditions') }}
              </p>
            </CardContent>
          </Card>

          <div class="grid grid-cols-2 gap-3 rounded-md border p-3">
            <label class="flex items-center justify-between gap-3">
              <span class="text-sm">{{ text('onCreate') }}</span>
              <Switch v-model="form.triggers.on_create" />
            </label>
            <label class="flex items-center justify-between gap-3">
              <span class="text-sm">{{ text('onNodeChange') }}</span>
              <Switch v-model="form.triggers.on_node_change" />
            </label>
          </div>

          <div v-if="formMessage" class="rounded-md border px-3 py-2 text-sm">{{ formMessage }}</div>
          <pre v-if="testOutput" class="max-h-64 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">{{ testOutput }}</pre>
        </div>

        <DialogFooter>
          <Button variant="outline" @click="run('automation-test', testTemplate)">
            <FlaskConical class="size-4" />
            {{ text('dryRun') }}
          </Button>
          <Button :disabled="!!formError || !!busy" @click="run('automation-save', saveTemplate)">
            <Loader2 v-if="busy === 'automation-save'" class="animate-spin" />
            <Save v-else class="size-4" />
            {{ text('save') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>

    <Dialog v-model:open="importOpen">
      <DialogContent class="w-[92vw] !max-w-[92vw] lg:w-[60vw] lg:!max-w-[60vw]">
        <DialogHeader>
          <DialogTitle>{{ text('importExport') }}</DialogTitle>
          <DialogDescription>{{ text('automationImportDesc') }}</DialogDescription>
        </DialogHeader>
        <div class="space-y-1.5">
          <Label>{{ text('importMode') }}</Label>
          <Select v-model="importMode">
            <SelectTrigger class="w-full">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="merge_skip">{{ text('mergeSkip') }}</SelectItem>
              <SelectItem value="merge_overwrite">{{ text('mergeOverwrite') }}</SelectItem>
              <SelectItem value="replace_all">{{ text('replaceAll') }}</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <textarea
          v-model="importText"
          class="min-h-[360px] w-full rounded-md border bg-background p-3 font-mono text-xs outline-none focus-visible:ring-2 focus-visible:ring-ring"
          spellcheck="false"
          :placeholder="text('pasteJson')"
        />
        <div v-if="importMessage" class="rounded-md border px-3 py-2 text-sm">{{ importMessage }}</div>
        <pre v-if="importResult" class="max-h-48 overflow-auto rounded-md border bg-muted/40 p-3 text-xs">{{ importResult }}</pre>
        <DialogFooter>
          <Button variant="outline" @click="importOpen = false">{{ text('cancel') }}</Button>
          <Button variant="outline" @click="run('automation-import-dry-run', () => importTemplates(true))">
            <FlaskConical class="size-4" />
            {{ text('importPreview') }}
          </Button>
          <Button @click="run('automation-import-apply', () => importTemplates(false))">
            <Upload class="size-4" />
            {{ text('applyImport') }}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  </div>
</template>
