<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { Download, Eye, Pencil, Plus, Trash2, Upload } from 'lucide-vue-next'
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
import { api, type BackendTarget, type TargetGroup } from '@/api'
import { t as text } from '@/lib/i18n'
import {
  healthVariant,
} from '@/lib/lb'
import { backendNodes, busy, refreshTargetGroupPage, run, targetGroupPage } from '@/composables/useNodeData'

type GroupForm = {
  name: string
  monitor: boolean
  probe_type: string
  probe_port: number | null
  probe_req: string
  probe_resp: string
  probe_skip_tls_verify: boolean
  period_secs: number | null
  retries: number | null
  targets: { address: string; weight: number }[]
}

const groupDialogOpen = ref(false)
const editingGroup = ref<string | null>(null)
const groupError = ref('')
const groupForm = reactive<GroupForm>({
  name: '', monitor: false, probe_type: 'tcp', probe_port: null, probe_req: '', probe_resp: '',
  probe_skip_tls_verify: false, period_secs: 15, retries: 3,
  targets: [{ address: '', weight: 1 }],
})
const groupImportInput = ref<HTMLInputElement | null>(null)
const memberDialogOpen = ref(false)
const selectedGroup = ref<TargetGroup | null>(null)

function showGroupMembers(group: TargetGroup) {
  selectedGroup.value = group
  memberDialogOpen.value = true
}

// 健康列统计只保留 ok / nok / unassociated 三类。
function groupHealthBadges(group: TargetGroup): { variant: 'success' | 'destructive' | 'outline'; label: string }[] {
  if (group.health === 'unassociated') {
    return [{ variant: 'outline', label: text('unassociated') }]
  }
  const counts = { ok: 0, nok: 0 }
  for (const target of group.targets ?? []) {
    const state = target.health?.toLowerCase()
    if (state === 'ok') counts.ok += 1
    else counts.nok += 1
  }
  const total = group.targets?.length ?? 0
  const badges = [{ variant: 'success' as const, label: `${counts.ok}/${total} ${text('healthy')}` }]
  if (counts.nok) {
    badges.push({ variant: 'destructive' as const, label: `${counts.nok} ${text('unhealthy')}` })
  }
  return badges
}

function downloadJson(filename: string, value: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' }))
  const anchor = document.createElement('a')
  anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url)
}
async function exportGroups() { downloadJson('edge-lb-target-groups.json', await api.exportTargetGroups()) }
function importGroups() { groupImportInput.value?.click() }
async function onGroupImport(event: Event) {
  const file = (event.target as HTMLInputElement).files?.[0]
  if (!file) return
  await run(text('import'), async () => api.importTargetGroups(JSON.parse(await file.text())))
  ;(event.target as HTMLInputElement).value = ''
}

function resetGroupForm(group?: TargetGroup) {
  editingGroup.value = group?.name ?? null
  Object.assign(groupForm, {
    name: group?.name ?? '', monitor: group?.monitor ?? false, probe_type: group?.probe_type ?? 'tcp',
    probe_port: group?.probe_port ?? null, probe_req: group?.probe_req ?? '', probe_resp: group?.probe_resp ?? '',
    probe_skip_tls_verify: group?.probe_skip_tls_verify ?? false,
    period_secs: group?.period_secs ?? 15, retries: group?.retries ?? 3,
    targets: group?.targets?.length ? group.targets.map((item) => ({ address: targetAddress(item), weight: item.weight })) : [{ address: '', weight: 1 }],
  })
  groupError.value = ''
  groupDialogOpen.value = true
}

function addGroupTarget() { groupForm.targets.push({ address: '', weight: 1 }) }
function removeGroupTarget(index: number) {
  if (groupForm.targets.length > 1) groupForm.targets.splice(index, 1)
}
function backendOptionDisabled(address: string, index: number) {
  if (!address) return false
  return groupForm.targets.some((item, other) => other !== index && item.address === address)
}

async function saveGroup() {
  const name = groupForm.name.trim()
  const items = groupForm.targets.filter((item) => item.address.trim())
  if (!name) { groupError.value = text('targetGroupNameRequired'); return }
  if (!items.length) { groupError.value = text('targetGroupTargetRequired'); return }
  if (items.some((item) => !backendNodes.value.some((node) => node.underlay_ip === item.address.trim()))) {
    groupError.value = text('noVxlanBackendForDefault'); return
  }
  if (items.some((item) => !Number.isInteger(item.weight) || item.weight < 1 || item.weight > 65535)) {
    groupError.value = text('targetWeightRange'); return
  }
  if (groupForm.monitor && groupForm.probe_type !== 'ping' && !groupForm.probe_port) {
    groupError.value = text('probePortRequired'); return
  }
  const targetKeys = items.map((item) => item.address.trim())
  if (new Set(targetKeys).size !== targetKeys.length) { groupError.value = text('targetDuplicate'); return }
  if (groupForm.monitor && ['http', 'https'].includes(groupForm.probe_type) && !groupForm.probe_req.trim()) {
    groupError.value = text('probeRequestRequired'); return
  }
  if (groupForm.monitor && groupForm.probe_type !== 'ping' && groupForm.probe_port !== null && (!Number.isInteger(groupForm.probe_port) || groupForm.probe_port < 1 || groupForm.probe_port > 65535)) {
    groupError.value = text('probePortRange'); return
  }
  if (groupForm.monitor && (!groupForm.period_secs || groupForm.period_secs < 1 || groupForm.period_secs > 65535)) {
    groupError.value = text('periodRange'); return
  }
  if (groupForm.monitor && (groupForm.retries === null || groupForm.retries < 0 || groupForm.retries > 65535)) {
    groupError.value = text('retriesRange'); return
  }
  const payload: TargetGroup = {
    name, monitor: groupForm.monitor, probe_type: groupForm.monitor ? groupForm.probe_type : null,
    probe_port: groupForm.monitor ? groupForm.probe_port : null, probe_req: groupForm.monitor ? groupForm.probe_req || null : null,
    probe_resp: groupForm.monitor ? groupForm.probe_resp || null : null,
    probe_skip_tls_verify: groupForm.monitor && groupForm.probe_type === 'https' && groupForm.probe_skip_tls_verify,
    period_secs: groupForm.monitor ? groupForm.period_secs : null, retries: groupForm.monitor ? groupForm.retries : null,
    targets: items.map((item) => ({ address: item.address.trim(), weight: Number(item.weight) })),
  }
  const saved = await run(text('save'), async () => {
    if (editingGroup.value) return api.updateTargetGroup(editingGroup.value, payload)
    return api.createTargetGroup(payload)
  })
  if (saved) groupDialogOpen.value = false
}

function deleteGroup(group: TargetGroup) {
  run(`${text('delete')} ${group.name}`, () => api.deleteTargetGroup(group.name))
}

function targetAddress(target: BackendTarget) {
  if (target.address && target.address !== '0.0.0.0' && target.address !== 'auto') {
    return target.address
  }
  return backendNodes.value.find((node) => node.name === target.backend)?.underlay_ip ?? target.address ?? 'auto'
}

function targetKey(target: BackendTarget) {
  return `${target.backend ?? target.address ?? 'auto'}`
}

function targetHealth(target: BackendTarget, group: TargetGroup) {
  return target.health ? { currState: target.health } : undefined
}

watch(
  () => targetGroupPage.page,
  () => { void refreshTargetGroupPage() },
)
</script>

<template>
        <Card>
          <CardHeader>
            <div class="flex items-start justify-between gap-4">
              <div>
                <CardTitle>{{ text('targetGroup') }}（{{ targetGroupPage.total }}）</CardTitle>
                <CardDescription>{{ text('targetGroupDesc') }}</CardDescription>
              </div>
              <div class="flex flex-wrap justify-end gap-2">
                <input ref="groupImportInput" type="file" accept="application/json" class="hidden" @change="onGroupImport" />
                <Button size="icon" variant="outline" :title="text('import')" @click="importGroups"><Upload /></Button>
                <Button size="icon" variant="outline" :title="text('export')" @click="run(text('export'), exportGroups)"><Download /></Button>
                <Button size="sm" @click="resetGroupForm()"><Plus /> {{ text('newTargetGroup') }}</Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            <PaginationBar
              v-model:page="targetGroupPage.page"
              v-model:q="targetGroupPage.q"
              :total="targetGroupPage.total"
              :per-page="targetGroupPage.per_page"
              @refresh="refreshTargetGroupPage"
            />
            <div class="overflow-x-auto">
            <Table class="min-w-[800px] table-fixed">
              <TableHeader>
                <TableRow class="hover:bg-transparent">
                  <TableHead class="w-[180px]">{{ text('name') }}</TableHead>
                  <TableHead class="w-[280px]">{{ text('targetGroupMembers') }}</TableHead>
                  <TableHead class="w-[100px]">{{ text('probeType') }}</TableHead>
                  <TableHead class="w-[180px]">{{ text('probe') }}</TableHead>
                  <TableHead class="w-[160px]">{{ text('health') }}</TableHead>
                  <TableHead class="w-[140px] text-right">{{ text('actions') }}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                <TableRow v-for="group in targetGroupPage.items" :key="group.name" class="align-top">
                  <TableCell class="font-medium">{{ group.name }}</TableCell>
                  <TableCell>
                    <span class="text-sm">{{ group.targets.length }} {{ text('targetGroupMembers') }}</span>
                  </TableCell>
                  <TableCell>
                    <Badge :variant="group.monitor ? 'secondary' : 'outline'">
                      {{ group.probe_type ?? 'none' }}
                    </Badge>
                  </TableCell>
                  <TableCell class="text-xs">
                    <div class="space-y-1">
                      <div v-if="group.probe_port">:{{ group.probe_port }}</div>
                      <div v-if="group.probe_req">{{ text('probeRequestShort') }} {{ group.probe_req }}</div>
                      <div v-if="group.probe_resp">{{ text('probeResponseShort') }} {{ group.probe_resp }}</div>
                      <div v-if="group.period_secs">{{ text('period') }} {{ group.period_secs }}s</div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <div class="flex flex-wrap items-center gap-1">
                      <Badge
                        v-for="(badge, index) in groupHealthBadges(group)"
                        :key="index"
                        :variant="badge.variant"
                      >
                        {{ badge.label }}
                      </Badge>
                    </div>
                  </TableCell>
                  <TableCell class="align-middle text-right">
                    <div class="flex items-center justify-end gap-1">
                      <Button size="icon" variant="ghost" :title="text('details')" @click="showGroupMembers(group)"><Eye /></Button>
                      <Button size="icon" variant="ghost" :title="text('edit')" @click="resetGroupForm(group)"><Pencil /></Button>
                      <Button size="icon" variant="ghost" class="text-destructive" :title="text('delete')" @click="deleteGroup(group)"><Trash2 /></Button>
                    </div>
                  </TableCell>
                </TableRow>
                <TableRow v-if="!targetGroupPage.items.length">
                  <TableCell colspan="6" class="text-muted-foreground">{{ text('empty') }}</TableCell>
                </TableRow>
              </TableBody>
            </Table>
            </div>
          </CardContent>
        </Card>

        <Dialog v-model:open="groupDialogOpen">
          <DialogContent class="w-[92vw] !max-w-[92vw] lg:w-[60vw] lg:!max-w-[60vw]">
            <DialogHeader>
              <DialogTitle>{{ editingGroup ? text('editTargetGroup') : text('newTargetGroup') }}</DialogTitle>
              <DialogDescription>{{ text('businessPersistDesc') }}</DialogDescription>
            </DialogHeader>
            <div class="max-h-[70vh] space-y-5 overflow-auto pr-1">
              <div class="grid items-end gap-4 md:grid-cols-[minmax(0,1fr)_auto]">
                <div class="space-y-1.5">
                  <Label>{{ text('name') }} <span class="text-destructive">*</span></Label>
                  <Input v-model="groupForm.name" :disabled="!!editingGroup" />
                </div>
                <div class="flex items-center gap-2 pb-2">
                  <Switch v-model="groupForm.monitor" />
                  <Label>{{ text('monitor') }}</Label>
                </div>
              </div>
              <div v-if="groupForm.monitor" class="rounded-md border bg-muted/20 p-4">
                <div class="flex flex-wrap items-end gap-4">
                <div class="w-[80px] max-w-full space-y-1.5">
                  <Label>{{ text('probeType') }}</Label>
                  <Select v-model="groupForm.probe_type">
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem v-for="probe in ['ping', 'tcp', 'udp', 'http', 'https']" :key="probe" :value="probe">{{ probe }}</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div v-if="groupForm.probe_type === 'https'" class="flex h-9 w-[220px] max-w-full items-center gap-2">
                  <Switch v-model="groupForm.probe_skip_tls_verify" />
                  <Label class="whitespace-nowrap">{{ text('skipTlsVerify') }}</Label>
                </div>
                <div v-if="groupForm.probe_type !== 'ping'" class="w-[140px] max-w-full space-y-1.5">
                  <Label>{{ text('probePort') }}</Label>
                  <Input v-model.number="groupForm.probe_port" class="w-full" type="number" min="1" max="65535" step="1" />
                </div>
                <div class="w-[140px] max-w-full space-y-1.5">
                  <Label>{{ text('period') }}</Label>
                  <Input v-model.number="groupForm.period_secs" class="w-full" type="number" min="1" max="65535" step="1" />
                </div>
                <div class="w-[140px] max-w-full space-y-1.5">
                  <Label>{{ text('retries') }}</Label>
                  <Input v-model.number="groupForm.retries" class="w-full" type="number" min="0" max="65535" step="1" />
                </div>
                <div v-if="groupForm.probe_type !== 'ping'" class="space-y-1.5 md:col-span-2">
                  <Label>{{ ['http', 'https'].includes(groupForm.probe_type) ? text('probePath') : text('probeRequest') }} <span v-if="['http', 'https'].includes(groupForm.probe_type)" class="text-destructive">*</span></Label>
                  <Input v-model="groupForm.probe_req" :placeholder="['http', 'https'].includes(groupForm.probe_type) ? '/health' : text('optional')" />
                </div>
                <div v-if="groupForm.probe_type !== 'ping' && !['http', 'https'].includes(groupForm.probe_type)" class="space-y-1.5 md:col-span-2">
                  <Label>{{ text('probeResponse') }}</Label>
                  <Input v-model="groupForm.probe_resp" :placeholder="text('optional')" />
                </div>
                <div v-if="['http', 'https'].includes(groupForm.probe_type)" class="space-y-1.5 md:col-span-2">
                  <Label>{{ text('probeResponse') }}</Label>
                  <Input v-model="groupForm.probe_resp" :placeholder="text('optional')" />
                </div>
                </div>
              </div>
              <div class="space-y-3 border-t pt-4">
                <div class="flex items-center justify-between">
                  <Label>{{ text('targetGroupMembers') }}</Label>
                  <Button type="button" variant="outline" size="sm" @click="addGroupTarget"><Plus /> {{ text('addBackendTarget') }}</Button>
                </div>
                <div v-for="(target, index) in groupForm.targets" :key="index" class="grid items-center gap-3 rounded-md border p-3 md:grid-cols-[minmax(0,1fr)_120px_auto]">
                  <div class="space-y-1.5">
                    <Label class="text-xs text-muted-foreground">{{ text('backend') }}</Label>
                    <Select v-model="target.address">
                    <SelectTrigger><SelectValue :placeholder="text('backend')" /></SelectTrigger>
                    <SelectContent disable-portal>
                      <SelectItem
                        v-if="target.address && !backendNodes.some((node) => node.underlay_ip === target.address)"
                        :value="target.address"
                        disabled
                      >
                        {{ target.address }}
                      </SelectItem>
                      <SelectItem
                        v-for="node in backendNodes"
                        :key="node.underlay_ip"
                        :value="node.underlay_ip"
                        :disabled="backendOptionDisabled(node.underlay_ip, index)"
                      >
                        {{ node.underlay_ip }} ({{ node.name }})
                      </SelectItem>
                    </SelectContent>
                    </Select>
                  </div>
                  <div class="space-y-1.5">
                    <Label class="text-xs text-muted-foreground">{{ text('weight') }}</Label>
                    <Input v-model.number="target.weight" class="w-[120px] max-w-full" type="number" min="1" max="65535" step="1" placeholder="1" />
                  </div>
                  <Button type="button" variant="ghost" size="icon" class="mt-5 justify-self-end text-destructive" :disabled="groupForm.targets.length === 1" :title="text('delete')" @click="removeGroupTarget(index)"><Trash2 /></Button>
                </div>
              </div>
              <div v-if="groupError" class="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">{{ groupError }}</div>
            </div>
            <DialogFooter>
              <Button variant="outline" @click="groupDialogOpen = false">{{ text('cancel') }}</Button>
              <Button :disabled="!!busy" @click="saveGroup">{{ text('save') }}</Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>

        <Dialog v-model:open="memberDialogOpen">
          <DialogContent class="w-[92vw] !max-w-[92vw] lg:w-[46vw] lg:!max-w-[46vw]">
            <DialogHeader>
              <DialogTitle>{{ selectedGroup?.name }}</DialogTitle>
              <DialogDescription>{{ text('targetGroupMembers') }}</DialogDescription>
            </DialogHeader>
            <div class="space-y-2">
              <div v-for="target in selectedGroup?.targets ?? []" :key="targetKey(target)" class="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
                <span class="font-mono text-sm">{{ targetAddress(target) }}</span>
                <div class="flex items-center gap-2">
                  <Badge variant="outline">{{ text('weight') }} {{ target.weight }}</Badge>
                  <Badge :variant="healthVariant(selectedGroup ? targetHealth(target, selectedGroup)?.currState : undefined)">
                    {{ selectedGroup?.health === 'unassociated' ? text('unassociated') : (targetHealth(target, selectedGroup!)?.currState?.toLowerCase() === 'ok' ? text('healthy') : text('unhealthy')) }}
                  </Badge>
                </div>
              </div>
            </div>
          </DialogContent>
        </Dialog>
</template>
