import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register } from 'claude-code'

import type { Band, Live, Progress } from '../types/progress'

const PANE = 'assessment-progress'
const TITLE = 'Assessment progress'
const KEEP = 200
const POLL_MS = 1000
// A resumed step replays earlier phases within seconds; no toast for those.
const REPLAY_S = 10
// The controller's default heartbeat threshold, for a lock that states no stale_after=.
const LIVE_STALE_S = 300
// Where a run started outside this session reports: the legacy directory in the
// checkout. A step this session launched names its own --output.
const LEGACY_REPORT_DIR = 'docs/security'

const progress = atom(
  { plugin: 'appsec-advisor', key: 'progress' } as const,
  { file: undefined, dir: undefined, lines: [] } as Progress,
)

const NO_BAND: Band = { file: undefined, phase: undefined, seenAt: 0, runBase: 0, dismissed: false }

const band = atom({ plugin: 'appsec-advisor', key: 'band' } as const, NO_BAND)

const now = atom({ plugin: 'appsec-advisor', key: 'now' } as const, 0)

const live = atom({ plugin: 'appsec-advisor', key: 'live' } as const, null as Live | null)

export type Row = { k: number; n: number; name: string; event: string; elapsed: number | undefined; detail: string }

export type Step = {
  phase: { k: number; n: number; name: string } | undefined
  event: string
  detail: string
  elapsed: number | undefined
  done: number[]
  outcome: 'running' | 'paused' | 'failed' | 'complete'
  message: string
}

const ROW = /^\d\d:\d\d:\d\d {2}(\d+)\/(\d+) (.+?) {2,}(start|done|·|⚠|↻)(.*)$/
const DURATION = /^(<1m|\d+h(\d\dm)?|\d+m)$/

export const isStepCommand = (command: string): boolean =>
  command.includes('run-headless.sh') && command.includes('--interactive-launch')

// The step command names the run's output directory; the skill passes it literally.
export const outputDirOf = (command: string): string | undefined => {
  const match = command.match(/--output\s+(?:"([^"]+)"|'([^']+)'|(\S+))/)

  return match === null ? undefined : (match[1] ?? match[2] ?? match[3])
}

export const outputFileOf = (text: string | undefined): string | undefined =>
  text?.match(/Output is being written to: (\S+\.output)/)?.[1]

export const tailOf = (text: string, keep: number): string[] =>
  text.replace(/\r/g, '').split('\n').filter(line => line.trim() !== '').slice(-keep)

export const secondsOf = (elapsed: string): number =>
  elapsed.startsWith('<') ? 0 : Number(elapsed.match(/(\d+)h/)?.[1] ?? 0) * 3600 + Number(elapsed.match(/(\d+)m/)?.[1] ?? 0) * 60

export const durationOf = (seconds: number): string => {
  const s = Math.max(0, Math.round(seconds))
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  const rest = String(s % 60).padStart(2, '0')
  if (h > 0) return `${h}h${String(m).padStart(2, '0')}m`

  return m > 0 ? `${m}m${rest}s` : `${s}s`
}

export const rowOf = (line: string): Row | undefined => {
  const match = line.match(ROW)
  if (match === null) return undefined
  // Cells after EVENT: PROGRESS, ELAPSED, LEFT (may be blank), DETAIL.
  const cells = match[5].trim().split(/\s{2,}/).filter(Boolean).slice(1)
  const durations = cells.filter(cell => DURATION.test(cell))

  return {
    k: Number(match[1]),
    n: Number(match[2]),
    name: match[3].trim(),
    event: match[4],
    elapsed: durations[0] === undefined ? undefined : secondsOf(durations[0]),
    detail: cells.filter(cell => !DURATION.test(cell)).join('  '),
  }
}

export const stepOf = (lines: string[]): Step => {
  const step: Step = { phase: undefined, event: '', detail: '', elapsed: undefined, done: [], outcome: 'running', message: '' }
  for (const line of lines) {
    const row = rowOf(line)
    if (row !== undefined) {
      if (row.event === 'start') step.elapsed = row.elapsed
      step.phase = { k: row.k, n: row.n, name: row.name }
      step.event = row.event
      step.detail = row.detail
      if (row.event === 'done') {
        step.done.push(row.k)
        if (row.k === row.n) step.outcome = 'complete'
      }
    } else if (line.startsWith('⏸')) {
      step.outcome = 'paused'
      step.message = line
    } else if (line.startsWith('✗')) {
      step.outcome = 'failed'
      step.message = line.replace(/^✗\s*/, '')
    }
  }

  return step
}

export const phaseKeyOf = (step: Step): string | undefined =>
  step.phase === undefined ? undefined : `${step.phase.k}/${step.phase.n}`

export const toastOf = (before: Step, after: Step, phaseSeconds: number, totalSeconds: number): string | undefined => {
  if (before.outcome !== 'running') return undefined
  if (after.outcome === 'failed') return `✗ Assessment: ${after.message}`
  if (after.outcome === 'complete') return `✓ Assessment complete (${durationOf(totalSeconds)})`
  const phase = before.phase
  if (phase === undefined || before.done.includes(phase.k) || !after.done.includes(phase.k)) return undefined
  if (phaseSeconds < REPLAY_S) return undefined

  return `✓ Phase ${phase.k}/${phase.n} ${phase.name} done (${durationOf(phaseSeconds)})`
}

// `.appsec-lock`: pid, heartbeat (epoch seconds), run id.
export const lockOf = (text: string): { heartbeat: number; runId: string; staleAfter: number } | undefined => {
  const lines = text.split('\n').map(line => line.trim())
  const heartbeat = lines[1]
  if (heartbeat === undefined || !/^\d+$/.test(heartbeat)) return undefined
  const runId = lines[2] !== undefined && !lines[2].includes('=') ? lines[2] : ''
  const staleAfter = Number(lines.find(line => line.startsWith('stale_after='))?.slice('stale_after='.length))

  return { heartbeat: Number(heartbeat), runId, staleAfter: staleAfter > 0 ? staleAfter : LIVE_STALE_S }
}

export const roleOf = (name: string): string => name.replace(/^\d+-/, '').replace(/\.jsonl$/, '')

// A host-events line is `<seconds>\t<stream-json event>`.
export const eventOf = (line: string): { activity: string; retrying: boolean } | undefined => {
  let event: Record<string, unknown>
  try {
    event = JSON.parse(line.slice(line.indexOf('\t') + 1))
  } catch {
    return undefined
  }
  if (event.subtype === 'api_retry') {
    const error = event.error_status ?? event.error
    const why = error === null || error === undefined ? '' : ` (${String(error)})`

    return { activity: `API retry ${String(event.attempt)}/${String(event.max_retries)}${why}`, retrying: true }
  }
  if (event.type === 'assistant') return { activity: 'answering', retrying: false }
  if (event.type === 'result') return { activity: 'answered', retrying: false }

  return { activity: 'waiting for the model', retrying: false }
}

const shortRun = (runId: string): string => runId.replace(/^assessment-/, '').slice(0, 7)

// A killed controller never writes its final status; with its lock gone stale a
// state that still says `running` describes a run that died.
export const endedOf = (runId: string, status: string): string =>
  `Assessment run ${shortRun(runId)} ended${status === '' ? '' : `: ${status === 'running' ? 'interrupted (process gone)' : status}`}`

const pollLive = async ($: EngineInterface, t: number): Promise<void> => {
  const dir = (await read($, progress)).dir ?? `${await $.session.root()}/${LEGACY_REPORT_DIR}`
  const text = await $.fs.read(`${dir}/.appsec-lock`).catch(() => undefined)
  const lock = text === undefined ? undefined : lockOf(text)
  const before = await read($, live)
  if (lock === undefined || t / 1000 - lock.heartbeat > lock.staleAfter) {
    if (before === null) return
    await update($, live, () => null)
    const state = await $.fs.read(`${dir}/.assessment-state.json`).catch(() => undefined)
    const status = state === undefined ? '' : String(JSON.parse(state).status ?? '')
    $.ui.toast(endedOf(before.runId, status))
    return
  }
  const state = await $.fs.read(`${dir}/.assessment-state.json`).catch(() => undefined)
  const startedAt = state === undefined ? lock.heartbeat : Number(JSON.parse(state).started_at ?? lock.heartbeat)
  const entries = await $.fs.list(`${dir}/.assessment-work/host-events`).catch(() => [])
  const newest = entries
    .filter(entry => entry.kind === 'file' && entry.name.endsWith('.jsonl'))
    .sort((a, b) => b.mtimeMs - a.mtimeMs)[0]
  let role: string | undefined
  let activity = ''
  let retrying = false
  // Host events of an earlier run stay in the folder; only this run's count.
  if (newest !== undefined && newest.mtimeMs / 1000 >= startedAt) {
    role = roleOf(newest.name)
    const events = await $.fs.read(`${dir}/.assessment-work/host-events/${newest.name}`).catch(() => '')
    const last = eventOf(tailOf(events, 1)[0] ?? '')
    activity = last?.activity ?? ''
    retrying = last?.retrying ?? false
  }
  await update($, live, () => ({
    runId: lock.runId,
    startedAt,
    heartbeat: lock.heartbeat,
    role,
    activity,
    retrying,
    eventAt: newest?.mtimeMs ?? 0,
  }))
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: PANE,
      description: 'Show the running appsec-analyzer step in a pane',
    })
    $.clock.every(POLL_MS, async () => {
      const t = await $.clock.now()
      await pollLive($, t).catch(() => undefined)
      const { file, lines } = await read($, progress)
      const before = stepOf(lines)
      if ((file !== undefined && before.outcome === 'running') || (await read($, live)) !== null) {
        await update($, now, () => t)
      }
      if (file === undefined) return
      const text = await $.fs.read(file).catch(() => undefined)
      if (text === undefined) return
      const tail = tailOf(text, KEEP)
      if (tail.length === lines.length && tail.at(-1) === lines.at(-1)) return
      const after = stepOf(tail)
      const b = await read($, band)
      const toast = toastOf(before, after, (t - b.seenAt) / 1000, b.runBase + (t - b.seenAt) / 1000)
      if (toast !== undefined) $.ui.toast(toast)
      await update($, progress, p => (p.file === file ? { ...p, lines: tail } : p))
      const phase = phaseKeyOf(after)
      if (phase !== b.phase) {
        await update($, band, x => (x.file === file ? { ...x, phase, seenAt: t, runBase: after.elapsed ?? x.runBase } : x))
      }
    })

    return next(e)
  })

  on('command.run', { command: PANE }, async $ => {
    await $.ui.open({ id: PANE, title: TITLE })
    const { file } = await read($, progress)

    return { text: file === undefined ? 'No assessment step seen yet in this session.' : `Showing ${file}` }
  })

  on('tool.call', { tool: 'Bash' }, async ($, e, next) => {
    const ran = await next(e)
    if (!e.run_in_background || !isStepCommand(e.command)) return ran
    const file = outputFileOf(ran.text)
    if (file === undefined) return ran
    const t = await $.clock.now()
    await update($, progress, () => ({ file, dir: outputDirOf(e.command), lines: [] }))
    await update($, band, () => ({ ...NO_BAND, file, seenAt: t }))
    void $.ui.open({ id: PANE, title: TITLE })

    return ran
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    const { file, lines } = await read($, progress)
    const b = await read($, band)
    const run = await read($, live)
    const { Box, Button, Text } = $.ui.resolve(e)
    const activity =
      run === null || run.activity === ''
        ? undefined
        : `${run.role === undefined ? '' : `${run.role}: `}${run.activity}`
    if (file === undefined || b.file !== file || b.dismissed) {
      // A run this session did not launch: lock, state and host events only.
      if (run === null) return next(e)
      const t = await read($, now)

      return (
        <Text wrap="truncate-end">
          <Text color="blue">▶ Assessment</Text>
          <Text> · run {shortRun(run.runId)} · {durationOf(t / 1000 - run.startedAt)}</Text>
          {activity !== undefined && <Text color={run.retrying ? 'yellow' : undefined} dimColor={!run.retrying}> · {activity}</Text>}
        </Text>
      )
    }
    const step = stepOf(lines)
    const phaseS = ((await read($, now)) - b.seenAt) / 1000
    const total = durationOf(b.runBase + phaseS)
    const phase = step.phase === undefined ? 'starting' : `${step.phase.k}/${step.phase.n} ${step.phase.name}`
    const dismiss = <Button key="dismiss" label="Dismiss" role="dismiss" onPress={() => update($, band, x => ({ ...x, dismissed: true }))} />

    if (step.outcome === 'failed') {
      return (
        <Box>
          <Text color="red" wrap="truncate-end">✗ Assessment · {phase} failed · {step.message} </Text>
          {dismiss}
        </Box>
      )
    }
    if (step.outcome === 'complete') {
      return (
        <Box>
          <Text color="green">✓ Assessment complete · {total} total </Text>
          {dismiss}
        </Box>
      )
    }
    if (step.outcome === 'paused') {
      return <Text dimColor>⏸ Assessment · paused after {phase} · {total} total</Text>
    }
    const warn = run?.retrying === true || (activity === undefined && (step.event === '⚠' || step.event === '↻'))
    const detail = activity ?? step.detail

    return (
      <Text wrap="truncate-end">
        <Text color="blue">▶ Assessment</Text>
        <Text> · {phase} · {durationOf(phaseS)} in phase · {total} total</Text>
        {detail !== '' && <Text color={warn ? 'yellow' : undefined} dimColor={!warn}> · {detail}</Text>}
      </Text>
    )
  })

  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const { file, lines } = await read($, progress)
    const room = Math.max(1, (e.viewport?.rows ?? 24) - 3)

    return (
      <Box flexDirection="column">
        {file === undefined && <Text dimColor>No assessment step running.</Text>}
        {file !== undefined && lines.length === 0 && <Text dimColor>Waiting for output…</Text>}
        {lines.slice(-room).map(line => (
          <Text color={colorOf(line)} wrap="truncate-end">
            {line}
          </Text>
        ))}
      </Box>
    )
  })
}

const colorOf = (line: string): 'red' | 'green' | 'yellow' | undefined => {
  if (/^✗|Traceback|interrupted/.test(line)) return 'red'
  if (/^⏸|\bdone\b/.test(line)) return 'green'
  if (/⚠|↻/.test(line)) return 'yellow'
  return undefined
}
