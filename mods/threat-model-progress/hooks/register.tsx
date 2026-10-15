import { atom, read, update } from 'claude-code'
import type { Register } from 'claude-code'

import type { Band, Progress } from '../types'

const PANE = 'threat-model-progress'
const TITLE = 'Threat model progress'
const KEEP = 200
const POLL_MS = 1000
// A resumed step replays earlier phases within seconds; no toast for those.
const REPLAY_S = 10

const progress = atom(
  { plugin: 'threat-model-progress', key: 'progress' } as const,
  { file: undefined, lines: [] } as Progress,
)

const NO_BAND: Band = { file: undefined, phase: undefined, seenAt: 0, runBase: 0, dismissed: false }

const band = atom({ plugin: 'threat-model-progress', key: 'band' } as const, NO_BAND)

const now = atom({ plugin: 'threat-model-progress', key: 'now' } as const, 0)

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
  if (after.outcome === 'failed') return `✗ Threat model: ${after.message}`
  if (after.outcome === 'complete') return `✓ Threat model complete (${durationOf(totalSeconds)})`
  const phase = before.phase
  if (phase === undefined || before.done.includes(phase.k) || !after.done.includes(phase.k)) return undefined
  if (phaseSeconds < REPLAY_S) return undefined

  return `✓ Phase ${phase.k}/${phase.n} ${phase.name} done (${durationOf(phaseSeconds)})`
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'threat-model-progress',
      description: 'Show the running create-threat-model2 step in a pane',
    })
    $.clock.every(POLL_MS, async () => {
      const { file, lines } = await read($, progress)
      if (file === undefined) return
      const t = await $.clock.now()
      const before = stepOf(lines)
      if (before.outcome === 'running') await update($, now, () => t)
      const text = await $.fs.read(file).catch(() => undefined)
      if (text === undefined) return
      const tail = tailOf(text, KEEP)
      if (tail.length === lines.length && tail.at(-1) === lines.at(-1)) return
      const after = stepOf(tail)
      const b = await read($, band)
      const toast = toastOf(before, after, (t - b.seenAt) / 1000, b.runBase + (t - b.seenAt) / 1000)
      if (toast !== undefined) $.ui.toast(toast)
      await update($, progress, p => (p.file === file ? { file, lines: tail } : p))
      const phase = phaseKeyOf(after)
      if (phase !== b.phase) {
        await update($, band, x => (x.file === file ? { ...x, phase, seenAt: t, runBase: after.elapsed ?? x.runBase } : x))
      }
    })

    return next(e)
  })

  on('command.run', { command: 'threat-model-progress' }, async $ => {
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
    await update($, progress, () => ({ file, lines: [] }))
    await update($, band, () => ({ ...NO_BAND, file, seenAt: t }))
    void $.ui.open({ id: PANE, title: TITLE })

    return ran
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.props.hasSurvey) return next(e)
    const { file, lines } = await read($, progress)
    const b = await read($, band)
    if (file === undefined || b.file !== file || b.dismissed) return next(e)
    const { Box, Button, Text } = $.ui.resolve(e)
    const step = stepOf(lines)
    const phaseS = ((await read($, now)) - b.seenAt) / 1000
    const total = durationOf(b.runBase + phaseS)
    const phase = step.phase === undefined ? 'starting' : `${step.phase.k}/${step.phase.n} ${step.phase.name}`
    const dismiss = <Button key="dismiss" label="Dismiss" role="dismiss" onPress={() => update($, band, x => ({ ...x, dismissed: true }))} />

    if (step.outcome === 'failed') {
      return (
        <Box>
          <Text color="red" wrap="truncate-end">✗ Threat model · {phase} failed · {step.message} </Text>
          {dismiss}
        </Box>
      )
    }
    if (step.outcome === 'complete') {
      return (
        <Box>
          <Text color="green">✓ Threat model complete · {total} total </Text>
          {dismiss}
        </Box>
      )
    }
    if (step.outcome === 'paused') {
      return <Text dimColor>⏸ Threat model · paused after {phase} · {total} total</Text>
    }
    const warn = step.event === '⚠' || step.event === '↻'

    return (
      <Text wrap="truncate-end">
        <Text color="blue">▶ Threat model</Text>
        <Text> · {phase} · {durationOf(phaseS)} in phase · {total} total</Text>
        {step.detail !== '' && <Text color={warn ? 'yellow' : undefined} dimColor={!warn}> · {step.detail}</Text>}
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
