import { atom, read, update } from 'claude-code'
import type { Register } from 'claude-code'

import type { Progress } from '../types'

const PANE = 'threat-model-progress'
const TITLE = 'Threat model progress'
const KEEP = 200
const POLL_MS = 2000

const progress = atom(
  { plugin: 'threat-model-progress', key: 'progress' } as const,
  { file: undefined, lines: [] } as Progress,
)

export const isStepCommand = (command: string): boolean =>
  command.includes('run-headless.sh') && command.includes('--interactive-launch')

export const outputFileOf = (text: string | undefined): string | undefined =>
  text?.match(/Output is being written to: (\S+\.output)/)?.[1]

export const tailOf = (text: string, keep: number): string[] =>
  text.replace(/\r/g, '').split('\n').filter(line => line.trim() !== '').slice(-keep)

const colorOf = (line: string): 'red' | 'green' | 'yellow' | undefined => {
  if (/^✗|Traceback|interrupted/.test(line)) return 'red'
  if (/^⏸|\bdone\b/.test(line)) return 'green'
  if (/⚠|↻/.test(line)) return 'yellow'
  return undefined
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
      const text = await $.fs.read(file).catch(() => undefined)
      if (text === undefined) return
      const tail = tailOf(text, KEEP)
      if (tail.length === lines.length && tail.at(-1) === lines.at(-1)) return
      await update($, progress, p => (p.file === file ? { file, lines: tail } : p))
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
    await update($, progress, () => ({ file, lines: [] }))
    void $.ui.open({ id: PANE, title: TITLE })

    return ran
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
