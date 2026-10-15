import { expect, test } from 'claude-code/testing'

import { durationOf, eventOf, isStepCommand, lockOf, outputFileOf, roleOf, rowOf, stepOf, tailOf, toastOf } from './progress'

const START = '18:55:27  1/8 Reconnaissance    start  planning      <1m'
const WARN = '17:56:51  1/8 Reconnaissance    ⚠      planning       3m          model call failed (server_error); repeating it in 15 s (attempt 2)'
const DONE = '19:04:40  1/8 Reconnaissance    done   planning       9m          recon complete'
const NEXT = '19:04:40  2/8 Architecture      start  planning       9m  1h02m'

test('recognizes a create-threat-model2 step command', () => {
  expect(isStepCommand('APPSEC_SINGLE_REPO_CONTROLLER=1 "/x/scripts/run-headless.sh" --repo r --output o --interactive-launch --pause-after 1')).toBe(true)
  expect(isStepCommand('"/x/scripts/run-headless.sh" --repo r')).toBe(false)
  expect(isStepCommand('npm test')).toBe(false)
})

test('takes the output file from the background notice', () => {
  const text = 'Command running in background with ID: bkh8r45b8. Output is being written to: /tmp/t/tasks/bkh8r45b8.output. You will be notified when it completes'
  expect(outputFileOf(text)).toBe('/tmp/t/tasks/bkh8r45b8.output')
  expect(outputFileOf('done')).toBe(undefined)
  expect(outputFileOf(undefined)).toBe(undefined)
})

test('keeps the last non-empty lines', () => {
  expect(tailOf('a\n\nb\r\nc\n', 2)).toEqual(['b', 'c'])
})

test('reads grid rows with a blank or filled LEFT column', () => {
  expect(rowOf(START)).toEqual({ k: 1, n: 8, name: 'Reconnaissance', event: 'start', elapsed: 0, detail: '' })
  expect(rowOf(WARN)?.detail).toBe('model call failed (server_error); repeating it in 15 s (attempt 2)')
  expect(rowOf(WARN)?.elapsed).toBe(180)
  expect(rowOf(NEXT)?.elapsed).toBe(540)
  expect(rowOf('18:55:27    Depth      : standard')).toBe(undefined)
})

test('derives the step outcome', () => {
  expect(stepOf([START, WARN]).outcome).toBe('running')
  expect(stepOf([START, DONE, '⏸ Paused after phase 1/8 — Reconnaissance; continue with --resume']).outcome).toBe('paused')
  expect(stepOf([START, '✗ assessment stopped: budget']).message).toBe('assessment stopped: budget')
  expect(stepOf(['12:00:00  8/8 Finalization      done   writing      1h10m']).outcome).toBe('complete')
})

test('toasts a phase end only when the phase was running before', () => {
  const before = stepOf([START])
  expect(toastOf(before, stepOf([START, DONE, NEXT]), 552, 552)).toBe('✓ Phase 1/8 Reconnaissance done (9m12s)')
  expect(toastOf(before, stepOf([START, DONE]), 2, 2)).toBe(undefined)
  expect(toastOf(stepOf([]), stepOf([START, DONE, NEXT]), 600, 600)).toBe(undefined)
  expect(toastOf(before, stepOf([START, '✗ boom']), 5, 5)).toBe('✗ Threat model: boom')
  expect(toastOf(stepOf([START, '✗ boom']), stepOf([START, '✗ boom', '✗ boom']), 5, 5)).toBe(undefined)
})

test('formats durations like the controller', () => {
  expect(durationOf(42)).toBe('42s')
  expect(durationOf(252)).toBe('4m12s')
  expect(durationOf(3840)).toBe('1h04m')
})

test('reads the lock heartbeat and run id', () => {
  expect(lockOf('3\n1792083952\nassessment-0cd1ee50\n')).toEqual({ heartbeat: 1792083952, runId: 'assessment-0cd1ee50' })
  expect(lockOf('garbage')).toBe(undefined)
})

test('names the role of a host-events file', () => {
  expect(roleOf('0002-recon_scanner.jsonl')).toBe('recon_scanner')
})

test('turns host events into activity', () => {
  const retry = '33.6\t{"type":"system","subtype":"api_retry","attempt":7,"max_retries":10,"error_status":null,"error":"unknown"}'
  expect(eventOf(retry)).toEqual({ activity: 'API retry 7/10 (unknown)', retrying: true })
  expect(eventOf('1.0\t{"type":"assistant","message":{}}')).toEqual({ activity: 'answering', retrying: false })
  expect(eventOf('0.1\t{"type":"system","subtype":"init"}')?.retrying).toBe(false)
  expect(eventOf('not json')).toBe(undefined)
})
