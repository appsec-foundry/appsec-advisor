import { expect, test } from 'claude-code/testing'

import { isStepCommand, outputFileOf, tailOf } from './register'

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
