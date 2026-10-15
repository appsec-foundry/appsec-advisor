export type Progress = { file: string | undefined; lines: string[] }

// The current phase of the watched file, when it was first seen and the run's
// elapsed seconds its start row reported.
export type Band = {
  file: string | undefined
  phase: string | undefined
  seenAt: number
  runBase: number
  dismissed: boolean
}

declare module 'claude-code' {
  interface PluginState {
    'threat-model-progress': { progress: Progress; band: Band; now: number }
  }
}
