// `dir` is the output directory the watched step command named.
export type Progress = { file: string | undefined; dir: string | undefined; lines: string[] }

// The current phase of the watched file, when it was first seen and the run's
// elapsed seconds its start row reported.
export type Band = {
  file: string | undefined
  phase: string | undefined
  seenAt: number
  runBase: number
  dismissed: boolean
}

// A run that holds the watched output directory (or the project's legacy
// docs/security), whoever launched it:
// its lock heartbeat and the newest model call's last host event.
export type Live = {
  runId: string
  startedAt: number
  heartbeat: number
  role: string | undefined
  activity: string
  retrying: boolean
  eventAt: number
}

declare module 'claude-code' {
  interface PluginState {
    'appsec-advisor': { progress: Progress; band: Band; now: number; live: Live | null }
  }
}
